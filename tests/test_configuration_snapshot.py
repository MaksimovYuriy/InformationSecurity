from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from botocore.exceptions import ClientError, EndpointConnectionError

from cloud_audit.application.audit import AuditError
from cloud_audit.application.snapshot import SnapshotService
from cloud_audit.domain.audit import Resource
from cloud_audit.infrastructure.s3_configuration import S3ConfigurationCollector
from cloud_audit.infrastructure.snapshots import JsonSnapshotRepository


def failure(code):
    return ClientError({'Error': {'Code': code, 'Message': 'never-print-secret'}}, 'GetConfig')


def configured_client():
    client = Mock()
    client.get_bucket_acl.return_value = {
        'Owner': {'ID': 'owner'},
        'Grants': [{'Grantee': {'Type': 'Group', 'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'},
                    'Permission': 'READ'}], 'ResponseMetadata': {'Secret': 'never-print-secret'}}
    client.get_bucket_policy.return_value = {'Policy': json.dumps({
        'Version': '2012-10-17', 'Statement': {'Effect': 'Deny', 'Principal': '*',
            'Action': 's3:DeleteObject', 'Resource': 'arn:aws:s3:::lab/*',
            'Condition': {'UnknownCondition': {'x': 'y'}}}})}
    client.get_public_access_block.return_value = {'PublicAccessBlockConfiguration': {
        'BlockPublicAcls': True, 'IgnorePublicAcls': False,
        'BlockPublicPolicy': True, 'RestrictPublicBuckets': False}}
    client.get_bucket_ownership_controls.return_value = {
        'OwnershipControls': {'Rules': [{'ObjectOwnership': 'BucketOwnerPreferred'}]}}
    client.get_bucket_versioning.return_value = {}
    client.get_bucket_logging.return_value = {}
    client.get_bucket_encryption.side_effect = failure('ServerSideEncryptionConfigurationNotFoundError')
    client.get_object_lock_configuration.side_effect = failure('ObjectLockConfigurationNotFoundError')
    return client


class CollectionTests(unittest.TestCase):
    def test_normalizes_data_preserves_policy_conditions_and_excludes_sdk_metadata(self):
        client = configured_client()
        items = S3ConfigurationCollector(client).collect(Resource('lab', 'lab'))
        fields = {item.name: item for item in items}
        self.assertEqual(fields['bucket_acl'].data['grants'][0]['permission'], 'READ')
        self.assertIn('Condition', fields['bucket_policy'].data['document']['Statement'])
        self.assertEqual(fields['versioning'].data['status'], 'Disabled')
        self.assertEqual(fields['logging'].status, 'absent')
        self.assertEqual(fields['encryption'].status, 'absent')
        self.assertNotIn('never-print-secret', json.dumps([asdict(x) for x in items]))
        self.assertEqual(len(client.method_calls), 8)
        self.assertTrue(all(call.kwargs == {'Bucket': 'lab'} for call in client.method_calls))

    def test_partial_data_keeps_denied_unsupported_and_network_errors_distinct(self):
        client = configured_client()
        client.get_bucket_acl.side_effect = failure('AccessDenied')
        client.get_public_access_block.side_effect = failure('NotImplemented')
        client.get_bucket_logging.side_effect = EndpointConnectionError(endpoint_url='secret')
        fields = {x.name: x for x in S3ConfigurationCollector(client).collect(Resource('lab', 'lab'))}
        self.assertEqual(fields['bucket_acl'].status, 'access_denied')
        self.assertEqual(fields['public_access_block'].status, 'unsupported')
        self.assertEqual(fields['logging'].status, 'error')
        self.assertEqual(fields['bucket_policy'].status, 'available')
        self.assertIsNone(fields['bucket_acl'].data)

    def test_missing_bucket_or_invalid_credentials_abort_without_saving(self):
        for code in ('NoSuchBucket', 'InvalidAccessKeyId', 'SignatureDoesNotMatch'):
            client = configured_client()
            client.get_bucket_policy.side_effect = failure(code)
            repo = Mock()
            with self.subTest(code=code), self.assertRaises(AuditError):
                SnapshotService(S3ConfigurationCollector(client), repo).collect('lab')
            repo.save.assert_not_called()

    def test_malformed_data_does_not_become_an_absent_or_safe_configuration(self):
        for response in ({}, {'Policy': 'not-json'}, {'Policy': '[]'}):
            client = configured_client()
            client.get_bucket_policy.return_value = response
            fields = {x.name: x for x in S3ConfigurationCollector(client).collect(Resource('lab', 'lab'))}
            self.assertEqual(fields['bucket_policy'].status, 'error')
        client = configured_client()
        client.get_public_access_block.return_value = {'PublicAccessBlockConfiguration': {'BlockPublicAcls': 'yes'}}
        fields = {x.name: x for x in S3ConfigurationCollector(client).collect(Resource('lab', 'lab'))}
        self.assertEqual(fields['public_access_block'].status, 'error')

    def test_service_makes_scope_and_collection_time_explicit(self):
        repo = Mock()
        snapshot = SnapshotService(S3ConfigurationCollector(configured_client()), repo).collect('lab')
        self.assertEqual(snapshot.scope, 'bucket_configuration_only')
        self.assertIn('object_acl_not_collected', snapshot.limitations)
        self.assertEqual(snapshot.schema_version, 1)
        self.assertEqual(snapshot.provider, 'vk')
        self.assertEqual(snapshot.collection_status, 'complete_for_scope')
        self.assertIsNotNone(datetime.fromisoformat(snapshot.collected_at).tzinfo)
        repo.save.assert_called_once_with(snapshot)
        client = configured_client()
        client.get_bucket_acl.side_effect = failure('AccessDenied')
        partial = SnapshotService(S3ConfigurationCollector(client), Mock()).collect('lab')
        self.assertEqual(partial.collection_status, 'partial')


class SnapshotRepositoryTests(unittest.TestCase):
    def test_roundtrip_permissions_identifier_and_corruption_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = JsonSnapshotRepository(Path(directory) / 'snapshots')
            snapshot = SnapshotService(S3ConfigurationCollector(configured_client()), repo).collect('lab')
            self.assertEqual(repo.get(snapshot.id), snapshot)
            folder = Path(directory) / 'snapshots'
            path = folder / (snapshot.id + '.json')
            self.assertEqual(folder.stat().st_mode & 0o777, 0o700)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(AuditError):
                repo.get('../outside')
            data = json.loads(path.read_text())
            for change in ({'schema_version': 99}, {'id': 'a' * 32},
                           {'collection_status': 'partial'}, {'observations': []}):
                path.write_text(json.dumps(data | change))
                with self.subTest(change=change), self.assertRaises(AuditError):
                    repo.get(snapshot.id)

    def test_expired_snapshots_are_rejected_and_removed_on_next_save(self):
        now = datetime(2026, 11, 22, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            repo = JsonSnapshotRepository(Path(directory), clock=lambda: now)
            snapshot = SnapshotService(S3ConfigurationCollector(configured_client()), Mock()).collect('lab')
            old = replace(snapshot, collected_at=(now - timedelta(days=8)).isoformat())
            # Simulate an artifact left by an earlier run.
            path = Path(directory) / (old.id + '.json')
            path.write_text(json.dumps(asdict(old)))
            with self.assertRaisesRegex(AuditError, 'expired'):
                repo.get(old.id)
            fresh = replace(snapshot, id='b' * 32, collected_at=now.isoformat())
            repo.save(fresh)
            self.assertFalse(path.exists())
            self.assertEqual(repo.get(fresh.id), fresh)


class SnapshotCliTests(unittest.TestCase):
    def test_collect_partial_snapshot_and_read_offline_in_another_process(self):
        import contextlib
        import io
        import os
        import subprocess
        import sys
        from unittest.mock import patch
        from botocore.stub import Stubber
        from cloud_audit.cli import main
        from cloud_audit.infrastructure.configuration import load_s3_settings
        from cloud_audit.infrastructure.s3 import S3Provider

        settings = load_s3_settings({'AWS_ACCESS_KEY_ID': 'fake-id', 'AWS_SECRET_ACCESS_KEY': 'fake-secret'})
        provider = S3Provider.from_settings(settings)
        with tempfile.TemporaryDirectory() as directory, Stubber(provider._client) as stub:
            stub.add_response('get_bucket_acl', {'Owner': {'ID': 'owner'}, 'Grants': []}, {'Bucket': 'lab'})
            for method, code in [('get_bucket_policy', 'NoSuchBucketPolicy'),
                                 ('get_public_access_block', 'NotImplemented'),
                                 ('get_bucket_ownership_controls', 'AccessDenied')]:
                stub.add_client_error(method, service_error_code=code, service_message='fake-secret',
                                      expected_params={'Bucket': 'lab'})
            stub.add_response('get_bucket_versioning', {}, {'Bucket': 'lab'})
            stub.add_response('get_bucket_logging', {}, {'Bucket': 'lab'})
            for method, code in [('get_bucket_encryption', 'NotImplemented'),
                                 ('get_object_lock_configuration', 'NotImplemented')]:
                stub.add_client_error(method, service_error_code=code, expected_params={'Bucket': 'lab'})
            output = io.StringIO()
            with patch.dict(os.environ, {'CLOUD_AUDIT_STATE_DIR': directory,
                                          'AWS_ACCESS_KEY_ID': 'fake-id', 'AWS_SECRET_ACCESS_KEY': 'fake-secret'}), \
                 patch('sys.argv', ['cloud-audit', 'collect', '--resource', 'lab']), \
                 patch.object(S3Provider, 'from_settings', return_value=provider), \
                 contextlib.redirect_stdout(output):
                self.assertEqual(main(), 3)
            snapshot = json.loads(output.getvalue())
            self.assertEqual(snapshot['collection_status'], 'partial')
            env = dict(os.environ, CLOUD_AUDIT_STATE_DIR=directory)
            env.pop('AWS_ACCESS_KEY_ID', None)
            env.pop('AWS_SECRET_ACCESS_KEY', None)
            result = subprocess.run([sys.executable, '-m', 'cloud_audit', 'snapshot', snapshot['id']],
                                    env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 3, result.stderr)
            self.assertEqual(json.loads(result.stdout), snapshot)
            self.assertNotIn('fake-secret', output.getvalue() + result.stderr)
            stub.assert_no_pending_responses()


class ConfigurationEvidenceTests(unittest.TestCase):
    def test_omitted_mfa_delete_setting_is_unknown_not_disabled(self):
        client = configured_client()
        fields = {x.name: x for x in S3ConfigurationCollector(client).collect(Resource('lab', 'lab'))}
        self.assertIsNone(fields['versioning'].data['mfa_delete'])

    def test_atomic_write_failure_preserves_previous_snapshot_and_cleans_temporary_file(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            repo = JsonSnapshotRepository(Path(directory))
            snapshot = SnapshotService(S3ConfigurationCollector(configured_client()), repo).collect('lab')
            with patch('cloud_audit.infrastructure.snapshots.os.replace', side_effect=OSError):
                with self.assertRaises(OSError):
                    repo.save(snapshot)
            self.assertEqual(repo.get(snapshot.id), snapshot)
            self.assertEqual(len(list(Path(directory).iterdir())), 1)


class SnapshotSchemaTests(unittest.TestCase):
    def test_replay_rejects_corrupted_normalized_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = JsonSnapshotRepository(Path(directory))
            snapshot = SnapshotService(S3ConfigurationCollector(configured_client()), repo).collect('lab')
            path = Path(directory) / (snapshot.id + '.json')
            original = json.loads(path.read_text())
            changes = [{'data': {}}, {'source': 'invented_method'},
                       {'status': 'absent', 'data': None, 'reason': 'permission_required'}]
            for change in changes:
                data = json.loads(json.dumps(original))
                data['observations'][0].update(change)
                path.write_text(json.dumps(data))
                with self.subTest(change=change), self.assertRaises(AuditError):
                    repo.get(snapshot.id)


class AdditionalConfigurationTests(unittest.TestCase):
    def test_present_encryption_logging_and_retention_normalize_without_sdk_metadata(self):
        client = configured_client()
        client.get_bucket_encryption.side_effect = None
        client.get_bucket_encryption.return_value = {'ServerSideEncryptionConfiguration': {'Rules': [{
            'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'aws:kms', 'KMSMasterKeyID': 'key-reference'},
            'BucketKeyEnabled': True}]}}
        client.get_bucket_logging.return_value = {'LoggingEnabled': {'TargetBucket': 'logs', 'TargetPrefix': 'audit/'}}
        client.get_object_lock_configuration.side_effect = None
        client.get_object_lock_configuration.return_value = {'ObjectLockConfiguration': {
            'ObjectLockEnabled': 'Enabled', 'Rule': {'DefaultRetention': {'Mode': 'GOVERNANCE', 'Days': 3}}}}
        with tempfile.TemporaryDirectory() as directory:
            repo = JsonSnapshotRepository(Path(directory))
            snapshot = SnapshotService(S3ConfigurationCollector(client), repo).collect('lab')
            fields = {item.name: item for item in snapshot.observations}
            self.assertEqual(fields['encryption'].data['rules'][0]['kms_key_id'], 'key-reference')
            self.assertEqual(fields['logging'].data['target_bucket'], 'logs')
            self.assertEqual(fields['object_lock'].data['default_retention']['days'], 3)
            self.assertEqual(repo.get(snapshot.id), snapshot)

    def test_rate_limits_and_generic_404_do_not_mean_missing_configuration(self):
        for code, reason in [('SlowDown', 'rate_limit'), ('404', 'service_error')]:
            client = configured_client()
            client.get_bucket_policy.side_effect = failure(code)
            fields = {item.name: item for item in S3ConfigurationCollector(client).collect(Resource('lab', 'lab'))}
            self.assertEqual(fields['bucket_policy'].status, 'error')
            self.assertEqual(fields['bucket_policy'].reason, reason)
