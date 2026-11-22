"""Scan CLI handles credentials explicitly and persists aggregate reports for offline export."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from cloud_audit.cli import main
from cloud_audit.configuration.environment import load_scan_settings
from cloud_audit.errors import ConfigurationError, AuditError
from cloud_audit.models.scanning import ScanRun
from cloud_audit.storage.scans import JsonScanRepository


class ScanConfigurationTests(unittest.TestCase):
    def test_no_keys_is_explicit_unsigned_mode_but_partial_keys_are_invalid(self):
        settings, authenticated = load_scan_settings({})
        self.assertFalse(authenticated)
        self.assertEqual(settings.access_key, '')
        with self.assertRaises(ConfigurationError):
            load_scan_settings({'AWS_ACCESS_KEY_ID': 'synthetic'})
        with self.assertRaises(ConfigurationError):
            load_scan_settings({'CLOUD_AUDIT_S3_ENDPOINT_URL': 'http://example.invalid'})


class ScanStorageTests(unittest.TestCase):
    def test_roundtrip_is_private_immutable_and_rejects_corruption(self):
        run = ScanRun('a'*32, 1, 'https://example.invalid', '2026-11-22T12:00:00+00:00',
                      '2026-11-22T12:01:00+00:00', 'explicit', 'complete', 20, False, ())
        with tempfile.TemporaryDirectory() as directory:
            repo = JsonScanRepository(Path(directory))
            repo.save(run)
            repo.save(run)
            from dataclasses import replace
            with self.assertRaises(AuditError):
                repo.save(replace(run, max_objects=1))
            self.assertEqual(repo.get(run.id), run)
            self.assertEqual((Path(directory)/(run.id+'.json')).stat().st_mode & 0o777, 0o600)
            (Path(directory)/(run.id+'.json')).write_text('{}')
            with self.assertRaises(AuditError):
                repo.get(run.id)


class ScanCliTests(unittest.TestCase):
    def test_unsigned_cli_never_constructs_signed_provider_and_reads_offline_report(self):
        from cloud_audit.models.scanning import ExternalResult, ObjectDiscovery
        external = Mock(namespace='https://example.invalid')
        external.inspect.return_value = ExternalResult((), ObjectDiscovery((), 'complete', 'anonymous', 20))
        with tempfile.TemporaryDirectory() as directory:
            with (patch.dict(os.environ, {'CLOUD_AUDIT_STATE_DIR': directory}, clear=True),
                  patch('cloud_audit.providers.external.ExternalInspector.from_settings', return_value=external),
                  patch('cloud_audit.providers.s3.S3Provider.from_settings') as signed,
                  patch('sys.argv', ['cloud-audit', '--no-env-file', 'scan', '--buckets', 'first', 'second']),
                  contextlib.redirect_stdout(io.StringIO()) as output):
                code = main()
                signed.assert_not_called()
                data = json.loads(output.getvalue())
                self.assertEqual(len(data['buckets']), 2)
                self.assertEqual(code, 0)
            with (patch.dict(os.environ, {'CLOUD_AUDIT_STATE_DIR': directory}, clear=True),
                  patch('sys.argv', ['cloud-audit', '--no-env-file', 'scan-report', data['id'], '--format', 'markdown']),
                  contextlib.redirect_stdout(io.StringIO()) as output):
                self.assertEqual(main(), 0)
                self.assertIn('first', output.getvalue())

    def test_all_buckets_without_credentials_and_unknown_mutation_scope_fail_before_io(self):
        for args in [('scan', '--all-buckets'), ('scan', '--buckets', 'first', '--mutation-buckets', 'second')]:
            with tempfile.TemporaryDirectory() as directory:
                with (patch.dict(os.environ, {'CLOUD_AUDIT_STATE_DIR': directory}, clear=True),
                      patch('sys.argv', ['cloud-audit', '--no-env-file', *args]), contextlib.redirect_stderr(io.StringIO()),
                      self.assertRaises(SystemExit) as caught):
                    main()
                self.assertEqual(caught.exception.code, 2)

    def test_two_real_service_pipelines_save_reports_and_offline_replay_keeps_unsigned_facts(self):
        from io import BytesIO
        from botocore.exceptions import ClientError
        from audit_fixtures import configured_client, failure
        from cloud_audit.providers.s3 import S3Provider
        from cloud_audit.providers.external import ExternalInspector
        from cloud_audit.storage.sqlite import SqliteReportRepository
        from cloud_audit.storage.snapshots import JsonSnapshotRepository
        from cloud_audit.services.audit import SecurityAuditService
        from cloud_audit.rules.engine import RuleEngine
        from cloud_audit.rules.registry import default_rules
        signed, anonymous = configured_client(), Mock()
        signed.get_bucket_policy.side_effect = failure('NoSuchBucketPolicy')
        signed.get_bucket_acl.return_value = {'Owner': {'ID': 'owner'}, 'Grants': []}
        signed.get_object_acl.return_value = {'Owner': {'ID': 'owner'}, 'Grants': []}
        signed.list_objects_v2.return_value = {'Contents': [{'Key': 'known.txt'}], 'IsTruncated': False, 'ResponseMetadata': {'HTTPStatusCode': 200}}
        denial = ClientError({'Error': {'Code': 'AccessDenied'}, 'ResponseMetadata': {'HTTPStatusCode': 403}}, 'Test')
        def listing(**kwargs):
            if kwargs['Bucket'] == 'first':
                raise denial
            return {'Contents': [{'Key': 'known.txt'}], 'IsTruncated': False, 'ResponseMetadata': {'HTTPStatusCode': 200}}
        def reading(**kwargs):
            if kwargs['Bucket'] == 'first':
                raise denial
            return {'Body': BytesIO(b'x'), 'ResponseMetadata': {'HTTPStatusCode': 206}}
        anonymous.list_objects_v2.side_effect = listing
        anonymous.get_object.side_effect = reading
        provider = S3Provider(signed, namespace='https://example.invalid')
        external = ExternalInspector(anonymous, 'https://example.invalid', signed)
        with tempfile.TemporaryDirectory() as directory:
            with (patch.dict(os.environ, {'CLOUD_AUDIT_STATE_DIR': directory, 'AWS_ACCESS_KEY_ID': 'synthetic', 'AWS_SECRET_ACCESS_KEY': 'synthetic'}, clear=True),
                  patch('cloud_audit.providers.s3.S3Provider.from_settings', return_value=provider),
                  patch('cloud_audit.providers.external.ExternalInspector.from_settings', return_value=external),
                  patch('sys.argv', ['cloud-audit', '--no-env-file', 'scan', '--buckets', 'first', 'second', '--max-objects', '2']),
                  contextlib.redirect_stdout(io.StringIO()) as output):
                self.assertEqual(main(), 3)
            data = json.loads(output.getvalue())
            self.assertEqual(len(data['buckets']), 2)
            repo = SqliteReportRepository(Path(directory)/'data/audit.sqlite3')
            for row in data['buckets']:
                report = repo.get(row['internal_report_id'])
                self.assertEqual(len(report.results), 8)
                if row['bucket'] == 'second':
                    self.assertEqual(next(f for f in report.results if f.rule_id == 'anonymous-read').status, 'confirmed_violation')
                    snapshot = JsonSnapshotRepository(Path(directory)/'data/snapshots').get(report.snapshot_id)
                    repeated = SecurityAuditService(RuleEngine(default_rules()), repo).audit(snapshot, report.policy)
                    self.assertEqual(repeated.results, report.results)
            stored = JsonScanRepository(Path(directory)/'data/scans').get(data['id'])
            self.assertEqual(stored.buckets[0].bucket, 'first')
            self.assertFalse(stored.buckets[0].target.allow_mutations)
            anonymous.put_object.assert_not_called()
            anonymous.delete_object.assert_not_called()

    def test_stored_summary_rejects_forged_findings_and_version(self):
        from dataclasses import asdict
        from cloud_audit.models.scanning import ProbeResult, ExternalResult, ObjectDiscovery, BucketScanResult, ScanTarget
        from cloud_audit.rules.external import external_findings
        target = ScanTarget('first')
        probe = ProbeResult('list', None, 'denied', 403, '2026-11-22T12:00:00+00:00')
        ext = ExternalResult((probe,), ObjectDiscovery((), 'failed', 'anonymous', 20, 'access_denied'))
        bucket = BucketScanResult('first', 'complete', ext, external_findings(ext.probes, target.policy), 'skipped', None, None, target=target)
        run = ScanRun('c'*32, 1, 'https://example.invalid', probe.checked_at, probe.checked_at, 'explicit', 'complete', 20, False, (bucket,))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = JsonScanRepository(root)
            repo.save(run)
            data = asdict(run)
            data['buckets'][0]['external_findings'][0]['risk']['score'] = 9
            (root/(run.id+'.json')).write_text(json.dumps(data))
            with self.assertRaises(AuditError):
                repo.get(run.id)
            data = asdict(run)
            data['schema_version'] = 2
            (root/(run.id+'.json')).write_text(json.dumps(data))
            with self.assertRaises(AuditError):
                repo.get(run.id)

    def test_unsigned_factory_never_uses_environment_credentials(self):
        from botocore import UNSIGNED
        from cloud_audit.providers.external import ExternalInspector
        with patch.dict(os.environ, {'AWS_ACCESS_KEY_ID': 'synthetic', 'AWS_SECRET_ACCESS_KEY': 'synthetic'}):
            settings, _ = load_scan_settings({}, external_only=True)
            inspector = ExternalInspector.from_settings(settings)
            self.assertEqual(inspector.anonymous.meta.config.signature_version, UNSIGNED)
            self.assertIsNone(inspector.anonymous._request_signer._credentials)
