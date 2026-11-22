"""Bounded discovery and independently verified unsigned mutation probes."""
import unittest
from unittest.mock import Mock
from botocore.exceptions import ClientError

from cloud_audit.providers.discovery import ObjectEnumerator
from cloud_audit.providers.external import ExternalInspector
from cloud_audit.providers.mutations import MutationProber
from cloud_audit.models.scanning import ScanTarget


def failure(code='AccessDenied', status=403):
    return ClientError({'Error': {'Code': code, 'Message': 'withheld'}, 'ResponseMetadata': {'HTTPStatusCode': status}}, 'Test')


class DiscoveryTests(unittest.TestCase):
    def test_pages_stop_at_limit_and_report_unseen_objects(self):
        client = Mock()
        client.list_objects_v2.side_effect = [
            {'Contents': [{'Key': 'one'}], 'IsTruncated': True, 'NextContinuationToken': 'next', 'ResponseMetadata': {'HTTPStatusCode': 200}},
            {'Contents': [{'Key': 'two'}], 'IsTruncated': True, 'NextContinuationToken': 'more', 'ResponseMetadata': {'HTTPStatusCode': 200}}]
        discovery, proof = ObjectEnumerator(client, 'anonymous').list('first', 2)
        self.assertEqual(discovery.keys, ('one', 'two'))
        self.assertEqual(discovery.status, 'limited')
        self.assertEqual(proof.outcome, 'allowed')
        self.assertEqual(client.list_objects_v2.call_count, 2)

    def test_denial_is_not_an_empty_successful_listing_and_broken_tokens_stop(self):
        client = Mock()
        client.list_objects_v2.side_effect = failure()
        result, proof = ObjectEnumerator(client, 'anonymous').list('first', 2)
        self.assertEqual(result.status, 'failed')
        self.assertEqual(proof.outcome, 'denied')
        client.list_objects_v2.side_effect = None
        client.list_objects_v2.return_value = {'Contents': [], 'IsTruncated': True, 'NextContinuationToken': 'same', 'ResponseMetadata': {'HTTPStatusCode': 200}}
        result, proof = ObjectEnumerator(client, 'anonymous').list('first', 2)
        self.assertEqual(result.status, 'failed')
        self.assertLessEqual(client.list_objects_v2.call_count, 3)


class ExternalInspectorTests(unittest.TestCase):
    def test_known_object_get_runs_even_when_list_denied_and_no_mutation_opt_in(self):
        client = Mock()
        client.list_objects_v2.side_effect = failure()
        body = Mock()
        client.get_object.return_value = {'Body': body, 'ResponseMetadata': {'HTTPStatusCode': 206}}
        inspector = ExternalInspector(client, 'https://example.invalid')
        result = inspector.inspect(ScanTarget('first', ('secret.txt',)), 2)
        self.assertEqual(next(p for p in result.probes if p.operation == 'read').outcome, 'allowed')
        client.put_object.assert_not_called()
        client.delete_object.assert_not_called()
        body.read.assert_called_once_with(1)
        body.close.assert_called_once()


class MutationEvidenceTests(unittest.TestCase):
    def clients(self):
        signed, unsigned = Mock(), Mock()
        signed.get_object_lock_configuration.side_effect = failure('ObjectLockConfigurationNotFoundError', 404)
        signed.get_bucket_versioning.return_value = {}
        signed.list_object_versions.return_value = {'Versions': [], 'DeleteMarkers': [], 'IsTruncated': False}
        signed.put_object.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
        signed.head_object.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
        unsigned.put_object.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
        unsigned.delete_object.return_value = {'ResponseMetadata': {'HTTPStatusCode': 204}}
        return signed, unsigned

    def test_delete_204_without_observed_absence_is_unverified(self):
        signed, unsigned = self.clients()
        results = MutationProber(unsigned, signed).run('first')
        delete = next(p for p in results if p.operation == 'delete')
        self.assertEqual(delete.outcome, 'unverified')
        self.assertEqual(delete.http_status, 204)

    def test_preexisting_key_is_never_modified(self):
        signed, unsigned = self.clients()
        signed.list_object_versions.return_value = {'IsTruncated': True}
        results = MutationProber(unsigned, signed).run('first')
        unsigned.put_object.assert_not_called()
        unsigned.delete_object.assert_not_called()
        signed.put_object.assert_not_called()
        self.assertTrue(all(p.outcome == 'not_tested' for p in results))

    def test_unsigned_only_requires_residue_acceptance(self):
        with self.assertRaises(ValueError):
            MutationProber(Mock()).run('first')

    def test_write_denial_does_not_imply_delete_denial(self):
        signed, unsigned = self.clients()
        unsigned.put_object.side_effect = failure()
        signed.head_object.side_effect = [{'ResponseMetadata': {'HTTPStatusCode': 200}}, failure('NoSuchKey', 404), failure('NoSuchKey', 404)]
        results = MutationProber(unsigned, signed).run('first')
        self.assertEqual(results[0].outcome, 'denied')
        self.assertEqual(results[1].outcome, 'allowed')
        self.assertEqual(results[1].verification, 'current_object_absent')

    def test_object_lock_unknown_prevents_mutations(self):
        signed, unsigned = self.clients()
        signed.get_object_lock_configuration.side_effect = failure()
        results = MutationProber(unsigned, signed).run('first')
        unsigned.put_object.assert_not_called()
        unsigned.delete_object.assert_not_called()
        self.assertTrue(all(p.outcome == 'not_tested' for p in results))

    def test_cleanup_never_removes_foreign_version_or_other_key(self):
        signed, unsigned = self.clients()
        signed.list_object_versions.return_value = {'Versions': [
            {'Key': 'ours', 'VersionId': 'v1'}, {'Key': 'foreign', 'VersionId': 'v2'}], 'DeleteMarkers': [], 'IsTruncated': False}
        signed.head_object.return_value = {'Metadata': {'cloud-audit-probe': 'different-owner'}}
        status = MutationProber(unsigned, signed)._cleanup('first', 'ours', 'expected-owner', set(), True, True)
        self.assertEqual(status, 'unknown')
        signed.delete_object.assert_not_called()

    def test_preparation_network_failure_still_searches_for_residual_versions(self):
        from botocore.exceptions import EndpointConnectionError
        signed, unsigned = self.clients()
        signed.put_object.side_effect = EndpointConnectionError(endpoint_url='withheld')
        results = MutationProber(unsigned, signed).run('first')
        self.assertGreaterEqual(signed.list_object_versions.call_count, 4)
        self.assertNotEqual(results[1].cleanup, 'not_needed')

    def test_unsigned_upload_reports_residue_even_if_unsigned_cleanup_returns_success(self):
        signed, unsigned = self.clients()
        unsigned.head_object.side_effect = failure()
        results = MutationProber(unsigned).run('first', allow_residue=True)
        self.assertEqual(results[0].outcome, 'allowed')
        self.assertEqual(results[0].cleanup, 'residue')
        self.assertEqual(results[1].outcome, 'unverified')

    def test_cleanup_marker_header_names_are_case_insensitive(self):
        signed, unsigned = self.clients()
        signed.list_object_versions.side_effect = [
            {'Versions': [{'Key': 'ours', 'VersionId': 'null'}], 'DeleteMarkers': [], 'IsTruncated': False},
            {'Versions': [], 'DeleteMarkers': [], 'IsTruncated': False}]
        signed.head_object.side_effect = [{'Metadata': {'Cloud-Audit-Probe': 'expected-owner'}}, failure('NoSuchKey', 404)]
        status = MutationProber(unsigned, signed)._cleanup('first', 'ours', 'expected-owner', set(), True, True)
        self.assertEqual(status, 'cleaned')
        signed.delete_object.assert_called_once_with(Bucket='first', Key='ours', VersionId='null')

    def test_unversioned_cleanup_uses_current_object_not_get_object_version_permission(self):
        signed, unsigned = self.clients()
        signed.list_object_versions.side_effect = [
            {'Versions': [{'Key': 'ours', 'VersionId': 'null', 'IsLatest': True}], 'DeleteMarkers': [], 'IsTruncated': False},
            {'Versions': [], 'DeleteMarkers': [], 'IsTruncated': False}]
        def head(**kwargs):
            if 'VersionId' in kwargs:
                raise failure()
            if signed.delete_object.called:
                raise failure('NoSuchKey', 404)
            return {'Metadata': {'Cloud-Audit-Probe': 'expected-owner'}, 'ResponseMetadata': {'HTTPStatusCode': 200}}
        signed.head_object.side_effect = head
        prober = MutationProber(unsigned, signed)
        self.assertTrue(prober._ready('first'))
        self.assertEqual(prober._cleanup('first', 'ours', 'expected-owner', set(), True, True), 'cleaned')
        signed.delete_object.assert_called_once_with(Bucket='first', Key='ours')

class DiscoveryLimitTests(unittest.TestCase):
    def test_server_returning_more_than_requested_is_not_a_complete_scope(self):
        client = Mock()
        client.list_objects_v2.return_value = {'Contents': [{'Key': 'one'}, {'Key': 'two'}], 'IsTruncated': False,
                                             'ResponseMetadata': {'HTTPStatusCode': 200}}
        discovery, _ = ObjectEnumerator(client, 'anonymous').list('first', 1)
        self.assertEqual(discovery.keys, ('one',))
        self.assertEqual(discovery.status, 'limited')

class MutationReadinessTests(unittest.TestCase):
    def test_versioning_failure_cannot_be_mistaken_for_absent_object_lock(self):
        signed, unsigned = Mock(), Mock()
        signed.get_bucket_versioning.side_effect = failure('ObjectLockConfigurationNotFoundError', 404)
        self.assertFalse(MutationProber(unsigned, signed)._ready('first'))
        results = MutationProber(unsigned, signed).run('first')
        self.assertTrue(all(p.outcome == 'not_tested' for p in results))
        unsigned.put_object.assert_not_called()
        signed.get_object_lock_configuration.assert_not_called()
