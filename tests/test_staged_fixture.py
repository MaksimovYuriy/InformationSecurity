"""The multi-bucket integration fixture cleans only buckets it successfully created."""
import unittest
from unittest.mock import Mock
from botocore.exceptions import ClientError
from scripts.verify_staged_scan import cleanup_fixture


class StagedFixtureTests(unittest.TestCase):
    def test_cleanup_continues_after_a_bucket_error_and_removes_versions(self):
        client = Mock()
        client.list_object_versions.side_effect = [ClientError({'Error': {'Code': 'AccessDenied'}}, 'ListObjectVersions'),
            {'Versions': [{'Key': 'synthetic.txt', 'VersionId': 'null'}], 'DeleteMarkers': [], 'IsTruncated': False}]
        self.assertFalse(cleanup_fixture(client, ('first', 'second')))
        self.assertEqual(client.delete_bucket.call_count, 2)
        client.delete_object.assert_called_once_with(Bucket='second', Key='synthetic.txt', VersionId='null')

    def test_no_owned_buckets_means_no_cloud_cleanup_requests(self):
        client = Mock()
        self.assertTrue(cleanup_fixture(client, ()))
        self.assertEqual(client.method_calls, [])

    def test_public_evidence_may_come_from_separate_runs_but_requires_clean_verified_mutations(self):
        from scripts.verify_staged_scan import public_phase_confirmed
        names = ('first', 'second', 'third')
        def probe(op, outcome, target=None, cleanup='not_needed', verification=None):
            return dict(operation=op, outcome=outcome, target=target, cleanup=cleanup, verification=verification)
        private = {'bucket': 'first', 'probes': [probe('list','denied'),probe('read','denied','known')]}
        object_only = {'bucket': 'third', 'probes': [probe('list','denied'),probe('read','allowed','known')]}
        attempts = [
            {'label':'public', 'buckets':[private, {'bucket':'second','probes':[probe('list','allowed'),probe('read','allowed','known'),probe('write','allowed','p',cleanup='cleaned')]}, object_only]},
            {'label':'public', 'buckets':[private, {'bucket':'second','probes':[probe('delete','allowed','d',cleanup='cleaned',verification='current_object_absent')]}, object_only]}]
        self.assertTrue(public_phase_confirmed(attempts, names, 'known'))
        attempts[1]['buckets'][1]['probes'][0]['verification'] = None
        self.assertFalse(public_phase_confirmed(attempts, names, 'known'))
