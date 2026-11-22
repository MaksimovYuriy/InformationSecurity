from io import BytesIO
import unittest
from unittest.mock import Mock
from botocore.exceptions import ClientError
from cloud_audit.domain.snapshot import CollectionOptions
from cloud_audit.domain.audit import Resource
from cloud_audit.infrastructure.anonymous import AnonymousProber
from cloud_audit.infrastructure.s3_configuration import S3ConfigurationCollector
from test_configuration_snapshot import configured_client, failure


class AccessCollectionTests(unittest.TestCase):
    def test_only_explicit_objects_are_collected_without_list_or_content_reads(self):
        client = configured_client()
        client.get_object_acl.return_value = {'Owner': {'ID': 'owner'}, 'Grants': []}
        result = S3ConfigurationCollector(client).collect(Resource('lab', 'lab'), CollectionOptions(('test.txt',)))
        self.assertEqual(result[-1].name, 'object_acl:test.txt')
        client.get_object_acl.assert_called_once_with(Bucket='lab', Key='test.txt')
        client.list_objects_v2.assert_not_called()
        client.get_object.assert_not_called()

    def test_missing_object_and_acl_denial_remain_distinct(self):
        for code, expected in [('NoSuchKey', 'not_found'), ('AccessDenied', 'access_denied')]:
            client = configured_client()
            client.get_object_acl.side_effect = failure(code)
            result = S3ConfigurationCollector(client).collect(Resource('lab', 'lab'), CollectionOptions(('x',)))
            self.assertEqual(result[-1].status, expected)

    def test_unsigned_reads_are_bounded_and_body_is_closed_without_persisting_contents(self):
        client = Mock()
        body = BytesIO(b'x')
        client.get_object.return_value = {'Body': body, 'ResponseMetadata': {'HTTPStatusCode': 206}}
        client.list_objects_v2.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
        prober = AnonymousProber(client)
        values = prober.read_only('lab', ('sample.txt',))
        self.assertTrue(body.closed)
        client.get_object.assert_called_once_with(Bucket='lab', Key='sample.txt', Range='bytes=0-0')
        client.list_objects_v2.assert_called_once_with(Bucket='lab', MaxKeys=1)
        self.assertTrue(all(x.data['outcome'] == 'allowed' for x in values))
        client.put_object.assert_not_called()
        client.delete_object.assert_not_called()

    def test_anonymous_404_is_unknown_not_a_denied_or_safe_result(self):
        client = Mock()
        client.get_object.side_effect = failure('NoSuchKey')
        client.list_objects_v2.side_effect = ClientError({'Error': {'Code': 'AccessDenied'},
            'ResponseMetadata': {'HTTPStatusCode': 403}}, 'ListObjectsV2')
        values = AnonymousProber(client).read_only('lab', ('x',))
        self.assertEqual(values[0].data['outcome'], 'denied')
        self.assertEqual(values[1].data['outcome'], 'not_found')

    def test_options_require_explicit_write_opt_in_and_limit_object_scope(self):
        for arguments in ({'allow_write_probes': True}, {'object_keys': ('',)},
                          {'object_keys': tuple(str(x) for x in range(21))}):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                CollectionOptions(**arguments)


class ProbeSafetyTests(unittest.TestCase):
    def test_factory_is_unsigned_even_when_environment_contains_credentials(self):
        from unittest.mock import patch
        from botocore import UNSIGNED
        from cloud_audit.infrastructure.configuration import S3Settings
        with patch.dict('os.environ', {'AWS_ACCESS_KEY_ID': 'must-not-send', 'AWS_SECRET_ACCESS_KEY': 'must-not-send'}):
            probe = AnonymousProber.from_settings(S3Settings('https://example.invalid', 'us-east-1', 'fake', 'fake'))
        self.assertEqual(probe._anonymous.meta.config.signature_version, UNSIGNED)

    def test_mutations_need_opt_in_and_cleanup_exact_created_versions_and_markers(self):
        anon, signed = Mock(), Mock()
        anon.put_object.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
        anon.delete_object.return_value = {'ResponseMetadata': {'HTTPStatusCode': 204}}
        seen = set()
        def versions(**kwargs):
            key = kwargs['Prefix']
            if key not in seen:
                seen.add(key)
                return {'IsTruncated': False}
            return {'Versions': [{'Key': key, 'VersionId': 'v1'}, {'Key': 'unrelated', 'VersionId': 'foreign'}],
                    'DeleteMarkers': [{'Key': key, 'VersionId': 'marker'}], 'IsTruncated': False}
        signed.list_object_versions.side_effect = versions
        probe = AnonymousProber(anon, signed)
        with self.assertRaises(ValueError):
            probe.mutations('lab')
        signed.put_object.assert_not_called()
        results = probe.mutations('lab', enabled=True)
        self.assertEqual([x.data['outcome'] for x in results], ['allowed', 'allowed'])
        for call in signed.delete_object.call_args_list:
            self.assertTrue(call.kwargs['Key'].startswith('_cloud-audit-probe/'))
            self.assertIn(call.kwargs['VersionId'], {'v1', 'marker'})
        self.assertEqual(anon.put_object.call_args.kwargs['IfNoneMatch'], '*')

    def test_fixture_access_denial_and_cleanup_failure_are_recorded_not_leaked(self):
        anon, signed = Mock(), Mock()
        signed.list_object_versions.side_effect = failure('AccessDenied')
        results = AnonymousProber(anon, signed).mutations('lab', enabled=True)
        self.assertTrue(all(x.data['outcome'] == 'error' for x in results))
        signed.delete_object.assert_not_called()
        signed.put_object.assert_not_called()
        anon.put_object.assert_not_called()

    def test_extended_snapshot_and_report_roundtrip_keep_scope_and_probe_evidence(self):
        import tempfile
        from pathlib import Path
        from cloud_audit.application.snapshot import SnapshotService
        from cloud_audit.application.security_audit import SecurityAuditService
        from cloud_audit.application.rules import RuleEngine
        from cloud_audit.domain.public_access import PublicAccessRule
        from cloud_audit.domain.rules import AuditPolicy
        from cloud_audit.infrastructure.snapshots import JsonSnapshotRepository
        from cloud_audit.infrastructure.reports import JsonReportRepository
        from cloud_audit.infrastructure.s3 import S3Provider
        client = configured_client()
        client.get_object_acl.return_value = {'Owner': {'ID': 'owner'}, 'Grants': []}
        anon = Mock()
        anon.list_objects_v2.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
        anon.get_object.return_value = {'Body': BytesIO(b'x'), 'ResponseMetadata': {'HTTPStatusCode': 206}}
        with tempfile.TemporaryDirectory() as directory:
            snapshots = JsonSnapshotRepository(Path(directory) / 'snapshots')
            data = SnapshotService(S3Provider(client, AnonymousProber(anon)), snapshots).collect(
                'lab', CollectionOptions(('x',), probe_anonymous=True))
            self.assertEqual(snapshots.get(data.id), data)
            repo = JsonReportRepository(Path(directory))
            report = SecurityAuditService(RuleEngine((PublicAccessRule('read'),)), repo).audit(data, AuditPolicy())
            self.assertEqual(repo.get(report.id), report)
            self.assertEqual(report.object_keys, ('x',))
            self.assertEqual(report.results[0].status, 'confirmed_violation')


class MutationIsolationTests(unittest.TestCase):
    def test_preexisting_versions_are_never_deleted_or_overwritten_by_probe(self):
        anon, signed = Mock(), Mock()
        signed.list_object_versions.side_effect = lambda **kw: {
            'Versions': [{'Key': kw['Prefix'], 'VersionId': 'existing'}], 'IsTruncated': False}
        results = AnonymousProber(anon, signed).mutations('lab', enabled=True)
        self.assertTrue(all(item.data['outcome'] == 'error' for item in results))
        signed.delete_object.assert_not_called()
        signed.put_object.assert_not_called()
        anon.put_object.assert_not_called()


class CleanupFailureTests(unittest.TestCase):
    def test_cleanup_failure_after_probe_is_explicit_and_preserves_positive_evidence(self):
        anon, signed = Mock(), Mock()
        anon.put_object.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
        anon.delete_object.return_value = {'ResponseMetadata': {'HTTPStatusCode': 204}}
        signed.list_object_versions.side_effect = [
            {'IsTruncated': False}, failure('AccessDenied'),
            {'IsTruncated': False}, failure('AccessDenied')]
        results = AnonymousProber(anon, signed).mutations('lab', enabled=True)
        self.assertTrue(all(x.data['outcome'] == 'allowed' and x.data['cleanup_failed'] for x in results))


class UnsignedTransportTests(unittest.TestCase):
    def test_serialized_sdk_requests_have_no_authorization_or_credential_query(self):
        from botocore.awsrequest import AWSResponse
        from cloud_audit.infrastructure.configuration import S3Settings
        prober = AnonymousProber.from_settings(S3Settings('https://example.invalid', 'us-east-1', 'secret-id', 'secret-key'))
        requests = []
        class Raw(BytesIO):
            def stream(self, amt=None, decode_content=False):
                yield self.read()
        def respond(request, **kwargs):
            requests.append(request)
            if 'list-type' in request.url:
                payload = b'<ListBucketResult><Name>lab</Name><KeyCount>0</KeyCount><IsTruncated>false</IsTruncated></ListBucketResult>'
                return AWSResponse(request.url, 200, {'content-type': 'application/xml'}, Raw(payload))
            return AWSResponse(request.url, 206, {'content-length': '1', 'content-range': 'bytes 0-0/1'}, Raw(b'x'))
        prober._anonymous.meta.events.register('before-send.s3', respond)
        results = prober.read_only('lab', ('test.txt',))
        self.assertEqual(len(requests), 2)
        self.assertTrue(all(x.data['outcome'] == 'allowed' for x in results))
        for request in requests:
            self.assertNotIn('Authorization', request.headers)
            self.assertNotIn('X-Amz-Security-Token', request.headers)
            self.assertNotIn('X-Amz-Credential', request.url)
            self.assertNotIn('secret-id', request.url)
