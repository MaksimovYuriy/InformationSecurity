import unittest
from unittest.mock import Mock

from botocore.exceptions import ClientError, EndpointConnectionError
from cloud_audit.application.audit import AuditError, AuditService
from cloud_audit.infrastructure.configuration import ConfigurationError, load_s3_settings
from cloud_audit.infrastructure.s3 import S3Provider


class S3ProviderTests(unittest.TestCase):
    def test_configuration_requires_explicit_credentials_and_https(self):
        env = {'AWS_ACCESS_KEY_ID': 'fake-id', 'AWS_SECRET_ACCESS_KEY': 'fake-secret'}
        settings = load_s3_settings(env)
        self.assertNotIn('fake-secret', repr(settings))
        for change in ({'AWS_ACCESS_KEY_ID': ''},
                       {'CLOUD_AUDIT_S3_ENDPOINT_URL': 'http://example.org'},
                       {'CLOUD_AUDIT_S3_ENDPOINT_URL': 'https://user:secret@example.org'}):
            with self.subTest(change=change), self.assertRaises(ConfigurationError):
                load_s3_settings(env | change)

    def test_lists_multiple_pages_and_connects_without_modification(self):
        client = Mock()
        client.list_buckets.side_effect = [
            {'Buckets': [{'Name': 'first'}], 'ContinuationToken': 'next'},
            {'Buckets': [{'Name': 'second'}]}, {'Buckets': []}]
        provider = S3Provider(client)
        self.assertEqual([r.id for r in provider.resources()], ['first', 'second'])
        self.assertEqual(client.list_buckets.call_args_list[1].kwargs,
                         {'ContinuationToken': 'next'})
        result = AuditService(provider, Mock()).connection()
        self.assertEqual(result['mode'], 'vk')
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(set(client.method_calls[i][0] for i in range(3)), {'list_buckets'})

    def test_errors_are_distinct_and_never_include_sdk_messages(self):
        for code, expected in [('AccessDenied', 'denied'), ('InvalidAccessKeyId', 'credentials'),
                               ('NoSuchBucket', 'not found'), ('SlowDown', 'limit'),
                               ('InternalError', 'service')]:
            client = Mock()
            client.list_buckets.side_effect = ClientError(
                {'Error': {'Code': code, 'Message': 'SECRET'}}, 'ListBuckets')
            with self.subTest(code=code), self.assertRaises(AuditError) as caught:
                S3Provider(client).resources()
            self.assertIn(expected, str(caught.exception))
            self.assertNotIn('SECRET', str(caught.exception))
        client.list_buckets.side_effect = EndpointConnectionError(endpoint_url='SECRET')
        with self.assertRaisesRegex(AuditError, 'network'):
            S3Provider(client).resources()

    def test_cloud_audit_cannot_produce_a_demo_report(self):
        repository = Mock()
        with self.assertRaisesRegex(AuditError, 'not implemented'):
            AuditService(S3Provider(Mock()), repository).audit('bucket', ())
        repository.save.assert_not_called()

    def test_broken_pagination_and_response_fail_instead_of_partial_success(self):
        for pages in ([{'Buckets': [] , 'ContinuationToken': 'same'}] * 2,
                      [{'unexpected': []}], [{'Buckets': [{'Name': 123}]}]):
            client = Mock()
            client.list_buckets.side_effect = pages
            with self.subTest(pages=pages), self.assertRaises(AuditError):
                S3Provider(client).resources()


class S3SdkWorkflowTests(unittest.TestCase):
    def test_real_sdk_response_flows_through_cli(self):
        import contextlib
        import io
        import json
        import tempfile
        from unittest.mock import patch
        from botocore.stub import Stubber
        from cloud_audit.cli import main

        settings = load_s3_settings({'AWS_ACCESS_KEY_ID': 'fake-id',
                                     'AWS_SECRET_ACCESS_KEY': 'fake-secret'})
        provider = S3Provider.from_settings(settings)
        with Stubber(provider._client) as stub, tempfile.TemporaryDirectory() as directory:
            stub.add_response('list_buckets', {'Buckets': [{'Name': 'one'}, {'Name': 'two'}]}, {})
            output = io.StringIO()
            with patch.dict('os.environ', {'CLOUD_AUDIT_STATE_DIR': directory,
                                          'AWS_ACCESS_KEY_ID': 'fake-id',
                                          'AWS_SECRET_ACCESS_KEY': 'fake-secret'}), \
                 patch('sys.argv', ['cloud-audit', 'resources', '--profile', 'vk']), \
                 patch.object(S3Provider, 'from_settings', return_value=provider), \
                 contextlib.redirect_stdout(output):
                self.assertEqual(main(), 0)
            data = json.loads(output.getvalue())
            self.assertEqual(data['mode'], 'vk')
            self.assertEqual([r['id'] for r in data['resources']], ['one', 'two'])
            self.assertNotIn('fake-secret', output.getvalue())
            stub.assert_no_pending_responses()

    def test_sdk_access_denied_is_not_an_empty_resource_list(self):
        from botocore.stub import Stubber
        settings = load_s3_settings({'AWS_ACCESS_KEY_ID': 'fake-id',
                                     'AWS_SECRET_ACCESS_KEY': 'fake-secret'})
        provider = S3Provider.from_settings(settings)
        with Stubber(provider._client) as stub:
            stub.add_client_error('list_buckets', service_error_code='AccessDenied',
                                  service_message='fake-secret', http_status_code=403,
                                  expected_params={})
            with self.assertRaisesRegex(AuditError, 'denied'):
                provider.resources()
