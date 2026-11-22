import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest.mock import Mock, patch

from cloud_audit.cli import main
from cloud_audit.infrastructure.s3 import S3Provider
from cloud_audit.infrastructure.anonymous import AnonymousProber
from cloud_audit.infrastructure.reports import JsonReportRepository
from pathlib import Path
from test_configuration_snapshot import configured_client, failure


class AccessCliTests(unittest.TestCase):
    def test_live_cli_selection_and_probes_roundtrip_all_eight_rules(self):
        signed, anon = configured_client(), Mock()
        signed.get_bucket_policy.side_effect = failure('NoSuchBucketPolicy')
        signed.get_object_acl.return_value = {'Owner': {'ID': 'owner'}, 'Grants': []}
        anon.get_object.return_value = {'ResponseMetadata': {'HTTPStatusCode': 206}, 'Body': io.BytesIO(b'x')}
        anon.list_objects_v2.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
        provider = S3Provider(signed, AnonymousProber(anon))
        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            with patch.dict(os.environ, {'CLOUD_AUDIT_STATE_DIR': directory, 'AWS_ACCESS_KEY_ID': 'fake',
                                         'AWS_SECRET_ACCESS_KEY': 'fake'}), \
                 patch('sys.argv', ['cloud-audit', 'audit', '--profile', 'vk', '--resource', 'lab',
                                    '--objects', 'sample.txt', '--probe-anonymous']), \
                 patch.object(S3Provider, 'from_settings', return_value=provider), \
                 contextlib.redirect_stdout(output):
                self.assertEqual(main(), 3)
            report = json.loads(output.getvalue())
            self.assertEqual(len(report['results']), 8)
            self.assertEqual(report['object_keys'], ['sample.txt'])
            self.assertEqual(JsonReportRepository(Path(directory) / 'data').get(report['id']).results[1].status,
                             'confirmed_violation')
            anon.put_object.assert_not_called()
            signed.put_object.assert_not_called()

    def test_probe_flags_cannot_mutate_offline_or_demo_or_without_opt_in(self):
        combinations = [ ['--profile', 'vk', '--snapshot', 'a' * 32, '--probe-anonymous'],
                         ['--resource', 'demo-public', '--probe-anonymous'],
                         ['--profile', 'vk', '--resource', 'lab', '--allow-write-probes'] ]
        for args in combinations:
            with self.subTest(args=args), patch('sys.argv', ['cloud-audit', 'audit', *args]), \
                 contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                main()
            self.assertEqual(error.exception.code, 2)


class AccessReportIntegrityTests(unittest.TestCase):
    def test_confirmed_access_requires_a_positive_unsigned_request_in_saved_evidence(self):
        from dataclasses import replace
        from cloud_audit.application.audit import AuditError
        from cloud_audit.application.rules import RuleEngine
        from cloud_audit.application.security_audit import SecurityAuditService
        from cloud_audit.domain.public_access import PublicAccessRule
        from cloud_audit.domain.rules import AuditPolicy
        from cloud_audit.domain.snapshot import ConfigurationObservation
        from test_public_access import config
        data = config()
        proof = ConfigurationObservation('anonymous_read:sample.txt', 'anonymous_get_object', 'available', {
            'outcome': 'allowed', 'http_status': 206, 'object_key': 'sample.txt', 'checked_at': data.collected_at})
        data = replace(data, observations=(*data.observations, proof))
        with tempfile.TemporaryDirectory() as directory:
            repo = JsonReportRepository(Path(directory))
            report = SecurityAuditService(RuleEngine((PublicAccessRule('read'),)), repo).audit(data, AuditPolicy())
            raw = json.loads((Path(directory) / (report.id + '.json')).read_text())
            evidence = next(x for x in raw['results'][0]['evidence'] if x['source'] == 'anonymous_get_object')
            changed = json.loads(evidence['value']) | {'outcome': 'denied', 'http_status': 403}
            evidence['value'] = json.dumps(changed)
            (Path(directory) / (report.id + '.json')).write_text(json.dumps(raw))
            with self.assertRaises(AuditError):
                repo.get(report.id)
