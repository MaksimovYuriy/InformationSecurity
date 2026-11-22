"""End-to-end acceptance scenarios for all built-in rules and CLI workflows."""
from dataclasses import asdict, replace
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from uuid import uuid4

from cloud_audit.models.resources import Resource
from cloud_audit.models.security import AuditPolicy, PermissionRequirement, RuleException
from cloud_audit.models.snapshot import ConfigurationObservation as Observation, ConfigurationSnapshot, collection_limitations
from cloud_audit.storage.snapshots import JsonSnapshotRepository

SUBJECT = 'arn:aws:iam::outside:user/app'


def configuration(kind='private'):
    statements = []
    if kind == 'public':
        statements = [{'Effect': 'Allow', 'Principal': '*', 'Action': ['s3:GetObject', 's3:ListBucket', 's3:PutObject', 's3:DeleteObject'],
                       'Resource': ['arn:aws:s3:::lab', 'arn:aws:s3:::lab/*']}]
    elif kind in {'external', 'excess'}:
        statements = [{'Effect': 'Allow', 'Principal': {'AWS': SUBJECT},
                       'Action': ['s3:GetObject', 's3:DeleteObject'] if kind == 'excess' else 's3:GetObject',
                       'Resource': 'arn:aws:s3:::lab/*'}]
    observations = (
        Observation('bucket_acl', 'get_bucket_acl', 'available', {'owner_id': 'inside', 'grants': []}),
        Observation('object_acl:sample.txt', 'get_object_acl', 'available', {'owner_id': 'inside', 'grants': []}),
        Observation('bucket_policy', 'get_bucket_policy', 'available' if statements else 'absent',
                    {'document': {'Statement': statements}} if statements else None, None if statements else 'not_configured'),
        Observation('ownership_controls', 'get_bucket_ownership_controls', 'available', {'object_ownership': 'BucketOwnerPreferred' if kind == 'acl' else 'BucketOwnerEnforced'}),
        Observation('versioning', 'get_bucket_versioning', 'available', {'status': 'Disabled' if kind == 'versioning' else 'Enabled', 'mfa_delete': None}),
        Observation('public_access_block', 'get_public_access_block', 'unsupported', None, 'api_not_supported'),
    )
    observations += tuple(Observation(name, source, 'unsupported', None, 'api_not_supported') for name, source in (('logging', 'get_bucket_logging'), ('encryption', 'get_bucket_encryption'), ('object_lock', 'get_object_lock_configuration')))
    return ConfigurationSnapshot(uuid4().hex, 2, 'vk', Resource('lab', 'lab'), datetime.now(timezone.utc).isoformat(),
        'bucket_and_selected_objects', collection_limitations(('sample.txt',)),
        'partial', observations, ('sample.txt',), 'https://example.invalid')


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(('AWS_', 'CLOUD_AUDIT_S3_'))}
        self.env['CLOUD_AUDIT_STATE_DIR'] = str(self.root)
        self.env['PYTHONPATH'] = str(Path(__file__).resolve().parents[1] / 'src')
        self.snapshots = JsonSnapshotRepository(self.root / 'data' / 'snapshots')

    def cli(self, *args):
        result = subprocess.run([sys.executable, '-m', 'cloud_audit', *args], env=self.env, capture_output=True, text=True, timeout=30)
        return result, json.loads(result.stdout) if result.stdout else None

    def audit(self, data, rule, policy=None):
        self.snapshots.save(data)
        path = self.root / 'policy.json'
        path.write_text(json.dumps(asdict(policy or AuditPolicy(trusted_project_ids=('inside',)))))
        result, report = self.cli('audit', '--profile', 'vk', '--snapshot', data.id, '--rules', rule, '--policy', str(path))
        self.assertIn(result.returncode, (0, 3), result.stderr)
        return result, report

    def test_rule_matrix_private_risky_and_unavailable_through_cli(self):
        cases = [
            ('bucket-versioning-enabled', 'versioning', 'confirmed_violation', None),
            *[(f'anonymous-{op}', 'public', 'potential_risk', None) for op in ('read', 'list', 'write', 'delete')],
            ('unapproved-external-access', 'external', 'potential_risk', None),
            ('excess-explicit-permissions', 'excess', 'potential_risk', AuditPolicy(trusted_project_ids=('inside',), required_permissions=(PermissionRequirement(SUBJECT, ('read',)),))),
            ('bucket-acl-disabled', 'acl', 'potential_risk', None),
        ]
        for rule, kind, expected, policy in cases:
            with self.subTest(rule=rule):
                _, report = self.audit(configuration(kind), rule, policy)
                finding = report['results'][0]
                self.assertEqual(finding['status'], expected)
                self.assertTrue(finding['evidence'])
                self.assertTrue(finding['recommendation'])
                self.assertTrue(finding['verification'])
                self.assertGreater(finding['risk']['score'], 0)
                clean = configuration('external' if rule == 'excess-explicit-permissions' else 'private')
                clean_policy = policy
                if rule == 'excess-explicit-permissions':
                    clean_policy = replace(policy, allowed_external_accounts=('outside',))
                _, clean_report = self.audit(clean, rule, clean_policy)
                self.assertEqual(clean_report['results'][0]['status'], 'passed')
                missing = replace(clean, observations=tuple(replace(x, status='access_denied', data=None, reason='permission_required') for x in clean.observations))
                result, missing_report = self.audit(missing, rule, policy)
                self.assertEqual(result.returncode, 3)
                self.assertEqual(missing_report['results'][0]['status'], 'insufficient_data')
                self.assertIsNone(missing_report['results'][0]['risk']['score'])

    def test_exception_keeps_violation_and_changed_coverage_cannot_resolve(self):
        policy = AuditPolicy(exceptions=(RuleException('lab', 'bucket-versioning-enabled', 'Synthetic acceptance'),))
        _, before = self.audit(configuration('versioning'), 'bucket-versioning-enabled', policy)
        self.assertEqual(before['results'][0]['exception_reason'], 'Synthetic acceptance')
        self.assertEqual(before['results'][0]['status'], 'confirmed_violation')
        clean = configuration()
        clean = replace(clean, object_keys=(), scope='bucket_configuration_only', limitations=collection_limitations(()), observations=tuple(x for x in clean.observations if not x.name.startswith('object_acl:')))
        _, after = self.audit(clean, 'bucket-versioning-enabled', policy)
        result, comparison = self.cli('compare', before['id'], after['id'])
        self.assertEqual(result.returncode, 3)
        self.assertEqual(comparison['changes'][0]['change'], 'unverified')

    def test_fresh_remediation_history_export_and_repeated_snapshot(self):
        _, before = self.audit(configuration('versioning'), 'bucket-versioning-enabled')
        clean = configuration()
        _, after = self.audit(clean, 'bucket-versioning-enabled')
        result, comparison = self.cli('compare', before['id'], after['id'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(comparison['changes'][0]['change'], 'resolved')
        result, history = self.cli('history', '--resource', 'lab', '--rule', 'bucket-versioning-enabled')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(history['total'], 2)
        target = self.root / 'comparison.md'
        result, _ = self.cli('compare', before['id'], after['id'], '--format', 'markdown', '--output', str(target))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.assertIn('resolved', target.read_text())
        _, repeated = self.audit(clean, 'bucket-versioning-enabled')
        result, comparison = self.cli('compare', after['id'], repeated['id'])
        self.assertEqual(result.returncode, 0)
        self.assertEqual(comparison['changes'][0]['change'], 'unchanged')

    def test_cloud_error_history_never_creates_a_clean_report(self):
        from cloud_audit.storage.sqlite import SqliteReportRepository
        _, before = self.audit(configuration('versioning'), 'bucket-versioning-enabled')
        repo = SqliteReportRepository(self.root / 'data' / 'audit.sqlite3')
        failed = repo.record_failure('lab', ('bucket-versioning-enabled',), ('sample.txt',), 'cloud_request_failed')
        result, history = self.cli('history', '--resource', 'lab', '--run-status', 'failed')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(history['total'], 1)
        self.assertEqual(history['entries'][0]['status_counts'], {})
        result, comparison = self.cli('compare', before['id'], failed)
        self.assertEqual(result.returncode, 2)
        self.assertIsNone(comparison)

    def test_api_errors_and_unknown_conditions_remain_unverified(self):
        _, before = self.audit(configuration('public'), 'anonymous-read')
        for status, reason in [('access_denied', 'permission_required'), ('error', 'sdk_or_network_error'),
                               ('error', 'rate_limit'), ('unsupported', 'api_not_supported')]:
            with self.subTest(status=status, reason=reason):
                data = configuration()
                data = replace(data, observations=tuple(replace(x, status=status, data=None, reason=reason) if x.name == 'bucket_policy' else x for x in data.observations))
                result, after = self.audit(data, 'anonymous-read')
                self.assertEqual(result.returncode, 3)
                result, comparison = self.cli('compare', before['id'], after['id'])
                self.assertEqual(result.returncode, 3)
                self.assertEqual(comparison['changes'][0]['change'], 'unverified')
        data = configuration('public')
        policy_row = next(x for x in data.observations if x.name == 'bucket_policy')
        for statement in policy_row.data['document']['Statement']:
            statement['Condition'] = {'UnknownCondition': {'key': 'value'}}
        _, after = self.audit(data, 'anonymous-read')
        self.assertEqual(after['results'][0]['status'], 'insufficient_data')

    def test_default_eight_rules_persist_and_check_runs_without_cloud_credentials(self):
        data = configuration('external')
        self.snapshots.save(data)
        policy = AuditPolicy(trusted_project_ids=('inside',), allowed_external_accounts=('outside',),
                             required_permissions=(PermissionRequirement(SUBJECT, ('read',)),))
        path = self.root / 'policy.json'
        path.write_text(json.dumps(asdict(policy)))
        result, checked = self.cli('check')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(checked['status'], 'ok')
        result, report = self.cli('audit', '--profile', 'vk', '--snapshot', data.id, '--policy', str(path))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(report['results']), 8)
        self.assertEqual({row['status'] for row in report['results']}, {'passed'})
        result, saved = self.cli('report', report['id'])
        self.assertEqual(result.returncode, 0)
        self.assertEqual(saved['results'], report['results'])

    def test_no_selected_objects_never_means_read_access_was_checked(self):
        data = configuration()
        data = replace(data, object_keys=(), scope='bucket_configuration_only', limitations=collection_limitations(()),
                       observations=tuple(x for x in data.observations if not x.name.startswith('object_acl:')))
        result, report = self.audit(data, 'anonymous-read')
        self.assertEqual(result.returncode, 3)
        self.assertEqual(report['results'][0]['status'], 'insufficient_data')

    def test_live_cli_collection_failures_are_recorded_without_false_remediation(self):
        import contextlib
        import io
        from unittest.mock import Mock, patch
        from cloud_audit.errors import AuditError
        from cloud_audit.cli import main
        from cloud_audit.providers.s3 import S3Provider
        from cloud_audit.storage.sqlite import SqliteReportRepository
        from cloud_audit.models.history import HistoryQuery
        _, before = self.audit(configuration('public'), 'anonymous-read')
        for message in ('Cloud access denied', 'Cloud request failed', 'Cloud resource not found'):
            with self.subTest(message=message):
                provider = Mock(mode='vk', namespace='https://example.invalid')
                provider.collect.side_effect = AuditError(message)
                with (patch.dict(os.environ, dict(self.env, AWS_ACCESS_KEY_ID='synthetic', AWS_SECRET_ACCESS_KEY='synthetic')),
                      patch('sys.argv', ['cloud-audit', 'audit', '--profile', 'vk', '--resource', 'lab', '--rules', 'anonymous-read']),
                      patch.object(S3Provider, 'from_settings', return_value=provider),
                      contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught):
                    main()
                self.assertEqual(caught.exception.code, 2)
        repo = SqliteReportRepository(self.root / 'data' / 'audit.sqlite3')
        failed = repo.history(HistoryQuery(resource_id='lab', run_status='failed'))
        self.assertEqual(failed.total, 3)
        for entry in failed.entries:
            self.assertEqual(entry.status_counts, {})
            result, comparison = self.cli('compare', before['id'], entry.id)
            self.assertEqual(result.returncode, 2)
            self.assertIsNone(comparison)
