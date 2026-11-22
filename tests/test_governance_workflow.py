from dataclasses import asdict
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock

from cloud_audit.rules.registry import default_rules
from cloud_audit.rules.engine import RuleEngine
from cloud_audit.services.audit import SecurityAuditService
from cloud_audit.services.snapshots import SnapshotService
from cloud_audit.models.security import AuditPolicy, PermissionRequirement
from cloud_audit.models.snapshot import CollectionOptions
from cloud_audit.configuration.policy import parse_audit_policy
from cloud_audit.errors import ConfigurationError
from cloud_audit.storage.json_reports import JsonReportRepository
from cloud_audit.storage.sqlite import SqliteReportRepository
from cloud_audit.providers.collection import S3ConfigurationCollector
from cloud_audit.storage.snapshots import JsonSnapshotRepository
from audit_fixtures import configured_client, failure


GOVERNANCE_RULES = ('unapproved-external-access', 'excess-explicit-permissions', 'bucket-acl-disabled')


class WorkflowTests(unittest.TestCase):
    def test_policy_supports_trusted_projects_acl_control_and_acl_write_permission(self):
        data = {'trusted_project_ids': ['inside'], 'required_controls': ['versioning', 'acl_disabled'],
                'required_permissions': [{'subject': 'app', 'operations': ['read', 'write_acl']}]}
        policy = parse_audit_policy(data)
        self.assertEqual(policy.trusted_project_ids, ('inside',))
        self.assertIn('write_acl', policy.required_permissions[0].operations)
        for change in ({'trusted_project_ids': 'inside'},
                       {'required_permissions': [{'subject': 'app', 'operations': ['read']}] * 2}):
            with self.subTest(change=change), self.assertRaises(ConfigurationError):
                parse_audit_policy(data | change)

    def test_registry_has_eight_unique_rules(self):
        rules = default_rules()
        self.assertEqual(len(rules), 8)
        self.assertEqual(len({row.id for row in rules}), 8)
        self.assertTrue(set(GOVERNANCE_RULES) <= {row.id for row in rules})

    def test_governance_policy_and_rules_roundtrip_in_report_and_offline_cli(self):
        client = configured_client()
        client.get_bucket_policy.side_effect = failure('NoSuchBucketPolicy')
        client.get_object_acl.return_value = {'Owner': {'ID': 'owner'}, 'Grants': [
            {'Grantee': {'Type': 'CanonicalUser', 'ID': 'external'}, 'Permission': 'READ'}]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshots = JsonSnapshotRepository(root / 'data' / 'snapshots')
            snapshot = SnapshotService(S3ConfigurationCollector(client), snapshots).collect('lab', CollectionOptions(('x',)))
            reports = JsonReportRepository(root / 'data')
            policy = AuditPolicy(trusted_project_ids=('inside',), required_controls=('acl_disabled',),
                required_permissions=(PermissionRequirement('external', ('read',)),))
            report = SecurityAuditService(RuleEngine(default_rules()), reports).audit(snapshot, policy, GOVERNANCE_RULES)
            self.assertEqual(reports.get(report.id), report)
            policy_path = root / 'policy.json'
            policy_path.write_text(json.dumps(asdict(policy)))
            env = dict(os.environ, CLOUD_AUDIT_STATE_DIR=directory)
            env.pop('AWS_ACCESS_KEY_ID', None)
            env.pop('AWS_SECRET_ACCESS_KEY', None)
            result = subprocess.run([sys.executable, '-m', 'cloud_audit', 'audit', '--profile', 'vk',
                '--snapshot', snapshot.id, '--policy', str(policy_path), '--rules', *GOVERNANCE_RULES],
                env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(result.stdout)
            self.assertEqual([x['rule_id'] for x in data['results']], list(GOVERNANCE_RULES))
            self.assertEqual(data['results'][-1]['status'], 'confirmed_violation')
            stored = SqliteReportRepository(root / 'data' / 'audit.sqlite3').get(data['id'])
            self.assertEqual(stored.policy.trusted_project_ids, ('inside',))


class ReportTests(unittest.TestCase):
    def test_acl_control_report_status_must_match_recorded_ownership(self):
        from audit_fixtures import config
        from cloud_audit.errors import AuditError
        with tempfile.TemporaryDirectory() as directory:
            repo = JsonReportRepository(Path(directory))
            report = SecurityAuditService(RuleEngine(default_rules()), repo).audit(config(), AuditPolicy(), ('bucket-acl-disabled',))
            path = Path(directory) / (report.id + '.json')
            raw = json.loads(path.read_text())
            raw['results'][0]['evidence'][0]['value'] = 'BucketOwnerEnforced'
            path.write_text(json.dumps(raw))
            with self.assertRaises(AuditError):
                repo.get(report.id)

    def test_governance_rules_honor_accepted_exception_without_hiding_evidence(self):
        from cloud_audit.models.security import RuleException
        from audit_fixtures import config
        policy = AuditPolicy(exceptions=(RuleException('lab', 'bucket-acl-disabled', 'Legacy uploader'),))
        report = SecurityAuditService(RuleEngine(default_rules()), Mock()).audit(
            config(), policy, ('bucket-acl-disabled',))
        self.assertEqual(report.results[0].exception_reason, 'Legacy uploader')
        self.assertEqual(report.results[0].status, 'potential_risk')
        self.assertTrue(report.results[0].evidence)


class EmptyPermissionBaselineTests(unittest.TestCase):
    def test_explicit_empty_operations_means_no_permissions_required_not_missing_baseline(self):
        from cloud_audit.rules.governance import ExcessPermissionsRule
        from audit_fixtures import named_statement
        from audit_fixtures import config
        subject = 'arn:aws:iam::outside:user/app'
        policy = parse_audit_policy({'trusted_project_ids': ['inside'],
            'required_permissions': [{'subject': subject, 'operations': []}]})
        finding = RuleEngine((ExcessPermissionsRule(),)).evaluate(config(statements=[named_statement(subject)]), policy)[0]
        self.assertEqual(finding.status, 'potential_risk')
        self.assertNotIn('required_permissions_baseline_missing', finding.limitations)
