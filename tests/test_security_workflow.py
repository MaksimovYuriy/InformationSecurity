from dataclasses import asdict
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock

from cloud_audit.application.rules import RuleEngine
from cloud_audit.application.security_audit import SecurityAuditService
from cloud_audit.application.snapshot import SnapshotService
from cloud_audit.domain.rules import AuditPolicy
from cloud_audit.domain.versioning import VersioningRule
from cloud_audit.infrastructure.audit_policy import load_audit_policy
from cloud_audit.infrastructure.configuration import ConfigurationError
from cloud_audit.infrastructure.reports import JsonReportRepository
from cloud_audit.infrastructure.s3_configuration import S3ConfigurationCollector
from cloud_audit.infrastructure.snapshots import JsonSnapshotRepository
from test_configuration_snapshot import configured_client


class PolicyTests(unittest.TestCase):
    def test_policy_parsing_and_rejection_without_leaking_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'policy.json'
            data = {'data_sensitivity': 'high', 'required_controls': [],
                    'allowed_external_accounts': ['trusted-account'],
                    'required_permissions': [{'subject': 'app', 'operations': ['read', 'list']}],
                    'exceptions': [{'resource_id': 'lab', 'rule_id': 'bucket-versioning-enabled',
                                    'reason': 'Disposable files'}]}
            path.write_text(json.dumps(data))
            policy = load_audit_policy(path)
            self.assertEqual(policy.allowed_external_accounts, ('trusted-account',))
            self.assertEqual(policy.required_permissions[0].operations, ('read', 'list'))
            for change in ({'data_sensitivity': 'SECRET'}, {'unknown': 'SECRET'},
                           {'exceptions': [{'resource_id': 'lab', 'rule_id': 'x', 'reason': ''}]},
                           {'required_controls': 'versioning'},
                           {'exceptions': [{'resource_id': 'lab', 'rule_id': 'x', 'reason': 'why',
                                            'expires_at': '2026-11-22'}]}):
                path.write_text(json.dumps(data | change))
                with self.subTest(change=change), self.assertRaises(ConfigurationError) as caught:
                    load_audit_policy(path)
                self.assertNotIn('SECRET', str(caught.exception))


class SecurityWorkflowTests(unittest.TestCase):
    def test_service_report_roundtrip_and_cli_offline_preserve_context_and_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            snapshots = JsonSnapshotRepository(root / 'data' / 'snapshots')
            snapshot = SnapshotService(S3ConfigurationCollector(configured_client()), snapshots).collect('lab')
            reports = JsonReportRepository(root / 'data')
            service = SecurityAuditService(RuleEngine((VersioningRule(),)), reports)
            report = service.audit(snapshot, AuditPolicy())
            self.assertEqual(reports.get(report.id), report)
            self.assertEqual(report.results[0].status, 'confirmed_violation')
            self.assertEqual(report.snapshot_id, snapshot.id)
            self.assertEqual((root / 'data' / (report.id + '.json')).stat().st_mode & 0o777, 0o600)
            env = dict(os.environ, CLOUD_AUDIT_STATE_DIR=directory)
            env.pop('AWS_ACCESS_KEY_ID', None)
            env.pop('AWS_SECRET_ACCESS_KEY', None)
            result = subprocess.run([sys.executable, '-m', 'cloud_audit', 'audit', '--profile', 'vk',
                                     '--snapshot', snapshot.id, '--rules', 'bucket-versioning-enabled'], capture_output=True, text=True, env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            saved = json.loads(result.stdout)
            self.assertEqual(saved['results'][0]['status'], 'confirmed_violation')
            read = subprocess.run([sys.executable, '-m', 'cloud_audit', 'report', saved['id'], '--format', 'text'],
                                  capture_output=True, text=True, env=env)
            self.assertEqual(read.returncode, 0, read.stderr)
            self.assertIn('VK CLOUD', read.stdout)
            self.assertNotIn('security not assessed', read.stdout)
            raw = json.loads((root / 'data' / (report.id + '.json')).read_text())
            raw['results'][0]['status'] = 'invented'
            (root / 'data' / (report.id + '.json')).write_text(json.dumps(raw))
            from cloud_audit.application.audit import AuditError
            with self.assertRaises(AuditError):
                reports.get(report.id)

    def test_insufficient_required_evidence_returns_incomplete_evaluation(self):
        collector = S3ConfigurationCollector(configured_client())
        client = configured_client()
        from test_configuration_snapshot import failure
        client.get_bucket_versioning.side_effect = failure('AccessDenied')
        snapshot = SnapshotService(S3ConfigurationCollector(client), Mock()).collect('lab')
        report = SecurityAuditService(RuleEngine((VersioningRule(),)), Mock()).audit(snapshot, AuditPolicy())
        self.assertEqual(report.evaluation_status, 'incomplete')
        self.assertEqual(report.results[0].status, 'insufficient_data')


class StrictPolicyTests(unittest.TestCase):
    def test_configuration_arrays_must_not_accept_objects_or_null(self):
        from cloud_audit.infrastructure.audit_policy import parse_audit_policy
        for key in ('required_permissions', 'exceptions'):
            for value in ({}, None, 'bad'):
                with self.subTest(key=key, value=value), self.assertRaises(ConfigurationError):
                    parse_audit_policy({key: value})

    def test_saved_finding_requires_evidence_and_consistent_risk(self):
        from cloud_audit.application.audit import AuditError
        with tempfile.TemporaryDirectory() as directory:
            snapshots = JsonSnapshotRepository(Path(directory) / 'snapshots')
            snapshot = SnapshotService(S3ConfigurationCollector(configured_client()), snapshots).collect('lab')
            repo = JsonReportRepository(Path(directory))
            report = SecurityAuditService(RuleEngine((VersioningRule(),)), repo).audit(snapshot, AuditPolicy())
            path = Path(directory) / (report.id + '.json')
            original = json.loads(path.read_text())
            for change in ({'evidence': []}, {'risk': original['results'][0]['risk'] | {'score': 9}}):
                data = json.loads(json.dumps(original))
                data['results'][0].update(change)
                path.write_text(json.dumps(data))
                with self.subTest(change=change), self.assertRaises(AuditError):
                    repo.get(report.id)


class PolicyCliTests(unittest.TestCase):
    def test_exception_and_missing_evidence_are_preserved_through_cli_and_saved_report(self):
        from test_configuration_snapshot import failure
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = JsonSnapshotRepository(root / 'data' / 'snapshots')
            policy = root / 'policy.json'
            policy.write_text(json.dumps({'exceptions': [{'resource_id': 'lab',
                'rule_id': 'bucket-versioning-enabled', 'reason': 'Disposable training data'}]}))
            env = dict(os.environ, CLOUD_AUDIT_STATE_DIR=directory)
            for unavailable in (False, True):
                client = configured_client()
                if unavailable:
                    client.get_bucket_versioning.side_effect = failure('AccessDenied')
                snapshot = SnapshotService(S3ConfigurationCollector(client), repo).collect('lab')
                result = subprocess.run([sys.executable, '-m', 'cloud_audit', 'audit', '--profile', 'vk',
                    '--snapshot', snapshot.id, '--policy', str(policy), '--rules', 'bucket-versioning-enabled'], env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 3 if unavailable else 0, result.stderr)
                finding = json.loads(result.stdout)['results'][0]
                self.assertEqual(finding['status'], 'insufficient_data' if unavailable else 'confirmed_violation')
                self.assertEqual(finding['exception_reason'], None if unavailable else 'Disposable training data')
