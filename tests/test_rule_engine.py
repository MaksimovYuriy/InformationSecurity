from dataclasses import replace
from datetime import datetime, timedelta, timezone
import unittest

from cloud_audit.application.audit import AuditError
from cloud_audit.application.rules import RuleEngine
from cloud_audit.domain.audit import Resource
from cloud_audit.domain.rules import AuditPolicy, RuleException
from cloud_audit.domain.snapshot import ConfigurationObservation, ConfigurationSnapshot, LIMITATIONS
from cloud_audit.domain.versioning import VersioningRule


def snapshot(value='Disabled', status='available'):
    return ConfigurationSnapshot('a' * 32, 1, 'vk', Resource('lab', 'lab'),
        datetime.now(timezone.utc).isoformat(), 'bucket_configuration_only', LIMITATIONS,
        'partial', (ConfigurationObservation('versioning', 'get_bucket_versioning', status,
                     {'status': value, 'mfa_delete': None} if status == 'available' else None,
                     None if status == 'available' else 'api_not_supported'),))


class RuleEngineTests(unittest.TestCase):
    def setUp(self):
        self.engine = RuleEngine((VersioningRule(),))

    def test_versioning_states_evidence_risk_and_recommendation(self):
        for value, expected in [('Enabled', 'passed'), ('Disabled', 'confirmed_violation'),
                                ('Suspended', 'confirmed_violation')]:
            with self.subTest(value=value):
                result = self.engine.evaluate(snapshot(value), AuditPolicy())[0]
                self.assertEqual(result.status, expected)
                self.assertEqual(result.evidence[0].value, value)
                self.assertEqual(result.evidence[0].source, 'get_bucket_versioning')
                if value != 'Enabled':
                    self.assertEqual(result.risk.score, 4)
                    self.assertEqual(result.risk.level, 'medium')
                    self.assertTrue(result.recommendation)
                    self.assertTrue(result.verification)
                else:
                    self.assertEqual(result.risk.score, 0)

    def test_missing_denied_and_unsupported_are_not_passed_even_with_an_exception(self):
        policy = AuditPolicy(exceptions=(RuleException('lab', 'bucket-versioning-enabled', 'Training data'),))
        for status in ('absent', 'access_denied', 'unsupported', 'error'):
            with self.subTest(status=status):
                result = self.engine.evaluate(snapshot(status=status), policy)[0]
                self.assertEqual(result.status, 'insufficient_data')
                self.assertIsNone(result.risk.score)
                self.assertIsNone(result.exception_reason)
        missing = replace(snapshot(), observations=())
        self.assertEqual(self.engine.evaluate(missing, AuditPolicy())[0].status, 'insufficient_data')

    def test_exception_preserves_finding_and_expiry_and_resource_boundaries(self):
        exception = RuleException('lab', 'bucket-versioning-enabled', 'Disposable training files')
        result = self.engine.evaluate(snapshot(), AuditPolicy(exceptions=(exception,)))[0]
        self.assertEqual(result.status, 'confirmed_violation')
        self.assertEqual(result.exception_reason, exception.reason)
        expired = replace(exception, expires_at=(datetime.now(timezone.utc) - timedelta(days=1)).isoformat())
        for item in (expired, replace(exception, resource_id='other')):
            self.assertIsNone(self.engine.evaluate(snapshot(), AuditPolicy(exceptions=(item,)))[0].exception_reason)

    def test_context_changes_risk_and_optional_control_is_potential(self):
        policy = AuditPolicy(data_sensitivity='high', required_controls=())
        result = self.engine.evaluate(snapshot(), policy)[0]
        self.assertEqual(result.status, 'potential_risk')
        self.assertEqual(result.risk.score, 6)
        self.assertEqual(result.risk.level, 'high')
        self.assertIn('unknown', self.engine.evaluate(snapshot(), AuditPolicy())[0].risk.rationale)

    def test_rule_registry_selection_applicability_and_determinism(self):
        with self.assertRaises(AuditError):
            self.engine.evaluate(snapshot(), AuditPolicy(), ('unknown',))
        with self.assertRaises(ValueError):
            RuleEngine((VersioningRule(), VersioningRule()))
        data = snapshot()
        self.assertEqual(self.engine.evaluate(data, AuditPolicy()), self.engine.evaluate(data, AuditPolicy()))
        self.assertEqual(len(self.engine.evaluate(data, AuditPolicy(), ('bucket-versioning-enabled',) * 2)), 1)
        not_applicable = replace(data, scope='object_only')
        self.assertEqual(self.engine.evaluate(not_applicable, AuditPolicy())[0].status, 'not_applicable')

    def test_malformed_available_evidence_is_insufficient_data(self):
        for value in ('unexpected', [], {}):
            data = replace(snapshot(), observations=(ConfigurationObservation(
                'versioning', 'get_bucket_versioning', 'available', {'status': value}),))
            with self.subTest(value=value):
                self.assertEqual(self.engine.evaluate(data, AuditPolicy())[0].status, 'insufficient_data')


class ExtensibilityTests(unittest.TestCase):
    def test_second_rule_can_use_known_absence_without_changing_engine(self):
        from cloud_audit.domain.rules import Finding, RiskModel, Evidence
        class PolicyAbsenceRule:
            id = 'test-policy-absence'
            required_data = ('bucket_policy',)
            recommendation = ''
            verification = ''
            def applicable(self, snapshot, policy):
                return True
            def evaluate(self, snapshot, policy):
                return Finding(self.id, 'potential_risk', 'Known policy absence is evidence',
                    (Evidence('bucket_policy', 'get_bucket_policy', 'absent', None),),
                    RiskModel().assess('potential_risk', policy.data_sensitivity), '', '')
        data = replace(snapshot(), observations=(*snapshot().observations,
            ConfigurationObservation('bucket_policy', 'get_bucket_policy', 'absent', None, 'not_configured')))
        findings = RuleEngine((VersioningRule(), PolicyAbsenceRule())).evaluate(data, AuditPolicy())
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[1].status, 'potential_risk')
