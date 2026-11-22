from audit_fixtures import version_report
from dataclasses import replace
from datetime import datetime, timedelta
import unittest
from unittest.mock import Mock

from cloud_audit.services.comparison import ReportComparisonService
from cloud_audit.rules.engine import RuleEngine
from cloud_audit.services.audit import SecurityAuditService
from cloud_audit.models.security import AuditPolicy




def compare(before, after):
    return ReportComparisonService().compare(before, after)


class ComparisonTests(unittest.TestCase):
    def test_new_persisted_and_resolved_findings(self):
        for old, new, expected in [('Enabled', 'Disabled', 'new'), ('Disabled', 'Suspended', 'persisted'),
                                   ('Disabled', 'Enabled', 'resolved'), ('Enabled', 'Enabled', 'unchanged')]:
            with self.subTest(old=old, new=new):
                result = compare(version_report(old), version_report(new, 1))
                self.assertEqual(result.changes[0].change, expected)
                self.assertTrue(result.comparable)

    def test_scope_resource_policy_and_ruleset_changes_prevent_false_resolution(self):
        before = version_report('Disabled')
        after = version_report('Enabled', 1)
        for altered in (replace(after, object_keys=('different',), scope='bucket_and_selected_objects'),
                        replace(after, resource=replace(after.resource, id='other')),
                        replace(after, policy=replace(after.policy, required_controls=())),
                        replace(after, ruleset_version='other'),
                        replace(after, ruleset_version=None)):
            with self.subTest(after=altered):
                result = compare(before, altered)
                self.assertFalse(result.comparable)
                self.assertEqual(result.changes[0].change, 'unverified')

    def test_missing_and_insufficient_results_never_count_as_resolved(self):
        before = version_report('Disabled')
        after = version_report('Enabled', 1)
        unknown = replace(after.results[0], status='insufficient_data')
        for altered in (replace(after, results=()), replace(after, results=(unknown,), evaluation_status='incomplete')):
            result = compare(before, altered)
            self.assertEqual(result.changes[0].change, 'unverified')

    def test_exception_acceptance_does_not_resolve_a_finding(self):
        before = version_report('Disabled')
        after = version_report('Disabled', 1)
        from cloud_audit.models.security import RuleException
        after = replace(after, policy=replace(after.policy, exceptions=(RuleException('lab', 'bucket-versioning-enabled', 'Accepted'),)),
                        results=(replace(after.results[0], exception_reason='Accepted'),))
        self.assertEqual(compare(before, after).changes[0].change, 'persisted')

    def test_reanalysis_of_same_snapshot_does_not_prove_remediation(self):
        before = version_report('Disabled')
        after = replace(version_report('Enabled'), snapshot_collected_at=before.snapshot_collected_at,
                        snapshot_id=before.snapshot_id)
        self.assertEqual(compare(before, after).changes[0].change, 'unverified')

    def test_runtime_confirmation_requires_matching_new_denial(self):
        from audit_fixtures import config
        from cloud_audit.rules.public_access import PublicAccessRule
        from cloud_audit.models.snapshot import ConfigurationObservation
        data = replace(config(), resource_namespace='https://example.invalid')
        proof = ConfigurationObservation('anonymous_read:sample.txt', 'anonymous_get_object', 'available', {
            'outcome': 'allowed', 'http_status': 206, 'object_key': 'sample.txt', 'checked_at': data.collected_at})
        data = replace(data, observations=(*data.observations, proof))
        service = SecurityAuditService(RuleEngine((PublicAccessRule('read'),)), Mock())
        before = service.audit(data, AuditPolicy())
        later = (datetime.fromisoformat(data.collected_at) + timedelta(minutes=1)).isoformat()
        closed = replace(data, collected_at=later, id='b' * 32,
                         observations=tuple(x for x in data.observations if not x.name.startswith('anonymous_')))
        self.assertEqual(compare(before, service.audit(closed, AuditPolicy())).changes[0].change, 'unverified')
        denial = replace(proof, data=proof.data | {'outcome': 'denied', 'http_status': 403, 'checked_at': later})
        after = service.audit(replace(closed, observations=(*closed.observations, denial)), AuditPolicy())
        self.assertEqual(compare(before, after).changes[0].change, 'resolved')


class NamespaceComparisonTests(unittest.TestCase):
    def test_same_bucket_name_on_another_or_unknown_endpoint_is_not_same_resource(self):
        before = replace(version_report('Disabled'), resource_namespace='https://one.example')
        after = replace(version_report('Enabled', 1), resource_namespace='https://two.example')
        result = compare(before, after)
        self.assertFalse(result.comparable)
        self.assertEqual(result.changes[0].change, 'unverified')
        self.assertEqual(result.before_context.resource_namespace, 'https://one.example')
        after = replace(after, resource_namespace=None)
        self.assertFalse(compare(before, after).comparable)


class ReanalysisComparisonTests(unittest.TestCase):
    def test_same_observation_cannot_be_claimed_as_new_incident(self):
        before = version_report('Enabled')
        after = replace(version_report('Disabled'), snapshot_id=before.snapshot_id,
                        snapshot_collected_at=before.snapshot_collected_at)
        self.assertEqual(compare(before, after).changes[0].change, 'unverified')
