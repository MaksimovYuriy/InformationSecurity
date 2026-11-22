from dataclasses import replace
import json
import unittest

from cloud_audit.application.rules import RuleEngine
from cloud_audit.domain.governance_rules import ExternalAccessRule, ExcessPermissionsRule, AclDisabledRule
from cloud_audit.domain.rules import AuditPolicy, PermissionRequirement, RuleException
from cloud_audit.domain.snapshot import ConfigurationObservation
from test_public_access import config, statement, grant, ALL


def named_statement(subject='arn:aws:iam::outside:user/app', action='s3:GetObject', **extra):
    return statement(Principal={'AWS': subject}, Action=action, **extra)


def run(rule, data, policy=None):
    return RuleEngine((rule,)).evaluate(data, policy or AuditPolicy())[0]


class ExternalAccessTests(unittest.TestCase):
    def test_unapproved_project_is_risk_and_approved_project_or_subject_is_allowed(self):
        subject = 'arn:aws:iam::outside:user/app'
        data = config(statements=[named_statement(subject)])
        for approved, expected in [((), 'potential_risk'), (('outside',), 'passed'), ((subject,), 'passed')]:
            policy = AuditPolicy(trusted_project_ids=('inside',), allowed_external_accounts=approved)
            self.assertEqual(run(ExternalAccessRule(), data, policy).status, expected)

    def test_policy_subject_cannot_be_classified_without_own_project_context(self):
        result = run(ExternalAccessRule(), config(statements=[named_statement()]))
        self.assertEqual(result.status, 'insufficient_data')
        self.assertIn('trusted_project_context_missing', result.limitations)

    def test_owner_is_trusted_but_foreign_object_owner_is_not_automatically_trusted(self):
        data = config(object_grants=({'principal_type': 'CanonicalUser', 'principal': 'outside', 'permission': 'READ'},))
        self.assertEqual(run(ExternalAccessRule(), data).status, 'potential_risk')
        self.assertEqual(run(ExternalAccessRule(), data, AuditPolicy(allowed_external_accounts=('outside',))).status, 'passed')
        own = config(bucket_grants=({'principal_type': 'CanonicalUser', 'principal': 'owner', 'permission': 'FULL_CONTROL'},))
        self.assertEqual(run(ExternalAccessRule(), own).status, 'passed')

    def test_deny_blocks_named_allow_and_acl_but_conditions_prevent_safe_conclusion(self):
        policy = AuditPolicy(trusted_project_ids=('inside',))
        data = config(statements=[named_statement(), named_statement(Effect='Deny')])
        self.assertEqual(run(ExternalAccessRule(), data, policy).status, 'passed')
        data = config(statements=[named_statement(Effect='Deny', Condition={'Unknown': {'x': 'y'}})])
        self.assertEqual(run(ExternalAccessRule(), data, policy).status, 'insufficient_data')

    def test_all_users_is_other_rule_but_authenticated_users_is_external_group(self):
        self.assertEqual(run(ExternalAccessRule(), config(bucket_grants=(grant('READ'),))).status, 'passed')
        data = config(bucket_grants=(grant('READ', ALL.replace('AllUsers', 'AuthenticatedUsers')),))
        self.assertEqual(run(ExternalAccessRule(), data).status, 'potential_risk')

    def test_unavailable_data_and_enforced_acl_semantics(self):
        data = config(bucket_grants=({'principal_type': 'CanonicalUser', 'principal': 'outside', 'permission': 'READ'},),
                      ownership='BucketOwnerEnforced')
        self.assertEqual(run(ExternalAccessRule(), data).status, 'passed')
        data = config()
        observations = tuple(replace(x, status='access_denied', data=None, reason='permission_required')
                             if x.name == 'bucket_policy' else x for x in data.observations)
        self.assertEqual(run(ExternalAccessRule(), replace(data, observations=observations)).status, 'insufficient_data')


class ExcessPermissionsTests(unittest.TestCase):
    def test_required_baseline_is_mandatory_and_overbroad_grant_is_evidence(self):
        subject = 'arn:aws:iam::outside:user/app'
        data = config(statements=[named_statement(subject, action=['s3:GetObject', 's3:DeleteObject'])])
        self.assertEqual(run(ExcessPermissionsRule(), data).status, 'insufficient_data')
        policy = AuditPolicy(trusted_project_ids=('inside',), required_permissions=(PermissionRequirement(subject, ('read',)),))
        result = run(ExcessPermissionsRule(), data, policy)
        self.assertEqual(result.status, 'potential_risk')
        self.assertIn('delete', result.explanation)
        policy = replace(policy, required_permissions=(PermissionRequirement(subject, ('read', 'delete')),))
        self.assertEqual(run(ExcessPermissionsRule(), data, policy).status, 'passed')

    def test_acl_bucket_write_expands_to_delete_while_object_full_control_does_not(self):
        row = {'principal_type': 'CanonicalUser', 'principal': 'outside', 'permission': 'WRITE'}
        data = config(bucket_grants=(row,))
        policy = AuditPolicy(required_permissions=(PermissionRequirement('outside', ('write',)),))
        self.assertEqual(run(ExcessPermissionsRule(), data, policy).status, 'potential_risk')
        data = config(object_grants=(row | {'permission': 'FULL_CONTROL'},))
        policy = replace(policy, required_permissions=(PermissionRequirement('outside', ('read', 'read_acl', 'write_acl')),))
        self.assertEqual(run(ExcessPermissionsRule(), data, policy).status, 'passed')

    def test_wildcard_unknown_actions_and_conditional_denies_are_not_full_pass(self):
        subject = 'arn:aws:iam::outside:user/app'
        policy = AuditPolicy(trusted_project_ids=('inside',), required_permissions=(PermissionRequirement(subject, ('read',)),))
        self.assertEqual(run(ExcessPermissionsRule(), config(statements=[named_statement(action='s3:*')]), policy).status,
                         'potential_risk')
        data = config(statements=[named_statement(action='s3:DeleteBucket')])
        self.assertEqual(run(ExcessPermissionsRule(), data, policy).status, 'insufficient_data')
        data = config(statements=[named_statement(), named_statement(Effect='Deny', Condition={'Unknown': {'x': 'y'}})])
        self.assertEqual(run(ExcessPermissionsRule(), data, policy).status, 'insufficient_data')

    def test_project_grant_and_user_specific_deny_are_evaluated_for_requested_user(self):
        subject = 'arn:aws:iam::outside:user/app'
        data = config(statements=[named_statement('outside', action='s3:DeleteObject'),
                                 named_statement(subject, action='s3:DeleteObject', Effect='Deny')])
        policy = AuditPolicy(trusted_project_ids=('inside',), required_permissions=(PermissionRequirement(subject, ('read',)),))
        self.assertEqual(run(ExcessPermissionsRule(), data, policy).status, 'passed')

    def test_implicit_internal_permissions_prevent_global_least_privilege_claim(self):
        policy = AuditPolicy(required_permissions=(PermissionRequirement('owner', ('read',)),))
        self.assertEqual(run(ExcessPermissionsRule(), config(), policy).status, 'insufficient_data')


class AclDisabledTests(unittest.TestCase):
    def test_enforced_is_passed_and_preferred_is_risk_or_baseline_violation(self):
        self.assertEqual(run(AclDisabledRule(), config(ownership='BucketOwnerEnforced')).status, 'passed')
        self.assertEqual(run(AclDisabledRule(), config()).status, 'potential_risk')
        policy = AuditPolicy(required_controls=('versioning', 'acl_disabled'))
        self.assertEqual(run(AclDisabledRule(), config(), policy).status, 'confirmed_violation')

    def test_missing_ownership_is_unknown_and_exception_does_not_hide_it(self):
        data = config()
        data = replace(data, observations=tuple(x for x in data.observations if x.name != 'ownership_controls'))
        policy = AuditPolicy(exceptions=(RuleException('lab', 'bucket-acl-disabled', 'Legacy uploader'),))
        result = run(AclDisabledRule(), data, policy)
        self.assertEqual(result.status, 'insufficient_data')
        self.assertIsNone(result.exception_reason)


class GovernanceBoundariesTests(unittest.TestCase):
    def test_unobserved_subject_and_missing_project_context_are_incomplete(self):
        for subject in ('not-observed', 'arn:aws:iam::unknown:user/app'):
            policy = AuditPolicy(trusted_project_ids=('inside',), required_permissions=(PermissionRequirement(subject, ('read',)),))
            self.assertEqual(run(ExcessPermissionsRule(), config(), policy).status, 'insufficient_data')

    def test_private_owner_acl_without_object_selection_is_not_external_exposure(self):
        data = config(bucket_grants=({'principal_type': 'CanonicalUser', 'principal': 'owner', 'permission': 'FULL_CONTROL'},))
        data = replace(data, object_keys=(), scope='bucket_configuration_only',
                       observations=tuple(x for x in data.observations if not x.name.startswith('object_acl:')))
        self.assertEqual(run(ExternalAccessRule(), data).status, 'passed')

    def test_ignore_public_acls_applies_to_unbounded_groups_but_not_named_canonical_grants(self):
        group = grant('READ', ALL.replace('AllUsers', 'AuthenticatedUsers'))
        data = config(bucket_grants=(group,))
        block = ConfigurationObservation('public_access_block', 'get_public_access_block', 'available',
            {'block_public_acls': True, 'ignore_public_acls': True,
             'block_public_policy': False, 'restrict_public_buckets': False})
        data = replace(data, observations=tuple(block if x.name == 'public_access_block' else x for x in data.observations))
        self.assertEqual(run(ExternalAccessRule(), data).status, 'passed')
        original = config(bucket_grants=({'principal_type': 'CanonicalUser', 'principal': 'outside', 'permission': 'READ'},))
        original = replace(original, observations=tuple(block if x.name == 'public_access_block' else x for x in original.observations))
        self.assertEqual(run(ExternalAccessRule(), original).status, 'potential_risk')


class SubjectCoverageTests(unittest.TestCase):
    def test_authenticated_group_grants_also_apply_to_configured_authenticated_user(self):
        subject = 'arn:aws:iam::outside:user/app'
        data = config(bucket_grants=(grant('WRITE', ALL.replace('AllUsers', 'AuthenticatedUsers')),),
                      statements=[named_statement(subject)])
        policy = AuditPolicy(trusted_project_ids=('inside',),
                             required_permissions=(PermissionRequirement(subject, ('read',)),))
        self.assertEqual(run(ExcessPermissionsRule(), data, policy).status, 'potential_risk')

    def test_unsupported_principal_form_cannot_hide_additional_grants(self):
        subject = 'arn:aws:iam::outside:user/app'
        policy = AuditPolicy(trusted_project_ids=('inside',),
                             required_permissions=(PermissionRequirement(subject, ('read',)),))
        for unsupported in ('arn:aws:iam::outside:root', 'arn:aws:iam::outside:user/app*'):
            data = config(statements=[named_statement(subject),
                named_statement(unsupported, action='s3:DeleteObject')])
            with self.subTest(unsupported=unsupported):
                self.assertNotEqual(run(ExcessPermissionsRule(), data, policy).status, 'passed')
