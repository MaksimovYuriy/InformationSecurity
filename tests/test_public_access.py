from dataclasses import replace
import unittest

from cloud_audit.application.rules import RuleEngine
from cloud_audit.domain.public_access import PublicAccessRule
from cloud_audit.domain.rules import AuditPolicy
from cloud_audit.domain.snapshot import ConfigurationObservation
from test_rule_engine import snapshot


ALL = 'http://acs.amazonaws.com/groups/global/AllUsers'


def config(bucket_grants=(), object_grants=(), statements=None, ownership='BucketOwnerPreferred'):
    items = [ConfigurationObservation('bucket_acl', 'get_bucket_acl', 'available',
                {'owner_id': 'owner', 'grants': list(bucket_grants)}),
             ConfigurationObservation('bucket_policy', 'get_bucket_policy',
                'absent' if statements is None else 'available',
                None if statements is None else {'document': {'Statement': statements}},
                'not_configured' if statements is None else None),
             ConfigurationObservation('ownership_controls', 'get_bucket_ownership_controls', 'available',
                {'object_ownership': ownership}),
             ConfigurationObservation('public_access_block', 'get_public_access_block', 'unsupported', None, 'api_not_supported'),
             ConfigurationObservation('object_acl:sample.txt', 'get_object_acl', 'available',
                {'owner_id': 'owner', 'grants': list(object_grants)})]
    return replace(snapshot(), schema_version=2, scope='bucket_and_selected_objects',
                   observations=tuple(items), object_keys=('sample.txt',))


def grant(permission, principal=ALL):
    return {'principal_type': 'Group', 'principal': principal, 'permission': permission}


def statement(effect='Allow', action='s3:GetObject', **extra):
    return {'Effect': effect, 'Principal': '*', 'Action': action,
            'Resource': ['arn:aws:s3:::lab', 'arn:aws:s3:::lab/*'], **extra}


def evaluate(data, operation):
    return RuleEngine((PublicAccessRule(operation),)).evaluate(data, AuditPolicy())[0]


class PublicAccessTests(unittest.TestCase):
    def test_bucket_read_is_listing_and_object_read_is_content_only(self):
        data = config(bucket_grants=(grant('READ'),))
        self.assertEqual(evaluate(data, 'list').status, 'potential_risk')
        self.assertEqual(evaluate(data, 'read').status, 'passed')
        data = config(object_grants=(grant('READ'),))
        self.assertEqual(evaluate(data, 'read').status, 'potential_risk')
        self.assertEqual(evaluate(data, 'list').status, 'passed')

    def test_bucket_write_in_vk_implies_upload_and_delete_but_object_full_control_does_not(self):
        data = config(bucket_grants=(grant('WRITE'),))
        self.assertEqual(evaluate(data, 'write').status, 'potential_risk')
        self.assertEqual(evaluate(data, 'delete').status, 'potential_risk')
        data = config(object_grants=(grant('FULL_CONTROL'),))
        self.assertEqual(evaluate(data, 'delete').status, 'passed')

    def test_unconditional_deny_wins_over_acl_and_policy_allow(self):
        data = config(object_grants=(grant('READ'),), statements=[statement(), statement('Deny')])
        self.assertEqual(evaluate(data, 'read').status, 'passed')
        data = config(statements=[statement(), statement('Deny', Resource='arn:aws:s3:::lab/other')])
        self.assertEqual(evaluate(data, 'read').status, 'potential_risk')

    def test_unknown_conditions_and_not_elements_never_claim_safety(self):
        for extra in ({'Condition': {'IpAddress': {'aws:SourceIp': '10.0.0.0/8'}}},
                      {'NotAction': 's3:PutObject'}, {'NotPrincipal': {'AWS': 'account'}},
                      {'NotResource': 'arn:aws:s3:::lab/excluded'}):
            row = statement('Deny', **extra)
            for field in ('Action', 'Principal', 'Resource'):
                if 'Not' + field in extra:
                    row.pop(field)
            data = config(object_grants=(grant('READ'),), statements=[row])
            self.assertNotEqual(evaluate(data, 'read').status, 'passed')
            self.assertNotEqual(evaluate(data, 'read').status, 'confirmed_violation')

    def test_ownership_enforced_disables_acl_and_authenticated_users_are_not_anonymous(self):
        self.assertEqual(evaluate(config(object_grants=(grant('READ'),), ownership='BucketOwnerEnforced'), 'read').status, 'passed')
        self.assertEqual(evaluate(config(bucket_grants=(grant('READ', ALL.replace('AllUsers', 'AuthenticatedUsers')),)), 'list').status, 'passed')

    def test_positive_anonymous_probe_is_fact_even_with_incomplete_configuration(self):
        data = config(statements=[statement('Deny')])
        proof = ConfigurationObservation('anonymous_read:sample.txt', 'anonymous_get_object', 'available',
            {'outcome': 'allowed', 'http_status': 206, 'checked_at': data.collected_at, 'object_key': 'sample.txt'})
        data = replace(data, observations=(*data.observations, proof))
        result = evaluate(data, 'read')
        self.assertEqual(result.status, 'confirmed_violation')
        self.assertEqual(result.risk.likelihood, 3)
        self.assertTrue(any(x.source == 'anonymous_get_object' for x in result.evidence))

    def test_no_selected_object_and_unknown_policy_do_not_imply_private_files(self):
        data = replace(config(), object_keys=(), observations=tuple(
            x for x in config().observations if not x.name.startswith('object_acl:')))
        self.assertEqual(evaluate(data, 'read').status, 'insufficient_data')
        data = config()
        items = tuple(replace(x, status='access_denied', data=None, reason='permission_required')
                      if x.name == 'bucket_policy' else x for x in data.observations)
        self.assertEqual(evaluate(replace(data, observations=items), 'read').status, 'insufficient_data')

    def test_resource_wildcards_are_iam_not_shell_character_classes(self):
        data = config(statements=[statement(Resource='arn:aws:s3:::lab/[s]ample.txt')])
        self.assertEqual(evaluate(data, 'read').status, 'passed')
        data = config(statements=[statement(Action='S3:Get*', Resource='arn:aws:s3:::lab/sam?le.*')])
        self.assertEqual(evaluate(data, 'read').status, 'potential_risk')


class RuntimeEvidenceTests(unittest.TestCase):
    def test_failed_probe_does_not_become_confirmation_and_denial_does_not_resolve_unknown_policy(self):
        data = config(statements=[statement(Condition={'Unknown': {'x': 'y'}})])
        for outcome, code in [('denied', 403), ('not_found', 404), ('error', None)]:
            proof = ConfigurationObservation('anonymous_read:sample.txt', 'anonymous_get_object', 'available',
                {'outcome': outcome, 'http_status': code, 'checked_at': data.collected_at, 'object_key': 'sample.txt'})
            result = evaluate(replace(data, observations=(*data.observations, proof)), 'read')
            self.assertEqual(result.status, 'insufficient_data')

    def test_public_block_ignoring_acl_does_not_ignore_policy_grants(self):
        data = config(object_grants=(grant('READ'),))
        block = ConfigurationObservation('public_access_block', 'get_public_access_block', 'available', {
            'block_public_acls': True, 'ignore_public_acls': True, 'block_public_policy': True,
            'restrict_public_buckets': False})
        fields = tuple(block if x.name == 'public_access_block' else x for x in data.observations)
        self.assertEqual(evaluate(replace(data, observations=fields), 'read').status, 'passed')
        data = config(statements=[statement()])
        fields = tuple(block if x.name == 'public_access_block' else x for x in data.observations)
        self.assertEqual(evaluate(replace(data, observations=fields), 'read').status, 'potential_risk')
