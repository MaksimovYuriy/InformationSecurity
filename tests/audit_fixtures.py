"""Synthetic snapshots, SDK responses and reports shared by behavior tests; no real credentials."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from uuid import uuid4
from unittest.mock import Mock
from botocore.exceptions import ClientError

from cloud_audit.models.resources import Resource
from cloud_audit.models.snapshot import ConfigurationObservation, ConfigurationSnapshot, LIMITATIONS
from cloud_audit.models.security import AuditPolicy
from cloud_audit.rules.engine import RuleEngine
from cloud_audit.rules.versioning import VersioningRule
from cloud_audit.services.audit import SecurityAuditService

ALL = 'http://acs.amazonaws.com/groups/global/AllUsers'


def snapshot(value='Disabled', status='available'):
    return ConfigurationSnapshot('a' * 32, 1, 'vk', Resource('lab', 'lab'),
        datetime.now(timezone.utc).isoformat(), 'bucket_configuration_only', LIMITATIONS,
        'partial', (ConfigurationObservation('versioning', 'get_bucket_versioning', status,
                     {'status': value, 'mfa_delete': None} if status == 'available' else None,
                     None if status == 'available' else 'api_not_supported'),))



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



def failure(code):
    return ClientError({'Error': {'Code': code, 'Message': 'never-print-secret'}}, 'GetConfig')



def configured_client():
    client = Mock()
    client.get_bucket_acl.return_value = {
        'Owner': {'ID': 'owner'},
        'Grants': [{'Grantee': {'Type': 'Group', 'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'},
                    'Permission': 'READ'}], 'ResponseMetadata': {'Secret': 'never-print-secret'}}
    client.get_bucket_policy.return_value = {'Policy': json.dumps({
        'Version': '2012-10-17', 'Statement': {'Effect': 'Deny', 'Principal': '*',
            'Action': 's3:DeleteObject', 'Resource': 'arn:aws:s3:::lab/*',
            'Condition': {'UnknownCondition': {'x': 'y'}}}})}
    client.get_public_access_block.return_value = {'PublicAccessBlockConfiguration': {
        'BlockPublicAcls': True, 'IgnorePublicAcls': False,
        'BlockPublicPolicy': True, 'RestrictPublicBuckets': False}}
    client.get_bucket_ownership_controls.return_value = {
        'OwnershipControls': {'Rules': [{'ObjectOwnership': 'BucketOwnerPreferred'}]}}
    client.get_bucket_versioning.return_value = {}
    client.get_bucket_logging.return_value = {}
    client.get_bucket_encryption.side_effect = failure('ServerSideEncryptionConfigurationNotFoundError')
    client.get_object_lock_configuration.side_effect = failure('ObjectLockConfigurationNotFoundError')
    return client



def version_report(value, minutes=0):
    data = snapshot(value)
    data = replace(data, resource_namespace='https://example.invalid', id=uuid4().hex, collected_at=(datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat())
    return SecurityAuditService(RuleEngine((VersioningRule(),)), Mock()).audit(data, AuditPolicy())



def named_statement(subject='arn:aws:iam::outside:user/app', action='s3:GetObject', **extra):
    return statement(Principal={'AWS': subject}, Action=action, **extra)

