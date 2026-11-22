"""Validation of normalized evidence persisted in snapshot schema version 1."""
from dataclasses import replace
from datetime import datetime
import re

from cloud_audit.domain.snapshot import ConfigurationObservation


SOURCES = {
    'bucket_acl': 'get_bucket_acl', 'bucket_policy': 'get_bucket_policy',
    'public_access_block': 'get_public_access_block',
    'ownership_controls': 'get_bucket_ownership_controls',
    'versioning': 'get_bucket_versioning', 'logging': 'get_bucket_logging',
    'encryption': 'get_bucket_encryption', 'object_lock': 'get_object_lock_configuration',
}
REASONS = {
    'absent': {'not_configured'}, 'access_denied': {'permission_required'},
    'unsupported': {'api_not_supported'},
    'error': {'rate_limit', 'service_error', 'sdk_or_network_error', 'invalid_response'},
    'not_found': {'resource_not_found'},
}


def validate_observation(item: ConfigurationObservation) -> None:
    if item.name.startswith('object_acl:'):
        if item.source != 'get_object_acl':
            raise ValueError
        validate_observation(replace(item, name='bucket_acl', source='get_bucket_acl'))
        return
    if item.name.startswith('anonymous_'):
        expected = ('anonymous_get_object' if item.name.startswith('anonymous_read:') else
                    {'anonymous_list': 'anonymous_list_objects_v2', 'anonymous_write': 'anonymous_put_object',
                     'anonymous_delete': 'anonymous_delete_object'}.get(item.name))
        data = item.data
        if item.source != expected or item.status != 'available' or item.reason is not None or not isinstance(data, dict):
            raise ValueError
        if data.get('outcome') not in {'allowed', 'denied', 'not_found', 'error'}:
            raise ValueError
        code = data.get('http_status')
        if code is not None and (type(code) is not int or not 100 <= code < 600):
            raise ValueError
        if data['outcome'] == 'allowed' and (code is None or not 200 <= code < 300):
            raise ValueError
        if data['outcome'] == 'denied' and code != 403:
            raise ValueError
        if datetime.fromisoformat(data['checked_at']).tzinfo is None:
            raise ValueError
        if item.name.startswith('anonymous_read:') and data.get('object_key') != item.name[len('anonymous_read:'):]:
            raise ValueError
        if item.name in {'anonymous_write', 'anonymous_delete'} and not re.fullmatch(
                r'_cloud-audit-probe/[0-9a-f]{32}/(write|delete)\.txt', data.get('object_key', '')):
            raise ValueError
        if 'cleanup_failed' in data and type(data['cleanup_failed']) is not bool:
            raise ValueError
        return
    if item.source != SOURCES[item.name]:
        raise ValueError
    if item.status != 'available':
        if item.data is not None or item.reason not in REASONS[item.status]:
            raise ValueError
        return
    data = item.data
    if not isinstance(data, dict) or item.reason is not None:
        raise ValueError
    valid = False
    if item.name == 'bucket_acl':
        valid = isinstance(data.get('owner_id'), str) and isinstance(data.get('grants'), list)
        if valid:
            valid = all(isinstance(grant, dict)
                        and grant.get('principal_type') in {'Group', 'CanonicalUser', 'AmazonCustomerByEmail'}
                        and isinstance(grant.get('principal'), str)
                        and grant.get('permission') in {'READ', 'WRITE', 'READ_ACP', 'WRITE_ACP', 'FULL_CONTROL'}
                        for grant in data['grants'])
    elif item.name == 'bucket_policy':
        document = data.get('document')
        valid = isinstance(document, dict) and isinstance(document.get('Statement'), (dict, list))
        if valid and isinstance(document['Statement'], list):
            valid = all(isinstance(statement, dict) for statement in document['Statement'])
    elif item.name == 'public_access_block':
        keys = {'block_public_acls', 'ignore_public_acls', 'block_public_policy', 'restrict_public_buckets'}
        valid = set(data) == keys and all(type(value) is bool for value in data.values())
    elif item.name == 'ownership_controls':
        valid = data.get('object_ownership') in {'BucketOwnerEnforced', 'BucketOwnerPreferred', 'ObjectWriter'}
    elif item.name == 'versioning':
        valid = (data.get('status') in {'Enabled', 'Suspended', 'Disabled'}
                 and 'mfa_delete' in data and data['mfa_delete'] in {None, 'Enabled', 'Disabled'})
    elif item.name == 'logging':
        valid = isinstance(data.get('target_bucket'), str) and isinstance(data.get('target_prefix'), str)
    elif item.name == 'encryption':
        rules = data.get('rules')
        valid = isinstance(rules, list) and bool(rules)
        if valid:
            valid = all(isinstance(rule, dict) and isinstance(rule.get('algorithm'), str)
                        and ('kms_key_id' not in rule or isinstance(rule['kms_key_id'], str))
                        and ('bucket_key_enabled' not in rule or type(rule['bucket_key_enabled']) is bool)
                        for rule in rules)
    elif item.name == 'object_lock':
        valid = data.get('enabled') is True
        if valid and 'default_retention' in data:
            retention = data['default_retention']
            valid = isinstance(retention, dict) and retention.get('mode') in {'GOVERNANCE', 'COMPLIANCE'}
            if valid:
                period = [key for key in ('days', 'years') if key in retention]
                valid = (len(period) == 1 and type(retention[period[0]]) is int
                         and retention[period[0]] > 0)
    if not valid:
        raise ValueError
