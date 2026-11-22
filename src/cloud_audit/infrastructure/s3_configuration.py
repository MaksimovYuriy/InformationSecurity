"""S3 configuration collection and normalization. Only Get operations are used."""
import json

from botocore.exceptions import BotoCoreError, ClientError
from botocore.parsers import ResponseParserError

from cloud_audit.application.audit import AuditError
from cloud_audit.domain.audit import Resource
from cloud_audit.domain.snapshot import ConfigurationObservation, CollectionOptions


def require_mapping(value):
    if not isinstance(value, dict):
        raise ValueError
    return value


def acl(response):
    owner = require_mapping(response['Owner'])
    if not isinstance(owner.get('ID'), str):
        raise ValueError
    grants = response['Grants']
    if not isinstance(grants, list):
        raise ValueError
    normalized = []
    for grant in grants:
        principal = require_mapping(grant['Grantee'])
        kind = principal['Type']
        identifier_key = {'CanonicalUser': 'ID', 'Group': 'URI', 'AmazonCustomerByEmail': 'EmailAddress'}[kind]
        identifier = principal[identifier_key]
        permission = grant['Permission']
        if not isinstance(identifier, str) or permission not in {'READ', 'WRITE', 'READ_ACP', 'WRITE_ACP', 'FULL_CONTROL'}:
            raise ValueError
        normalized.append({'principal_type': kind, 'principal': identifier, 'permission': permission})
    return {'owner_id': owner['ID'], 'grants': normalized}


def policy(response):
    document = json.loads(response['Policy'])
    require_mapping(document)
    statements = document['Statement']
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not all(isinstance(item, dict) for item in statements):
        raise ValueError
    # Preserve conditions, NotAction, NotPrincipal and unknown constructs for later analysis.
    # Collection does not interpret policy semantics or infer safety.
    return {'document': document}


def public_access(response):
    block = require_mapping(response['PublicAccessBlockConfiguration'])
    names = {'BlockPublicAcls': 'block_public_acls', 'IgnorePublicAcls': 'ignore_public_acls',
             'BlockPublicPolicy': 'block_public_policy', 'RestrictPublicBuckets': 'restrict_public_buckets'}
    if any(type(block.get(key)) is not bool for key in names):
        raise ValueError
    return {target: block[source] for source, target in names.items()}


def ownership(response):
    rules = require_mapping(response['OwnershipControls'])['Rules']
    if not isinstance(rules, list) or len(rules) != 1:
        raise ValueError
    value = rules[0]['ObjectOwnership']
    if value not in {'BucketOwnerEnforced', 'BucketOwnerPreferred', 'ObjectWriter'}:
        raise ValueError
    return {'object_ownership': value}


def versioning(response):
    value = response.get('Status', 'Disabled')
    mfa = response.get('MFADelete')
    if value not in {'Enabled', 'Suspended', 'Disabled'} or mfa not in {None, 'Enabled', 'Disabled'}:
        raise ValueError
    return {'status': value, 'mfa_delete': mfa}


def logging_configuration(response):
    if 'LoggingEnabled' not in response:
        return None
    enabled = require_mapping(response['LoggingEnabled'])
    if not isinstance(enabled['TargetBucket'], str) or not isinstance(enabled['TargetPrefix'], str):
        raise ValueError
    return {'target_bucket': enabled['TargetBucket'], 'target_prefix': enabled['TargetPrefix']}


def encryption(response):
    rules = require_mapping(response['ServerSideEncryptionConfiguration'])['Rules']
    if not isinstance(rules, list) or not rules:
        raise ValueError
    normalized = []
    for rule in rules:
        default = require_mapping(rule['ApplyServerSideEncryptionByDefault'])
        algorithm = default['SSEAlgorithm']
        if not isinstance(algorithm, str):
            raise ValueError
        item = {'algorithm': algorithm}
        if 'KMSMasterKeyID' in default:
            if not isinstance(default['KMSMasterKeyID'], str):
                raise ValueError
            item['kms_key_id'] = default['KMSMasterKeyID']
        if 'BucketKeyEnabled' in rule:
            if type(rule['BucketKeyEnabled']) is not bool:
                raise ValueError
            item['bucket_key_enabled'] = rule['BucketKeyEnabled']
        normalized.append(item)
    return {'rules': normalized}


def object_lock(response):
    config = require_mapping(response['ObjectLockConfiguration'])
    if config.get('ObjectLockEnabled') != 'Enabled':
        raise ValueError
    result = {'enabled': True}
    if 'Rule' in config:
        retention = require_mapping(config['Rule'])['DefaultRetention']
        require_mapping(retention)
        mode = retention['Mode']
        if mode not in {'GOVERNANCE', 'COMPLIANCE'}:
            raise ValueError
        period = [key for key in ('Days', 'Years') if key in retention]
        if len(period) != 1 or type(retention[period[0]]) is not int or retention[period[0]] <= 0:
            raise ValueError
        result['default_retention'] = {'mode': mode, period[0].lower(): retention[period[0]]}
    return result


# name, SDK method, normalizer, setting-specific absence codes
COLLECTION_SPECS = (
    ('bucket_acl', 'get_bucket_acl', acl, frozenset()),
    ('bucket_policy', 'get_bucket_policy', policy, {'NoSuchBucketPolicy'}),
    ('public_access_block', 'get_public_access_block', public_access, {'NoSuchPublicAccessBlockConfiguration'}),
    ('ownership_controls', 'get_bucket_ownership_controls', ownership, {'OwnershipControlsNotFoundError'}),
    ('versioning', 'get_bucket_versioning', versioning, frozenset()),
    ('logging', 'get_bucket_logging', logging_configuration, frozenset()),
    ('encryption', 'get_bucket_encryption', encryption, {'ServerSideEncryptionConfigurationNotFoundError'}),
    ('object_lock', 'get_object_lock_configuration', object_lock, {'ObjectLockConfigurationNotFoundError'}),
)


class S3ConfigurationCollector:
    mode = 'vk'
    namespace = None
    def __init__(self, client):
        self._client = client

    def collect(self, resource: Resource, options: CollectionOptions | None = None) -> tuple[ConfigurationObservation, ...]:
        result = tuple(self._read(resource.id, *spec) for spec in COLLECTION_SPECS)
        if options:
            result += tuple(self._read(resource.id, f'object_acl:{key}', 'get_object_acl', acl,
                                       frozenset(), key=key) for key in options.object_keys)
        return result

    def _read(self, bucket, name, method, normalize, absence_codes, key=None):
        try:
            response = getattr(self._client, method)(**({'Bucket': bucket, 'Key': key}
                                                      if key is not None else {'Bucket': bucket}))
            require_mapping(response)
            data = normalize(response)
            # Reject non-JSON structures, including datetime and SDK objects.
            json.dumps(data, allow_nan=False)
            return ConfigurationObservation(name, method, 'available' if data is not None else 'absent',
                                            data, None if data is not None else 'not_configured')
        except ClientError as error:
            code = error.response.get('Error', {}).get('Code', '')
            if code == 'NoSuchBucket':
                raise AuditError('Cloud resource not found') from None
            if code in {'InvalidAccessKeyId', 'SignatureDoesNotMatch', 'ExpiredToken', 'InvalidToken'}:
                raise AuditError('Cloud credentials rejected') from None
            if key is not None and code in {'NoSuchKey', 'NotFound', '404'}:
                status, reason = 'not_found', 'resource_not_found'
            elif code in absence_codes:
                status, reason = 'absent', 'not_configured'
            elif code in {'AccessDenied', '403', 'AllAccessDisabled'}:
                status, reason = 'access_denied', 'permission_required'
            elif code in {'NotImplemented', '501', 'UnsupportedOperation'}:
                status, reason = 'unsupported', 'api_not_supported'
            elif code in {'SlowDown', 'Throttling', 'TooManyRequests', '429'}:
                status, reason = 'error', 'rate_limit'
            else:
                status, reason = 'error', 'service_error'
        except (BotoCoreError, ResponseParserError):
            status, reason = 'error', 'sdk_or_network_error'
        except (ValueError, TypeError, KeyError, IndexError):
            status, reason = 'error', 'invalid_response'
        return ConfigurationObservation(name, method, status, None, reason)
