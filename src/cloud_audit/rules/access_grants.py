"""
Строит инвентарь явных разрешений и запретов для выбранных ресурсов; не подменяет полный IAM и
действующие сеансы доступа.
"""
from dataclasses import dataclass
import json
import re

from cloud_audit.rules.public_access import matches, strings, ALL_USERS
from cloud_audit.models.security import Evidence


# Only operations with an explicit interpretation in our baseline are expanded.
ACTION_OPERATIONS = {
    's3:GetObject': ('read', 'object'), 's3:ListBucket': ('list', 'bucket'),
    's3:PutObject': ('write', 'object'), 's3:DeleteObject': ('delete', 'object'),
    's3:GetBucketAcl': ('read_acl', 'bucket'), 's3:GetObjectAcl': ('read_acl', 'object'),
    's3:PutBucketAcl': ('write_acl', 'bucket'), 's3:PutObjectAcl': ('write_acl', 'object'),
    's3:GetBucketPolicy': ('read_policy', 'bucket'),
}


def project_id(subject: str) -> str | None:
    """Извлекает проект из поддерживаемого IAM ARN пользователя/root; при другой форме возвращает None."""
    match = re.fullmatch(r'arn:aws:iam::([^:]+):(user/.+|root)', subject)
    return match.group(1) if match else None


def subject_covers(grant: str, subject: str) -> bool:
    """Проверяет точный субъект, группу AuthenticatedUsers или покрытие пользователя проектным грантом."""
    authenticated_group = ALL_USERS.replace('AllUsers', 'AuthenticatedUsers')
    return (grant == '*' or grant == subject or grant == authenticated_group and subject != '*'
            or project_id(subject) is not None and grant == project_id(subject))


@dataclass(frozen=True)
class ExplicitGrant:
    """Явная операция субъекта над конкретным ARN с указанием источника."""
    subject: str
    operation: str
    resource: str
    source: str


@dataclass(frozen=True)
class GrantInventory:
    """Разрешения, запреты, доказательства, неизвестности и владелец в выбранном охвате."""
    grants: tuple[ExplicitGrant, ...]
    denies: tuple[ExplicitGrant, ...]
    evidence: tuple[Evidence, ...]
    unknown: tuple[str, ...]
    owner_id: str | None

    def denied(self, grant: ExplicitGrant, subject: str | None = None) -> bool:
        """Проверяет, перекрывает ли явный Deny операцию и ресурс гранта для указанного субъекта."""
        return any(row.operation == grant.operation and row.resource == grant.resource
                   and subject_covers(row.subject, subject or grant.subject) for row in self.denies)

    def for_subject(self, subject: str):
        """Возвращает явные разрешения, покрывающие субъекта, за вычетом подходящих явных запретов."""
        return tuple(row for row in self.grants if subject_covers(row.subject, subject)
                     and not self.denied(row, subject))


def inventory(snapshot) -> GrantInventory:
    """
    Нормализует явные ACL/политики в операции по выбранным целям; учитывает ownership, запреты и
    неполноту анализа.
    """
    fields = {item.name: item for item in snapshot.observations}
    grants, denies, evidence, unknown = [], [], [], []
    bucket_arn = f'arn:aws:s3:::{snapshot.resource.id}'
    targets = [('bucket', bucket_arn)] + [('object', bucket_arn + '/' + key) for key in snapshot.object_keys]
    bucket_acl = fields.get('bucket_acl')
    owner = bucket_acl.data.get('owner_id') if bucket_acl and bucket_acl.status == 'available' else None
    ownership = fields.get('ownership_controls')
    mode = ownership.data.get('object_ownership') if ownership and ownership.status == 'available' else None
    if mode not in {'BucketOwnerEnforced', 'BucketOwnerPreferred', 'ObjectWriter'}:
        unknown.append('acl_applicability_unknown')
    if ownership:
        evidence.append(Evidence('ownership_controls', ownership.source, ownership.status,
                                 json.dumps(ownership.data, sort_keys=True)))
    block = fields.get('public_access_block')
    ignore_public_acls = bool(block and block.status == 'available' and block.data.get('ignore_public_acls') is True)
    if block:
        evidence.append(Evidence('public_access_block', block.source, block.status,
                                 json.dumps(block.data, sort_keys=True)))
    if mode != 'BucketOwnerEnforced':
        for name, resource, is_bucket in [('bucket_acl', bucket_arn, True), *(
                (f'object_acl:{key}', bucket_arn + '/' + key, False) for key in snapshot.object_keys)]:
            item = fields.get(name)
            evidence.append(Evidence(name, item.source if item else 'not_collected',
                                     item.status if item else 'missing',
                                     json.dumps(item.data, sort_keys=True) if item and item.data else None))
            if item is None or item.status != 'available':
                unknown.append('acl_data_unavailable')
                continue
            try:
                for row in item.data['grants']:
                    if ignore_public_acls and row['principal_type'] == 'Group' and row['principal'] in {
                            ALL_USERS, ALL_USERS.replace('AllUsers', 'AuthenticatedUsers')}:
                        continue
                    subject = '*' if row['principal_type'] == 'Group' and row['principal'] == ALL_USERS else row['principal']
                    permission = row['permission']
                    operations = ({'READ': ('list',), 'WRITE': ('write', 'delete'),
                        'READ_ACP': ('read_acl',), 'WRITE_ACP': ('write_acl',),
                        'FULL_CONTROL': ('list', 'write', 'delete', 'read_acl', 'write_acl')} if is_bucket else
                        {'READ': ('read',), 'WRITE': (), 'READ_ACP': ('read_acl',),
                         'WRITE_ACP': ('write_acl',), 'FULL_CONTROL': ('read', 'read_acl', 'write_acl')})[permission]
                    for operation in operations:
                        resources = [bucket_arn + '/' + key for key in snapshot.object_keys] if is_bucket and operation in {'write', 'delete'} else [resource]
                        if not resources and subject != owner:
                            unknown.append('object_targets_not_selected')
                        grants.extend(ExplicitGrant(subject, operation, value, item.source) for value in resources)
            except (KeyError, TypeError):
                unknown.append('invalid_acl_data')
    item = fields.get('bucket_policy')
    evidence.append(Evidence('bucket_policy', item.source if item else 'not_collected',
        item.status if item else 'missing', json.dumps(item.data, sort_keys=True) if item and item.data else None))
    if item is None or item.status not in {'available', 'absent'}:
        unknown.append('policy_data_unavailable')
    elif item.status == 'available':
        try:
            statements = item.data['document']['Statement']
            statements = [statements] if isinstance(statements, dict) else statements
            if not isinstance(statements, list):
                raise ValueError
            for row in statements:
                try:
                    principals = row['Principal']
                    if isinstance(principals, dict):
                        if set(principals) != {'AWS'}:
                            raise ValueError
                        principals = principals['AWS']
                    principals = strings(principals)
                    if any((subject.startswith('arn:') and not re.fullmatch(r'arn:aws:iam::[^:]+:user/.+', subject))
                           or (subject != '*' and any(char in subject for char in '*?')) for subject in principals):
                        unknown.append('unsupported_principal_form')
                    actions, resources = strings(row['Action']), strings(row['Resource'])
                    if set(row) - {'Sid', 'Effect', 'Principal', 'Action', 'Resource'}:
                        unknown.append('policy_conditions_or_not_elements_unresolved')
                        continue
                    if row['Effect'] not in {'Allow', 'Deny'}:
                        raise ValueError
                    if any(action.lower() not in {x.lower() for x in ACTION_OPERATIONS} for action in actions):
                        unknown.append('unmapped_actions_or_wildcards')
                    if not snapshot.object_keys and any(resource != bucket_arn for resource in resources):
                        unknown.append('object_policy_targets_not_selected')
                    destination = grants if row['Effect'] == 'Allow' else denies
                    for action, (operation, scope) in ACTION_OPERATIONS.items():
                        if not any(matches(pattern.lower(), action.lower()) for pattern in actions):
                            continue
                        for target_scope, resource in targets:
                            if target_scope == scope and any(matches(pattern, resource) for pattern in resources):
                                destination.extend(ExplicitGrant(subject, operation, resource, item.source) for subject in principals)
                except (KeyError, TypeError, ValueError, AttributeError):
                    unknown.append('policy_conditions_or_not_elements_unresolved')
        except (KeyError, TypeError, ValueError):
            unknown.append('invalid_policy_data')
    return GrantInventory(tuple(dict.fromkeys(grants)), tuple(dict.fromkeys(denies)), tuple(evidence),
                          tuple(dict.fromkeys(unknown)), owner)
