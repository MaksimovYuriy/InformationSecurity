"""
Загружает строгую политику аудита из JSON: чувствительность, обязательные контроли, доверие,
необходимые права и исключения.
"""
import json
from datetime import datetime
from pathlib import Path

from cloud_audit.models.security import AuditPolicy, PermissionRequirement, RuleException
from cloud_audit.errors import ConfigurationError


def string_list(value):
    """Проверяет массив непустых строк и удаляет повторы с сохранением порядка; отклоняет null и словари."""
    if not isinstance(value, list) or any(not isinstance(x, str) or not x.strip() for x in value):
        raise ValueError
    return tuple(dict.fromkeys(value))


def parse_audit_policy(data: dict) -> AuditPolicy:
    """
    Проверяет типы, допустимые поля/операции, уникальные subject и исключения, timezone сроков;
    строит AuditPolicy.
    """
    try:
        if not isinstance(data, dict) or set(data) - {
                'data_sensitivity', 'required_controls', 'allowed_external_accounts',
                'required_permissions', 'exceptions', 'trusted_project_ids'}:
            raise ValueError
        sensitivity = data.get('data_sensitivity', 'unknown')
        if sensitivity not in {'low', 'medium', 'high', 'unknown'}:
            raise ValueError
        controls = string_list(data.get('required_controls', ['versioning']))
        if set(controls) - {'versioning', 'acl_disabled'}:
            raise ValueError
        accounts = string_list(data.get('allowed_external_accounts', []))
        trusted = string_list(data.get('trusted_project_ids', []))
        for key in ('required_permissions', 'exceptions'):
            if not isinstance(data.get(key, []), list):
                raise ValueError
        permissions = []
        subjects = set()
        for item in data.get('required_permissions', []):
            if set(item) != {'subject', 'operations'} or not isinstance(item['subject'], str) or not item['subject'].strip():
                raise ValueError
            operations = string_list(item['operations'])
            if item['subject'] in subjects:
                raise ValueError
            subjects.add(item['subject'])
            if set(operations) - {'read', 'list', 'write', 'delete', 'read_acl', 'read_policy', 'write_acl'}:
                raise ValueError
            permissions.append(PermissionRequirement(item['subject'], operations))
        exceptions = []
        seen = set()
        for item in data.get('exceptions', []):
            exception = RuleException(**item)
            if any(not isinstance(x, str) or not x.strip() for x in
                   (exception.resource_id, exception.rule_id, exception.reason)):
                raise ValueError
            if exception.expires_at is not None and datetime.fromisoformat(exception.expires_at).tzinfo is None:
                raise ValueError
            key = (exception.resource_id, exception.rule_id)
            if key in seen:
                raise ValueError
            seen.add(key)
            exceptions.append(exception)
        return AuditPolicy(sensitivity, controls, accounts, tuple(permissions), tuple(exceptions), trusted)
    except (ValueError, TypeError, KeyError, AttributeError):
        raise ConfigurationError('Invalid audit policy; check schema and field types') from None


def load_audit_policy(path: Path | None = None) -> AuditPolicy:
    """При отсутствии пути возвращает базовую политику; иначе читает UTF-8 JSON до 64 КиБ и проверяет его."""
    if path is None:
        return AuditPolicy()
    try:
        if path.stat().st_size > 64 * 1024:
            raise ValueError
        return parse_audit_policy(json.loads(path.read_text(encoding='utf-8')))
    except (ValueError, UnicodeError, RecursionError):
        raise ConfigurationError('Invalid audit policy file; expected JSON up to 64 KiB') from None
