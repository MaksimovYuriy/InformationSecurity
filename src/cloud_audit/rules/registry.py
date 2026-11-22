"""Собирает восемь встроенных правил в стабильном порядке; реестр передаётся движку через конструктор."""
from cloud_audit.rules.versioning import VersioningRule
from cloud_audit.rules.public_access import PublicAccessRule
from cloud_audit.rules.governance import ExternalAccessRule, ExcessPermissionsRule, AclDisabledRule


def default_rules():
    """Возвращает восемь встроенных проверок в фиксированном порядке, без обращения к внешним системам."""
    return (VersioningRule(), *(PublicAccessRule(operation) for operation in ('read', 'list', 'write', 'delete')),
            ExternalAccessRule(), ExcessPermissionsRule(), AclDisabledRule())
