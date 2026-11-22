"""Composition of the current built-in rules; execution remains generic."""
from cloud_audit.domain.versioning import VersioningRule
from cloud_audit.domain.public_access import PublicAccessRule


def default_rules():
    return (VersioningRule(), *(PublicAccessRule(operation) for operation in ('read', 'list', 'write', 'delete')))
