"""Provider-independent configuration evidence, not security findings."""
from dataclasses import dataclass

from cloud_audit.domain.audit import Resource


CONFIGURATION_FIELDS = frozenset({
    'bucket_acl', 'bucket_policy', 'public_access_block', 'ownership_controls',
    'versioning', 'logging', 'encryption', 'object_lock',
})
OBSERVATION_STATUSES = frozenset({'available', 'absent', 'access_denied', 'unsupported', 'error'})
LIMITATIONS = ('object_acl_not_collected', 'object_contents_not_collected',
               'account_controls_not_collected', 'security_not_assessed',
               'sequential_requests_not_atomic')


@dataclass(frozen=True)
class ConfigurationObservation:
    name: str
    source: str
    status: str
    data: dict | None
    reason: str | None = None


@dataclass(frozen=True)
class ConfigurationSnapshot:
    id: str
    schema_version: int
    provider: str
    resource: Resource
    collected_at: str
    scope: str
    limitations: tuple[str, ...]
    collection_status: str
    observations: tuple[ConfigurationObservation, ...]
