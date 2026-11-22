"""Provider-independent configuration evidence, not security findings."""
from dataclasses import dataclass

from cloud_audit.domain.audit import Resource


CONFIGURATION_FIELDS = frozenset({
    'bucket_acl', 'bucket_policy', 'public_access_block', 'ownership_controls',
    'versioning', 'logging', 'encryption', 'object_lock',
})
OBSERVATION_STATUSES = frozenset({'available', 'absent', 'access_denied', 'unsupported', 'error', 'not_found'})
LIMITATIONS = ('object_acl_not_collected', 'object_contents_not_collected',
               'account_controls_not_collected', 'security_not_assessed',
               'sequential_requests_not_atomic')


@dataclass(frozen=True)
class CollectionOptions:
    object_keys: tuple[str, ...] = ()
    probe_anonymous: bool = False
    allow_write_probes: bool = False

    def __post_init__(self):
        if (len(self.object_keys) > 20 or len(set(self.object_keys)) != len(self.object_keys)
                or any(not isinstance(key, str) or not key or len(key.encode('utf-8')) > 1024
                       for key in self.object_keys)
                or self.allow_write_probes and not self.probe_anonymous):
            raise ValueError('Invalid object scope or probe options')


def collection_limitations(keys: tuple[str, ...]):
    return ('only_selected_objects_collected' if keys else 'object_acl_not_collected',
            'object_contents_not_stored', 'account_controls_not_collected',
            'security_not_assessed', 'sequential_requests_not_atomic')


def collection_complete(observations):
    return all(item.status in {'available', 'absent'}
               and (not item.name.startswith('anonymous_') or
                    item.data.get('outcome') in {'allowed', 'denied'} and not item.data.get('cleanup_failed'))
               for item in observations)


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
    object_keys: tuple[str, ...] = ()
    resource_namespace: str | None = None
