from datetime import datetime, timezone
from typing import Protocol
from uuid import uuid4

from cloud_audit.application.audit import AuditError
from cloud_audit.domain.audit import Resource
from cloud_audit.domain.snapshot import ConfigurationObservation, ConfigurationSnapshot, LIMITATIONS


class ConfigurationCollector(Protocol):
    mode: str
    def collect(self, resource: Resource) -> tuple[ConfigurationObservation, ...]: ...


class SnapshotRepository(Protocol):
    def save(self, snapshot: ConfigurationSnapshot) -> None: ...
    def get(self, snapshot_id: str) -> ConfigurationSnapshot: ...


class SnapshotService:
    def __init__(self, collector: ConfigurationCollector, repository: SnapshotRepository):
        self._collector = collector
        self._repository = repository

    def collect(self, resource_id: str) -> ConfigurationSnapshot:
        if not resource_id.strip():
            raise AuditError('Resource identifier is required')
        resource = Resource(resource_id, resource_id)
        # Timestamp marks the beginning of sequential requests, not an atomic cloud snapshot.
        started_at = datetime.now(timezone.utc).isoformat()
        observations = self._collector.collect(resource)
        status = ('complete_for_scope' if all(item.status in {'available', 'absent'}
                                             for item in observations) else 'partial')
        snapshot = ConfigurationSnapshot(uuid4().hex, 1, self._collector.mode, resource, started_at,
                                         'bucket_configuration_only', LIMITATIONS,
                                         status, observations)
        self._repository.save(snapshot)
        return snapshot
