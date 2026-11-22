from datetime import datetime, timezone
from typing import Protocol
from uuid import uuid4

from cloud_audit.application.audit import AuditError
from cloud_audit.domain.audit import Resource
from cloud_audit.domain.snapshot import (ConfigurationObservation, ConfigurationSnapshot, LIMITATIONS,
    CollectionOptions, collection_limitations, collection_complete)


class ConfigurationCollector(Protocol):
    mode: str
    def collect(self, resource: Resource, options: CollectionOptions | None = None) -> tuple[ConfigurationObservation, ...]: ...


class SnapshotRepository(Protocol):
    def save(self, snapshot: ConfigurationSnapshot) -> None: ...
    def get(self, snapshot_id: str) -> ConfigurationSnapshot: ...


class SnapshotService:
    def __init__(self, collector: ConfigurationCollector, repository: SnapshotRepository):
        self._collector = collector
        self._repository = repository

    def collect(self, resource_id: str, options: CollectionOptions | None = None) -> ConfigurationSnapshot:
        if not resource_id.strip():
            raise AuditError('Resource identifier is required')
        resource = Resource(resource_id, resource_id)
        # Timestamp marks the beginning of sequential requests, not an atomic cloud snapshot.
        started_at = datetime.now(timezone.utc).isoformat()
        observations = self._collector.collect(resource, options) if options else self._collector.collect(resource)
        status = 'complete_for_scope' if collection_complete(observations) else 'partial'
        keys = options.object_keys if options else ()
        snapshot = ConfigurationSnapshot(uuid4().hex, 2 if options else 1, self._collector.mode, resource, started_at,
                                         'bucket_and_selected_objects' if keys else 'bucket_configuration_only',
                                         collection_limitations(keys) if options else LIMITATIONS,
                                         status, observations, keys)
        self._repository.save(snapshot)
        return snapshot
