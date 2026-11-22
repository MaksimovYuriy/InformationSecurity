"""
Оркестрирует сбор и сохранение снимка; фиксирует начало последовательного, не атомарного наблюдения
и namespace провайдера.
"""
from datetime import datetime, timezone
from uuid import uuid4

from cloud_audit.interfaces import ConfigurationCollector, SnapshotRepository
from cloud_audit.errors import AuditError
from cloud_audit.models.resources import Resource
from cloud_audit.models.snapshot import (ConfigurationObservation, ConfigurationSnapshot, LIMITATIONS,
    CollectionOptions, collection_limitations, collection_complete)


class SnapshotService:
    """Собирает снимок через коллектор и сохраняет его через независимый репозиторий."""
    def __init__(self, collector: ConfigurationCollector, repository: SnapshotRepository):
        """
        Сохраняет переданные зависимости и параметры экземпляра; конкретные внешние действия
        выполняются отдельными методами.
        """
        self._collector = collector
        self._repository = repository

    def collect(self, resource_id: str, options: CollectionOptions | None = None) -> ConfigurationSnapshot:
        """
        Фиксирует начало сбора, создаёт Resource, вызывает коллектор, вычисляет полноту/охват и
        сохраняет снимок v1/v2.
        """
        if not resource_id.strip():
            raise AuditError('Resource identifier is required')
        resource = Resource(resource_id, resource_id)
        # Timestamp marks the beginning of sequential requests, not an atomic cloud snapshot.
        started_at = datetime.now(timezone.utc).isoformat()
        observations = self._collector.collect(resource, options) if options else self._collector.collect(resource)
        status = 'complete_for_scope' if collection_complete(observations) else 'partial'
        keys = options.object_keys if options else ()
        namespace = getattr(self._collector, 'namespace', None)
        namespace = namespace if isinstance(namespace, str) else None
        snapshot = ConfigurationSnapshot(uuid4().hex, 2 if options else 1, self._collector.mode, resource, started_at,
                                         'bucket_and_selected_objects' if keys else 'bucket_configuration_only',
                                         collection_limitations(keys) if options else LIMITATIONS,
                                         status, observations, keys, namespace)
        self._repository.save(snapshot)
        return snapshot

    def enrich(self, snapshot, observations):
        """Сохраняет новый снимок с фактами внешнего этапа и пересчитанной полнотой, не меняя старый ID."""
        from dataclasses import replace
        facts = {row.name: row for row in snapshot.observations}
        facts.update({row.name: row for row in observations})
        values = tuple(facts.values())
        times = [datetime.fromisoformat(snapshot.collected_at)]
        times.extend(datetime.fromisoformat(row.data['checked_at']) for row in observations if row.name.startswith('anonymous_'))
        result = replace(snapshot, id=uuid4().hex, schema_version=2, limitations=collection_limitations(snapshot.object_keys),
                         observations=values, collected_at=min(times).isoformat(),
                         collection_status='complete_for_scope' if collection_complete(values) else 'partial')
        self._repository.save(result)
        return result
