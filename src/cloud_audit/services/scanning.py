"""Последовательная обработка нескольких бакетов с независимыми внешним и внутренним этапами."""
from dataclasses import replace
from datetime import datetime, timezone
from uuid import uuid4

from cloud_audit.errors import AuditError
from cloud_audit.interfaces import ExternalInspection, ScanRunRepository, ScanProvider
from cloud_audit.services.snapshots import SnapshotService
from cloud_audit.services.audit import SecurityAuditService
from cloud_audit.models.scanning import ScanTarget, ScanRun, BucketScanResult, ExternalResult, ObjectDiscovery
from cloud_audit.models.snapshot import CollectionOptions, ConfigurationObservation
from cloud_audit.rules.external import external_findings


class ScanService:
    """Не создаёт SDK/файлы: получает инспектор, репозитории и необязательные авторизованные сервисы извне."""
    def __init__(self, external: ExternalInspection, repository: ScanRunRepository, provider: ScanProvider | None = None,
                 snapshots: SnapshotService | None = None, audits: SecurityAuditService | None = None):
        """Сохраняет зависимости; отсутствие провайдера означает внешний режим без ключей."""
        self.external, self.repository = external, repository
        self.provider, self.snapshots, self.audits = provider, snapshots, audits

    def run(self, targets, *, all_buckets=False, max_objects=20, external_only=False, mutation_buckets=(), allow_residue=False, selection_source="explicit", default_policy=None):
        """Выбирает цели, сохраняет отдельные ошибки и общий результат; мутации не включаются автоматически при обнаружении бакета."""
        if type(max_objects) is not int or not 1 <= max_objects <= 20:
            raise AuditError('Object limit must be between 1 and 20')
        if all_buckets and (self.provider is None or external_only):
            raise AuditError('All-bucket selection requires authenticated listing')
        started = datetime.now(timezone.utc).isoformat()
        selection_status, errors = 'complete', ()
        if all_buckets:
            try:
                targets = tuple(ScanTarget(item.id) for item in self.provider.resources())
            except (AuditError, ValueError):
                targets, selection_status, errors = (), 'failed', ('bucket_listing_failed',)
        targets = tuple(targets)
        if default_policy is not None:
            targets = tuple(replace(t, policy=default_policy) for t in targets)
        if len(targets) > 500 or len({t.name for t in targets}) != len(targets):
            raise AuditError('Too many or duplicate scan targets')
        if set(mutation_buckets) - {t.name for t in targets} and selection_status == 'complete':
            raise AuditError('Mutation permission names a bucket outside the selected scope')
        targets = tuple(replace(t, allow_mutations=True, allow_residue=allow_residue or t.allow_residue)
                        if t.name in mutation_buckets else t for t in targets)
        if any(len(t.object_keys) > max_objects for t in targets):
            raise AuditError('Explicit object scope exceeds the chosen limit')
        if any(t.allow_mutations and not t.allow_residue for t in targets) and (self.provider is None or external_only):
            raise AuditError('Unsigned-only mutations require explicit acceptance of possible residue')
        results = tuple(self._bucket(target, max_objects, external_only) for target in targets)
        run = ScanRun(uuid4().hex, 1, self.external.namespace, started, datetime.now(timezone.utc).isoformat(),
                      'all' if all_buckets else selection_source, selection_status, max_objects,
                      self.provider is not None and not external_only, results, errors)
        self.repository.save(run)
        return run

    def _bucket(self, target, limit, external_only):
        """Ошибка или запрет внешнего этапа не подавляет внутренний; ошибка одного бакета не прерывает другие."""
        external, internal_discovery, report_id = None, None, None
        external_status, internal_status, errors, limitations = 'failed', 'skipped', [], []
        try:
            external = self.external.inspect(target, limit)
            external_status = 'incomplete' if any(p.outcome in {'error', 'unverified', 'not_found'} for p in external.probes) else 'complete'
        except AuditError:
            errors.append('external_probe_failed')
        if self.provider is not None and not external_only:
            try:
                if self.snapshots is None or self.audits is None:
                    raise AuditError('Internal scan services are not configured')
                internal_discovery = self.provider.discover_objects(target.name, limit)
                combined = tuple(dict.fromkeys((*target.object_keys, *(external.discovery.keys if external else ()), *internal_discovery.keys)))
                keys = combined[:limit]
                if len(combined) > limit:
                    internal_discovery = replace(internal_discovery, status='limited', error_code='combined_scope_limit')
                if internal_discovery.status != 'complete':
                    limitations.append('internal_object_listing_' + internal_discovery.status)
                known = {p.target for p in external.probes if p.operation == 'read'} if external else set()
                extra = self.external.read_objects(target.name, tuple(k for k in keys if k not in known))
                if external is not None:
                    external = replace(external, probes=external.probes + extra)
                elif extra:
                    external = ExternalResult(extra, ObjectDiscovery((), 'failed', 'anonymous', limit, 'external_probe_failed'))
                    external_status = 'incomplete'
                snapshot = self.snapshots.collect(target.name, CollectionOptions(keys))
                if external is not None:
                    facts = tuple(self._observation(p) for p in external.probes if p.outcome != 'not_tested' and (p.operation != 'read' or p.target in keys))
                    snapshot = self.snapshots.enrich(snapshot, facts)
                report = self.audits.audit(snapshot, target.policy)
                report_id, internal_status = report.id, report.evaluation_status
            except AuditError:
                internal_status = 'failed'
                errors.append('internal_audit_failed')
            except OSError:
                internal_status = 'failed'
                errors.append('internal_storage_failed')
        elif external is not None and external.discovery.status != 'complete':
            limitations.append('anonymous_object_listing_' + external.discovery.status)
        if external is not None:
            if external.discovery.status == 'limited' or any(p.outcome in {'error', 'unverified', 'not_found'} or p.outcome == 'not_tested' and p.reason != 'mutation_not_enabled' for p in external.probes):
                external_status = 'incomplete'
            if external.probes and not any(p.operation == 'read' for p in external.probes):
                external_status = 'incomplete'
        findings = external_findings(external.probes, target.policy) if external else ()
        return BucketScanResult(target.name, external_status, external, findings, internal_status, report_id,
                                internal_discovery, tuple(errors), tuple(limitations), target)

    @staticmethod
    def _observation(probe):
        """Переносит только доказанные исходы проб в evidence внутреннего отчёта; пропуски становятся error, не allowed."""
        operation = probe.operation
        source = {'list': 'list_objects_v2', 'read': 'get_object', 'write': 'put_object', 'delete': 'delete_object'}[operation]
        data = {'outcome': probe.outcome if probe.outcome in {'allowed', 'denied', 'not_found'} else 'error',
                'http_status': probe.http_status, 'checked_at': probe.checked_at,
                'verification': probe.verification, 'preparation': probe.preparation, 'cleanup': probe.cleanup}
        if probe.target is not None:
            data['object_key'] = probe.target
        if probe.cleanup in {'residue', 'unknown'}:
            data['cleanup_failed'] = True
        return ConfigurationObservation('anonymous_read:' + probe.target if operation == 'read' else 'anonymous_' + operation,
                                        'anonymous_' + source, 'available', data)
