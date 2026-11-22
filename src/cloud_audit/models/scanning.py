"""Цели и самодостаточный результат последовательной внешней/внутренней проверки бакетов."""
from dataclasses import dataclass, field
from datetime import datetime
import re

from cloud_audit.models.security import AuditPolicy, Finding
from cloud_audit.models.snapshot import CollectionOptions


@dataclass(frozen=True)
class ScanTarget:
    """Отдельный бакет, известные объекты, контекст и явное разрешение мутаций/остатков."""
    name: str
    object_keys: tuple[str, ...] = ()
    allow_mutations: bool = False
    allow_residue: bool = False
    policy: AuditPolicy = field(default_factory=AuditPolicy)

    def __post_init__(self):
        """Проверяет имя S3-бакета, ограниченный охват и явные булевы разрешения."""
        if (not isinstance(self.name, str) or not re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', self.name)
                or '..' in self.name or type(self.allow_mutations) is not bool or type(self.allow_residue) is not bool
                or self.allow_residue and not self.allow_mutations):
            raise ValueError('Invalid scan target')
        CollectionOptions(self.object_keys)


@dataclass(frozen=True)
class ProbeResult:
    """Факт одного unsigned-запроса; подготовка/уборка и проверка эффекта указаны отдельно."""
    operation: str
    target: str | None
    outcome: str
    http_status: int | None
    checked_at: str
    verification: str | None = None
    preparation: str = 'none'
    cleanup: str = 'not_needed'
    reason: str | None = None

    def __post_init__(self):
        """Отклоняет нераспознанные статусы, неверный HTTP и время без timezone."""
        if (self.operation not in {'read', 'list', 'write', 'delete'} or self.outcome not in
                {'allowed', 'denied', 'not_found', 'error', 'not_tested', 'unverified'}
                or self.cleanup not in {'not_needed', 'cleaned', 'residue', 'unknown'}
                or self.preparation not in {'none', 'authenticated', 'anonymous'}
                or self.http_status is not None and (type(self.http_status) is not int or not 100 <= self.http_status < 600)
                or datetime.fromisoformat(self.checked_at).tzinfo is None
                or self.outcome == 'allowed' and (self.http_status is None or not 200 <= self.http_status < 300)
                or self.outcome == 'denied' and self.http_status != 403):
            raise ValueError('Invalid probe evidence')


@dataclass(frozen=True)
class ObjectDiscovery:
    """Ограниченное перечисление объектов; limited/failed не означает полного охвата."""
    keys: tuple[str, ...]
    status: str
    source: str
    limit: int
    error_code: str | None = None

    def __post_init__(self):
        """Проверяет предел перечисления и допустимые источник/статус."""
        CollectionOptions(self.keys)
        if (type(self.limit) is not int or not 1 <= self.limit <= 20 or len(self.keys) > self.limit
                or self.status not in {'complete', 'limited', 'failed'}
                or self.source not in {'anonymous', 'authenticated'}):
            raise ValueError('Invalid discovery scope')


@dataclass(frozen=True)
class ExternalResult:
    """Набор независимых проб и охват анонимного списка, без облачных секретов."""
    probes: tuple[ProbeResult, ...]
    discovery: ObjectDiscovery


@dataclass(frozen=True)
class BucketScanResult:
    """Результаты двух этапов одного бакета, находки внешнего этапа и ссылка на внутренний отчёт."""
    bucket: str
    external_status: str
    external: ExternalResult | None
    external_findings: tuple[Finding, ...]
    internal_status: str
    internal_report_id: str | None
    internal_discovery: ObjectDiscovery | None
    errors: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    target: ScanTarget | None = None

    def __post_init__(self):
        """Проверяет согласованность статусов этапов и ссылки на внутренний отчёт."""
        if (self.external_status not in {'complete', 'incomplete', 'failed'} or self.internal_status not in {'complete', 'incomplete', 'failed', 'skipped'}
                or self.internal_report_id is not None and not re.fullmatch(r'[0-9a-f]{32}', self.internal_report_id)):
            raise ValueError('Invalid bucket scan status')


@dataclass(frozen=True)
class ScanRun:
    """Общая сводка запуска с сохранёнными фактами каждого бакета и полнотой выбора целей."""
    id: str
    schema_version: int
    namespace: str
    started_at: str
    completed_at: str
    selection_source: str
    selection_status: str
    max_objects: int
    authenticated: bool
    buckets: tuple[BucketScanResult, ...]
    errors: tuple[str, ...] = ()

    def __post_init__(self):
        """Проверяет версию, ID, время, пределы, происхождение целей и уникальность бакетов."""
        if (not re.fullmatch(r'[0-9a-f]{32}', self.id) or self.schema_version != 1
                or not self.namespace.startswith('https://') or self.selection_source not in {'all', 'explicit', 'file'}
                or self.selection_status not in {'complete', 'failed'} or type(self.max_objects) is not int or not 1 <= self.max_objects <= 20
                or type(self.authenticated) is not bool or len(self.buckets) > 500
                or len({row.bucket for row in self.buckets}) != len(self.buckets)):
            raise ValueError('Invalid scan run')
        start, end = datetime.fromisoformat(self.started_at), datetime.fromisoformat(self.completed_at)
        if start.tzinfo is None or end.tzinfo is None or end < start:
            raise ValueError('Invalid scan time')

    @property
    def incomplete(self):
        """Определяет частичность выбранных операций и охвата; выключенные мутации не считаются выполненными."""
        if self.selection_status != 'complete':
            return True
        for row in self.buckets:
            if row.external_status != 'complete' or row.internal_status in {'failed', 'incomplete'}:
                return True
            if row.internal_discovery is not None and row.internal_discovery.status != 'complete':
                return True
            if row.external is None or any(p.cleanup in {'residue', 'unknown'} for p in row.external.probes):
                return True
        return False
