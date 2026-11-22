"""Запросы и страницы истории, контексты сравнения и объяснимые переходы результатов правил."""
from dataclasses import dataclass

from cloud_audit.models.resources import Resource
from cloud_audit.models.security import Finding, AuditPolicy


@dataclass(frozen=True)
class HistoryQuery:
    """Неизменяемые фильтры истории; limit/offset проверяются реализацией репозитория."""
    resource_id: str | None = None
    rule_id: str | None = None
    severity: str | None = None
    finding_status: str | None = None
    mode: str | None = 'vk'
    run_status: str | None = None
    limit: int = 50
    offset: int = 0


@dataclass(frozen=True)
class HistoryEntry:
    """
    Краткая запись запуска с выбранными правилами, полными счётчиками статусов и безопасной
    категорией ошибки.
    """
    id: str
    mode: str
    resource: Resource
    observed_at: str | None
    recorded_at: str
    run_status: str
    selected_rules: tuple[str, ...]
    status_counts: dict[str, int]
    error_code: str | None = None
    resource_namespace: str | None = None


@dataclass(frozen=True)
class HistoryPage:
    """Страница записей и общее число совпадений до пагинации."""
    entries: tuple[HistoryEntry, ...]
    total: int
    limit: int
    offset: int


@dataclass(frozen=True)
class FindingChange:
    """Переход одного rule_id: before/after, классификация изменения и объяснение."""
    rule_id: str
    change: str
    reason: str
    before: Finding | None
    after: Finding | None


@dataclass(frozen=True)
class ComparisonContext:
    """Контекст одного сравниваемого отчёта: снимок, endpoint, версия правил, охват, политика и полнота."""
    snapshot_id: str
    resource_namespace: str | None
    ruleset_version: str | None
    scope: str
    object_keys: tuple[str, ...]
    policy: AuditPolicy
    collection_status: str
    evaluation_status: str


@dataclass(frozen=True)
class ReportComparison:
    """Полное сравнение двух отчётов: идентичность, время, сопоставимость, причины и переходы."""
    before_id: str
    after_id: str
    before_resource: Resource
    after_resource: Resource
    before_observed_at: str
    after_observed_at: str
    comparable: bool
    reasons: tuple[str, ...]
    changes: tuple[FindingChange, ...]
    before_context: ComparisonContext
    after_context: ComparisonContext
