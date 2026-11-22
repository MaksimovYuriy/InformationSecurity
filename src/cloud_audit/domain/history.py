from dataclasses import dataclass

from cloud_audit.domain.audit import Resource
from cloud_audit.domain.rules import Finding, AuditPolicy


@dataclass(frozen=True)
class HistoryQuery:
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
    entries: tuple[HistoryEntry, ...]
    total: int
    limit: int
    offset: int


@dataclass(frozen=True)
class FindingChange:
    rule_id: str
    change: str
    reason: str
    before: Finding | None
    after: Finding | None


@dataclass(frozen=True)
class ComparisonContext:
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
