"""
Неизменяемые входы политики и выходы настоящего аудита; статусы, доказательства, риск и версия
набора правил.
"""
from dataclasses import dataclass

from cloud_audit.models.resources import Resource


FINDING_STATUSES = frozenset({'confirmed_violation', 'potential_risk', 'passed',
                              'insufficient_data', 'not_applicable'})
CURRENT_RULESET_VERSION = '1'


@dataclass(frozen=True)
class RuleException:
    """Принятое исключение для точной пары ресурс/правило с причиной и необязательным сроком."""
    resource_id: str
    rule_id: str
    reason: str
    expires_at: str | None = None


@dataclass(frozen=True)
class PermissionRequirement:
    """Заданные необходимые операции одного субъекта, с которыми сравниваются явные гранты."""
    subject: str
    operations: tuple[str, ...]


@dataclass(frozen=True)
class AuditPolicy:
    """
    Контекст оценки: чувствительность, обязательность контролей, доверенные субъекты, baseline и
    исключения.
    """
    data_sensitivity: str = 'unknown'
    required_controls: tuple[str, ...] = ('versioning',)
    allowed_external_accounts: tuple[str, ...] = ()
    required_permissions: tuple[PermissionRequirement, ...] = ()
    exceptions: tuple[RuleException, ...] = ()
    trusted_project_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class Evidence:
    """
    Нормализованный факт: поле, источник, статус наблюдения и строковое значение, без содержимого
    файлов.
    """
    field: str
    source: str
    observation_status: str
    value: str | None


@dataclass(frozen=True)
class RiskAssessment:
    """Объяснимая порядковая оценка: уровень, балл, вероятность/ущерб как категории и затронутые операции."""
    level: str
    score: int | None
    likelihood: int | None
    impact: int | None
    rationale: str
    affected_operations: tuple[str, ...] = ()
    model_version: int = 1


@dataclass(frozen=True)
class Finding:
    """Результат одного правила с доказательствами, риском, рекомендацией, подтверждением и ограничениями."""
    rule_id: str
    status: str
    explanation: str
    evidence: tuple[Evidence, ...]
    risk: RiskAssessment
    recommendation: str
    verification: str
    exception_reason: str | None = None
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class SecurityReport:
    """Самодостаточный настоящий отчёт со временем, снимком, охватом, политикой, результатами и provenance."""
    id: str
    schema_version: int
    mode: str
    resource: Resource
    snapshot_id: str
    snapshot_collected_at: str
    evaluated_at: str
    scope: str
    limitations: tuple[str, ...]
    collection_status: str
    evaluation_status: str
    policy: AuditPolicy
    results: tuple[Finding, ...]
    object_keys: tuple[str, ...] = ()
    ruleset_version: str | None = None
    resource_namespace: str | None = None


