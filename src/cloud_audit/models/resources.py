"""Неизменяемые модели идентичности ресурса и совместимого демонстрационного отчёта."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Resource:
    """Идентификатор и отображаемое имя бакета; используется без объектов SDK."""
    id: str
    name: str


@dataclass(frozen=True)
class RuleResult:
    """Результат демонстрационного сценария: правило, simulated и пояснение."""
    rule_id: str
    status: str
    explanation: str


@dataclass(frozen=True)
class AuditReport:
    """Совместимый демонстрационный отчёт; не содержит настоящих обнаружений или оценки риска."""
    id: str
    mode: str
    resource: Resource
    results: tuple[RuleResult, ...]
