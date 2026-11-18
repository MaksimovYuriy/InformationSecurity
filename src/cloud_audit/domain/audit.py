from dataclasses import dataclass


@dataclass(frozen=True)
class Resource:
    id: str
    name: str


@dataclass(frozen=True)
class RuleResult:
    rule_id: str
    status: str
    explanation: str


@dataclass(frozen=True)
class AuditReport:
    id: str
    mode: str
    resource: Resource
    results: tuple[RuleResult, ...]
