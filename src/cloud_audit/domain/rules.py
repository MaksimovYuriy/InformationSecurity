"""Security rule contracts and policy, independent of SDK and storage."""
from dataclasses import dataclass
from typing import Protocol

from cloud_audit.domain.audit import Resource
from cloud_audit.domain.snapshot import ConfigurationSnapshot


FINDING_STATUSES = frozenset({'confirmed_violation', 'potential_risk', 'passed',
                              'insufficient_data', 'not_applicable'})


@dataclass(frozen=True)
class RuleException:
    resource_id: str
    rule_id: str
    reason: str
    expires_at: str | None = None


@dataclass(frozen=True)
class PermissionRequirement:
    subject: str
    operations: tuple[str, ...]


@dataclass(frozen=True)
class AuditPolicy:
    data_sensitivity: str = 'unknown'
    required_controls: tuple[str, ...] = ('versioning',)
    allowed_external_accounts: tuple[str, ...] = ()
    required_permissions: tuple[PermissionRequirement, ...] = ()
    exceptions: tuple[RuleException, ...] = ()


@dataclass(frozen=True)
class Evidence:
    field: str
    source: str
    observation_status: str
    value: str | None


@dataclass(frozen=True)
class RiskAssessment:
    level: str
    score: int | None
    likelihood: int | None
    impact: int | None
    rationale: str
    affected_operations: tuple[str, ...] = ()
    model_version: int = 1


@dataclass(frozen=True)
class Finding:
    rule_id: str
    status: str
    explanation: str
    evidence: tuple[Evidence, ...]
    risk: RiskAssessment
    recommendation: str
    verification: str
    exception_reason: str | None = None


@dataclass(frozen=True)
class SecurityReport:
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


class SecurityRule(Protocol):
    id: str
    required_data: tuple[str, ...]
    recommendation: str
    verification: str
    def applicable(self, snapshot: ConfigurationSnapshot, policy: AuditPolicy) -> bool: ...
    def evaluate(self, snapshot: ConfigurationSnapshot, policy: AuditPolicy) -> Finding: ...


class RiskModel:
    """Ordinal, documented prioritization; not a measured incident probability."""
    def assess(self, status: str, sensitivity: str,
               operations: tuple[str, ...] = (), exposure: str = 'unknown') -> RiskAssessment:
        if status in {'passed', 'not_applicable'}:
            return RiskAssessment('none', 0, 0, 0, 'No finding for this rule', operations)
        if status == 'insufficient_data':
            return RiskAssessment('unknown', None, None, None, 'Insufficient evidence; risk not scored', operations)
        impact = {'low': 1, 'medium': 2, 'high': 3, 'unknown': 2}[sensitivity]
        likelihood = 3 if exposure == 'public_confirmed' else 2
        score = impact * likelihood
        level = 'critical' if score == 9 else 'high' if score >= 6 else 'medium' if score >= 3 else 'low'
        rationale = (f'Estimated ordinal risk: likelihood={likelihood}, impact={impact}; '
                     f'data_sensitivity={sensitivity}, exposure={exposure}. '
                     'Affected operations describe the threat, not measured granted permissions. '
                     'Other recovery mechanisms and actual permissions are not assessed.')
        return RiskAssessment(level, score, likelihood, impact, rationale, operations)
