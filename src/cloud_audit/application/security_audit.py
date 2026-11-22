from datetime import datetime, timezone
from typing import Protocol
from uuid import uuid4

from cloud_audit.application.rules import RuleEngine
from cloud_audit.domain.rules import AuditPolicy, SecurityReport
from cloud_audit.domain.snapshot import ConfigurationSnapshot


class SecurityReportRepository(Protocol):
    def save(self, report: SecurityReport) -> None: ...


class SecurityAuditService:
    def __init__(self, engine: RuleEngine, reports: SecurityReportRepository):
        self._engine = engine
        self._reports = reports

    def audit(self, snapshot: ConfigurationSnapshot, policy: AuditPolicy,
              selected: tuple[str, ...] = ()) -> SecurityReport:
        results = self._engine.evaluate(snapshot, policy, selected)
        limitations = tuple(x for x in snapshot.limitations if x != 'security_not_assessed')
        report = SecurityReport(uuid4().hex, 1, snapshot.provider, snapshot.resource,
            snapshot.id, snapshot.collected_at, datetime.now(timezone.utc).isoformat(),
            snapshot.scope, (*limitations, 'only_selected_rules_evaluated'), snapshot.collection_status,
            'incomplete' if any(x.status == 'insufficient_data' for x in results) else 'complete', policy, results)
        self._reports.save(report)
        return report
