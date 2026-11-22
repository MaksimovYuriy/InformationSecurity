from typing import Protocol
from uuid import uuid4

from cloud_audit.domain.audit import AuditReport, Resource, RuleResult
from cloud_audit.domain.rules import SecurityReport


class AuditError(ValueError):
    pass


class StorageProvider(Protocol):
    mode: str
    audit_available: bool
    connection_message: str
    def connect(self) -> None: ...
    def resources(self) -> tuple[Resource, ...]: ...
    def preview(self, resource: Resource, rules: tuple[str, ...]) -> tuple[RuleResult, ...]: ...


class ReportRepository(Protocol):
    def save(self, report: AuditReport | SecurityReport) -> None: ...
    def get(self, report_id: str) -> AuditReport | SecurityReport: ...


class AuditService:
    def __init__(self, provider: StorageProvider, reports: ReportRepository):
        self._provider = provider
        self._reports = reports

    def connection(self) -> dict[str, str]:
        self._provider.connect()
        return {'mode': self._provider.mode, 'status': 'ok',
                'message': self._provider.connection_message}

    def resources(self) -> tuple[Resource, ...]:
        return self._provider.resources()

    def audit(self, resource_id: str, rules: tuple[str, ...]) -> AuditReport:
        if not self._provider.audit_available:
            raise AuditError('Cloud security audit is not implemented yet')
        resource = next((item for item in self.resources() if item.id == resource_id), None)
        if resource is None:
            raise AuditError('Resource not found in selected profile')
        results = self._provider.preview(resource, rules)
        report = AuditReport(uuid4().hex, self._provider.mode, resource, results)
        self._reports.save(report)
        return report

    def report(self, report_id: str) -> AuditReport | SecurityReport:
        return self._reports.get(report_id)
