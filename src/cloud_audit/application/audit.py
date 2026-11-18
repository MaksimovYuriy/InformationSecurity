from typing import Protocol
from uuid import uuid4

from cloud_audit.domain.audit import AuditReport, Resource, RuleResult


class AuditError(ValueError):
    pass


class StorageProvider(Protocol):
    def connect(self) -> None: ...
    def resources(self) -> tuple[Resource, ...]: ...
    def preview(self, resource: Resource, rules: tuple[str, ...]) -> tuple[RuleResult, ...]: ...


class ReportRepository(Protocol):
    def save(self, report: AuditReport) -> None: ...
    def get(self, report_id: str) -> AuditReport: ...


class AuditService:
    def __init__(self, provider: StorageProvider, reports: ReportRepository):
        self._provider = provider
        self._reports = reports

    def connection(self) -> dict[str, str]:
        self._provider.connect()
        return {'mode': 'demo', 'status': 'ok', 'message': 'Simulated connection; no cloud contacted'}

    def resources(self) -> tuple[Resource, ...]:
        return self._provider.resources()

    def audit(self, resource_id: str, rules: tuple[str, ...]) -> AuditReport:
        resource = next((item for item in self.resources() if item.id == resource_id), None)
        if resource is None:
            raise AuditError('Resource not found in demo profile')
        results = self._provider.preview(resource, rules)
        report = AuditReport(uuid4().hex, 'demo', resource, results)
        self._reports.save(report)
        return report

    def report(self, report_id: str) -> AuditReport:
        return self._reports.get(report_id)
