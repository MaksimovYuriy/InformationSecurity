from typing import Protocol

from cloud_audit.application.comparison import ReportComparisonService
from cloud_audit.domain.history import HistoryQuery, HistoryPage
from cloud_audit.domain.rules import SecurityReport
from cloud_audit.domain.audit import AuditReport


class AuditHistoryRepository(Protocol):
    def get(self, report_id: str) -> AuditReport | SecurityReport: ...
    def history(self, query: HistoryQuery) -> HistoryPage: ...


class AuditHistoryService:
    def __init__(self, repository: AuditHistoryRepository):
        self._repository = repository

    def history(self, query: HistoryQuery) -> HistoryPage:
        return self._repository.history(query)

    def compare(self, before_id: str, after_id: str):
        return ReportComparisonService().compare(self._repository.get(before_id), self._repository.get(after_id))
