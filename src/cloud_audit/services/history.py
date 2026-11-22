"""Предоставляет историю и сравнение сохранённых полных отчётов через внедряемый репозиторий."""
from cloud_audit.interfaces import AuditHistoryRepository

from cloud_audit.services.comparison import ReportComparisonService
from cloud_audit.models.history import HistoryQuery, HistoryPage


class AuditHistoryService:
    """Координирует чтение истории и сравнение полных сохранённых отчётов."""
    def __init__(self, repository: AuditHistoryRepository):
        """
        Сохраняет переданные зависимости и параметры экземпляра; конкретные внешние действия
        выполняются отдельными методами.
        """
        self._repository = repository

    def history(self, query: HistoryQuery) -> HistoryPage:
        """Передаёт HistoryQuery в репозиторий и возвращает HistoryPage."""
        return self._repository.history(query)

    def compare(self, before_id: str, after_id: str):
        """
        Читает два полных отчёта по ID и передаёт их чистому сервису сравнения; фильтрованные
        представления не использует.
        """
        return ReportComparisonService().compare(self._repository.get(before_id), self._repository.get(after_id))
