"""
Работа с профилем: подключение, ресурсы, демонстрация и чтение отчёта. Реальные проверки выполняет
отдельный сервис аудита.
"""
from typing import cast
from uuid import uuid4

from cloud_audit.models.resources import AuditReport, Resource
from cloud_audit.models.security import SecurityReport
from cloud_audit.errors import AuditError
from cloud_audit.interfaces import StorageProvider, SimulationProvider, ReportRepository


class ProfileService:
    """Сценарии профиля и демонстрации; облачный ресурс не может получить имитированный отчёт."""
    def __init__(self, provider: StorageProvider, reports: ReportRepository):
        """
        Сохраняет переданные зависимости и параметры экземпляра; конкретные внешние действия
        выполняются отдельными методами.
        """
        self._provider = provider
        self._reports = reports

    def connection(self) -> dict[str, str]:
        """Вызывает connect провайдера и возвращает mode/status/безопасное сообщение."""
        self._provider.connect()
        return {'mode': self._provider.mode, 'status': 'ok',
                'message': self._provider.connection_message}

    def resources(self) -> tuple[Resource, ...]:
        """Передаёт запрос списка ресурсов внедрённому провайдеру."""
        return self._provider.resources()

    def simulate(self, resource_id: str, rules: tuple[str, ...]) -> AuditReport:
        """
        Разрешает только mode=demo, находит ресурс, запускает preview, сохраняет демонстрационный
        отчёт; vk отклоняет.
        """
        if self._provider.mode != 'demo':
            raise AuditError('Simulation requires the demo profile; cloud audits use the rule engine')
        resource = next((item for item in self.resources() if item.id == resource_id), None)
        if resource is None:
            raise AuditError('Resource not found in selected profile')
        results = cast(SimulationProvider, self._provider).preview(resource, rules)
        report = AuditReport(uuid4().hex, self._provider.mode, resource, results)
        self._reports.save(report)
        return report

    def report(self, report_id: str) -> AuditReport | SecurityReport:
        """Читает ранее сохранённый отчёт через репозиторий без подключения к облаку."""
        return self._reports.get(report_id)
