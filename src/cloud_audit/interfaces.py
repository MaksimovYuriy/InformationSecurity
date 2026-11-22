"""
Контракты внедряемых провайдеров, репозиториев и правил. Описывают необходимые операции без
зависимости от boto3, SQLite и CLI.
"""
from typing import Protocol

from cloud_audit.models.resources import AuditReport, Resource, RuleResult
from cloud_audit.models.security import AuditPolicy, Finding, SecurityReport
from cloud_audit.models.snapshot import CollectionOptions, ConfigurationObservation, ConfigurationSnapshot
from cloud_audit.models.history import HistoryQuery, HistoryPage


class StorageProvider(Protocol):
    """Интерфейс подключения и перечисления ресурсов; не содержит имитации или облачной логики правил."""
    mode: str
    connection_message: str
    def connect(self) -> None:
        """
        Контракт операции connect; реализация передаётся извне. Типы аргументов и результата
        определяют ожидаемые данные, тело Protocol не выполняет интеграцию.
        """
        ...
    def resources(self) -> tuple[Resource, ...]:
        """
        Контракт операции resources; реализация передаётся извне. Типы аргументов и результата
        определяют ожидаемые данные, тело Protocol не выполняет интеграцию.
        """
        ...


class SimulationProvider(StorageProvider, Protocol):
    """Дополнительный контракт preview только для демонстрационного профиля."""
    def preview(self, resource: Resource, rules: tuple[str, ...]) -> tuple[RuleResult, ...]:
        """
        Контракт операции preview; реализация передаётся извне. Типы аргументов и результата
        определяют ожидаемые данные, тело Protocol не выполняет интеграцию.
        """
        ...
    def preview(self, resource: Resource, rules: tuple[str, ...]) -> tuple[RuleResult, ...]:
        """
        Контракт операции preview; реализация передаётся извне. Типы аргументов и результата
        определяют ожидаемые данные, тело Protocol не выполняет интеграцию.
        """
        ...


class ReportRepository(Protocol):
    """Контракт сохранения и чтения demo или настоящего отчёта."""
    def save(self, report: AuditReport | SecurityReport) -> None:
        """
        Контракт операции save; реализация передаётся извне. Типы аргументов и результата определяют
        ожидаемые данные, тело Protocol не выполняет интеграцию.
        """
        ...
    def save(self, report: AuditReport | SecurityReport) -> None:
        """
        Контракт операции save; реализация передаётся извне. Типы аргументов и результата определяют
        ожидаемые данные, тело Protocol не выполняет интеграцию.
        """
        ...
    def get(self, report_id: str) -> AuditReport | SecurityReport:
        """
        Контракт операции get; реализация передаётся извне. Типы аргументов и результата определяют
        ожидаемые данные, тело Protocol не выполняет интеграцию.
        """
        ...


class SecurityReportRepository(Protocol):
    """Минимальный контракт записи настоящего отчёта для сервиса аудита."""
    def save(self, report: SecurityReport) -> None:
        """
        Контракт операции save; реализация передаётся извне. Типы аргументов и результата определяют
        ожидаемые данные, тело Protocol не выполняет интеграцию.
        """
        ...
    def save(self, report: SecurityReport) -> None:
        """
        Контракт операции save; реализация передаётся извне. Типы аргументов и результата определяют
        ожидаемые данные, тело Protocol не выполняет интеграцию.
        """
        ...


class AuditHistoryRepository(Protocol):
    """Контракт чтения полных отчётов и страниц истории."""
    def get(self, report_id: str) -> AuditReport | SecurityReport:
        """
        Контракт операции get; реализация передаётся извне. Типы аргументов и результата определяют
        ожидаемые данные, тело Protocol не выполняет интеграцию.
        """
        ...
    def get(self, report_id: str) -> AuditReport | SecurityReport:
        """
        Контракт операции get; реализация передаётся извне. Типы аргументов и результата определяют
        ожидаемые данные, тело Protocol не выполняет интеграцию.
        """
        ...
    def history(self, query: HistoryQuery) -> HistoryPage:
        """
        Контракт операции history; реализация передаётся извне. Типы аргументов и результата
        определяют ожидаемые данные, тело Protocol не выполняет интеграцию.
        """
        ...


class StateStorage(Protocol):
    """Контракт подготовки локального состояния, допускающий другую реализацию."""
    def prepare(self) -> None:
        """
        Контракт операции prepare; реализация передаётся извне. Типы аргументов и результата
        определяют ожидаемые данные, тело Protocol не выполняет интеграцию.
        """
        ...
    def prepare(self) -> None:
        """
        Контракт операции prepare; реализация передаётся извне. Типы аргументов и результата
        определяют ожидаемые данные, тело Protocol не выполняет интеграцию.
        """
        ...


class ConfigurationCollector(Protocol):
    """Контракт получения нормализованных наблюдений выбранного ресурса."""
    mode: str
    def collect(self, resource: Resource, options: CollectionOptions | None = None) -> tuple[ConfigurationObservation, ...]:
        """
        Контракт операции collect; реализация передаётся извне. Типы аргументов и результата
        определяют ожидаемые данные, тело Protocol не выполняет интеграцию.
        """
        ...


class SnapshotRepository(Protocol):
    """Контракт сохранения и чтения снимка по идентификатору."""
    def save(self, snapshot: ConfigurationSnapshot) -> None:
        """
        Контракт операции save; реализация передаётся извне. Типы аргументов и результата определяют
        ожидаемые данные, тело Protocol не выполняет интеграцию.
        """
        ...
    def save(self, snapshot: ConfigurationSnapshot) -> None:
        """
        Контракт операции save; реализация передаётся извне. Типы аргументов и результата определяют
        ожидаемые данные, тело Protocol не выполняет интеграцию.
        """
        ...
    def get(self, snapshot_id: str) -> ConfigurationSnapshot:
        """
        Контракт операции get; реализация передаётся извне. Типы аргументов и результата определяют
        ожидаемые данные, тело Protocol не выполняет интеграцию.
        """
        ...


class SecurityRule(Protocol):
    """Контракт правила: ID, обязательные данные, применимость, алгоритм, рекомендация и подтверждение."""
    id: str
    required_data: tuple[str, ...]
    recommendation: str
    verification: str
    def applicable(self, snapshot: ConfigurationSnapshot, policy: AuditPolicy) -> bool:
        """
        Проверяет поддерживаемый scope снимка; при неприменимости движок формирует not_applicable
        без выполнения алгоритма.
        """
        ...
    def evaluate(self, snapshot: ConfigurationSnapshot, policy: AuditPolicy) -> Finding:
        """
        Контракт операции evaluate; реализация передаётся извне. Типы аргументов и результата
        определяют ожидаемые данные, тело Protocol не выполняет интеграцию.
        """
        ...
