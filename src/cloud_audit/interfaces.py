"""
Контракты внедряемых провайдеров, репозиториев и правил. Описывают необходимые операции без
зависимости от boto3, SQLite и CLI.
"""
from typing import Protocol

from cloud_audit.models.resources import AuditReport, Resource, RuleResult
from cloud_audit.models.security import AuditPolicy, Finding, SecurityReport
from cloud_audit.models.snapshot import CollectionOptions, ConfigurationObservation, ConfigurationSnapshot
from cloud_audit.models.history import HistoryQuery, HistoryPage
from cloud_audit.models.scanning import ScanTarget, ScanRun, ExternalResult, ObjectDiscovery, ProbeResult


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


class ReportRepository(Protocol):
    """Контракт сохранения и чтения demo или настоящего отчёта."""
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


class AuditHistoryRepository(Protocol):
    """Контракт чтения полных отчётов и страниц истории."""
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


class ExternalInspection(Protocol):
    """Внешняя проверка через unsigned-клиент и ограниченное чтение дополнительно найденных объектов."""
    namespace: str

    def inspect(self, target: ScanTarget, limit: int) -> ExternalResult:
        """Возвращает факты выбранных операций и охват списка, без внутреннего аудита."""
        ...

    def read_objects(self, bucket: str, keys: tuple[str, ...]) -> tuple[ProbeResult, ...]:
        """Проверяет новые ключи, не повторяя запись/удаление или список."""
        ...


class ScanRunRepository(Protocol):
    """Сохранение и чтение самодостаточного многоцелевого запуска."""
    def save(self, run: ScanRun) -> None:
        """Публикует неизменяемую сводку по ID."""
        ...

    def get(self, identifier: str) -> ScanRun:
        """Возвращает проверенную сводку без подключения к облаку."""
        ...


class ScanProvider(StorageProvider, ConfigurationCollector, Protocol):
    """Авторизованный провайдер выбора бакетов, настроек и ограниченных ключей объектов."""
    def discover_objects(self, bucket: str, limit: int) -> ObjectDiscovery:
        """Возвращает явный полный/ограниченный/ошибочный охват объектов."""
        ...
