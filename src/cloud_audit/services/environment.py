"""Готовит локальное состояние и формирует результат проверки окружения через внедряемое хранилище."""
from dataclasses import dataclass

from cloud_audit.interfaces import StateStorage
from cloud_audit.models.settings import Settings


@dataclass(frozen=True)
class EnvironmentReport:
    """Результат локальной проверки готовности без облачных ключей."""
    status: str
    environment: str
    log_level: str


class EnvironmentService:
    """Проверка конфигурации и доступности каталогов через StateStorage."""
    def __init__(self, settings: Settings, storage: StateStorage):
        """
        Сохраняет переданные зависимости и параметры экземпляра; конкретные внешние действия
        выполняются отдельными методами.
        """
        self._settings = settings
        self._storage = storage

    def check(self) -> EnvironmentReport:
        """Готовит каталоги через StateStorage, возвращает status=ok и параметры окружения без ключей."""
        self._storage.prepare()
        return EnvironmentReport('ok', self._settings.environment, self._settings.log_level)
