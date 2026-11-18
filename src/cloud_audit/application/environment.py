from dataclasses import dataclass
from typing import Protocol

from cloud_audit.domain.settings import Settings


class StateStorage(Protocol):
    def prepare(self) -> None: ...


@dataclass(frozen=True)
class EnvironmentReport:
    status: str
    environment: str
    log_level: str


class EnvironmentService:
    def __init__(self, settings: Settings, storage: StateStorage):
        self._settings = settings
        self._storage = storage

    def check(self) -> EnvironmentReport:
        self._storage.prepare()
        return EnvironmentReport('ok', self._settings.environment, self._settings.log_level)
