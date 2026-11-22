"""Настройки окружения и S3. Ключи исключены из repr; сериализация настроек в отчёты не предусмотрена."""
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    """Параметры среды, уровня журнала и выделенного корня состояния."""
    environment: str
    log_level: str
    state_dir: Path


@dataclass(frozen=True)
class S3Settings:
    """HTTPS endpoint, регион подписи и ключи с repr=False; не передаётся модели ИИ."""
    endpoint_url: str
    region: str
    access_key: str = field(repr=False)
    secret_key: str = field(repr=False)


