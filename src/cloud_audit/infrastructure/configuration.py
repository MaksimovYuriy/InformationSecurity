from collections.abc import Mapping
from pathlib import Path

from cloud_audit.domain.settings import Settings


class ConfigurationError(ValueError):
    """Invalid configuration; messages never include supplied values."""


def load_settings(environment: Mapping[str, str]) -> Settings:
    name = environment.get('CLOUD_AUDIT_ENV', 'development')
    level = environment.get('CLOUD_AUDIT_LOG_LEVEL', 'INFO')
    state = environment.get('CLOUD_AUDIT_STATE_DIR', '.state')
    if name not in {'development', 'test', 'production'}:
        raise ConfigurationError('Invalid CLOUD_AUDIT_ENV')
    if level not in {'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'}:
        raise ConfigurationError('Invalid CLOUD_AUDIT_LOG_LEVEL')
    if not state.strip():
        raise ConfigurationError('Invalid CLOUD_AUDIT_STATE_DIR')
    return Settings(name, level, Path(state))
