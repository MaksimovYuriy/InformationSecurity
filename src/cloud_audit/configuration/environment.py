"""Проверяет переменные окружения приложения и S3; отдельно загружает ключи только для сетевых команд."""
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import urlsplit

from cloud_audit.models.settings import Settings, S3Settings
from cloud_audit.errors import ConfigurationError


def load_settings(environment: Mapping[str, str]) -> Settings:
    """Проверяет допустимые ENV/LOG_LEVEL и непустой STATE_DIR; возвращает Settings без чтения .env."""
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


def load_s3_settings(environment: Mapping[str, str]) -> S3Settings:
    """
    Проверяет HTTPS endpoint без credentials/пути/query, регион и непустые явные ключи; не выводит
    введённые значения.
    """
    endpoint = environment.get('CLOUD_AUDIT_S3_ENDPOINT_URL',
                               'https://hb.ru-msk.vkcloud-storage.ru')
    try:
        url = urlsplit(endpoint)
        valid = (url.scheme == 'https' and url.hostname and not url.username
                 and not url.password and url.path in ('', '/')
                 and not url.query and not url.fragment and url.port in (None, 443))
    except ValueError:
        valid = False
    if not valid:
        raise ConfigurationError('Invalid CLOUD_AUDIT_S3_ENDPOINT_URL; HTTPS endpoint required')
    region = environment.get('CLOUD_AUDIT_S3_REGION', 'us-east-1')
    if not region.strip():
        raise ConfigurationError('Invalid CLOUD_AUDIT_S3_REGION')
    values = []
    for name in ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY'):
        value = environment.get(name, '')
        if not value.strip():
            raise ConfigurationError(f'Missing {name}')
        values.append(value)
    return S3Settings(endpoint, region, *values)


def load_scan_settings(environment: Mapping[str, str], *, external_only=False):
    """Разрешает отсутствие обоих ключей для scan; один ключ — ошибка, external-only явно игнорирует пару."""
    from dataclasses import replace
    access, secret = environment.get('AWS_ACCESS_KEY_ID', ''), environment.get('AWS_SECRET_ACCESS_KEY', '')
    if not external_only and bool(access.strip()) != bool(secret.strip()):
        raise ConfigurationError('Both S3 credentials must be supplied together')
    authenticated = bool(access.strip() and secret.strip()) and not external_only
    checked = load_s3_settings(dict(environment, AWS_ACCESS_KEY_ID=access if authenticated else 'validation-only',
                                   AWS_SECRET_ACCESS_KEY=secret if authenticated else 'validation-only'))
    return (checked if authenticated else replace(checked, access_key='', secret_key='')), authenticated
