"""Строгий файл целей: объекты и разрешения мутаций задаются отдельно для каждого бакета."""
import json
from pathlib import Path

from cloud_audit.configuration.policy import parse_audit_policy
from cloud_audit.errors import ConfigurationError
from cloud_audit.models.scanning import ScanTarget


def parse_targets(data):
    """Проверяет поля, типы и уникальность до любых сетевых запросов; ключи доступа здесь запрещены."""
    try:
        if not isinstance(data, dict) or set(data) != {'buckets'} or not isinstance(data['buckets'], list) or not data['buckets'] or len(data['buckets']) > 500:
            raise ValueError
        result = []
        for row in data['buckets']:
            if not isinstance(row, dict) or set(row) - {'name', 'objects', 'allow_mutations', 'allow_residue', 'policy'}:
                raise ValueError
            keys = row.get('objects', [])
            if not isinstance(keys, list):
                raise ValueError
            result.append(ScanTarget(row['name'], tuple(keys), row.get('allow_mutations', False),
                                     row.get('allow_residue', False), parse_audit_policy(row.get('policy', {}))))
        if len({row.name for row in result}) != len(result):
            raise ValueError
        return tuple(result)
    except (ValueError, KeyError, TypeError, AttributeError):
        raise ConfigurationError('Invalid scan targets; check bucket names, scopes and permissions') from None


def load_targets(path: Path):
    """Читает UTF-8 JSON до 256 КиБ без исполнения содержимого."""
    try:
        if path.stat().st_size > 256 * 1024:
            raise ValueError
        return parse_targets(json.loads(path.read_text(encoding='utf-8')))
    except (ValueError, UnicodeError, RecursionError):
        raise ConfigurationError('Invalid scan targets file') from None
