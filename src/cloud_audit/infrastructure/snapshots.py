"""Versioned JSON snapshots with private atomic storage and seven-day retention."""
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Callable

from cloud_audit.application.audit import AuditError
from cloud_audit.domain.audit import Resource
from cloud_audit.domain.snapshot import (
    ConfigurationObservation, ConfigurationSnapshot, CONFIGURATION_FIELDS,
    LIMITATIONS, OBSERVATION_STATUSES,
    CollectionOptions, collection_limitations, collection_complete,
)
from cloud_audit.infrastructure.snapshot_schema import validate_observation


class JsonSnapshotRepository:
    RETENTION = timedelta(days=7)
    MAX_BYTES = 2 * 1024 * 1024

    def __init__(self, directory: Path, clock: Callable[[], datetime] | None = None):
        self._directory = directory
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def _path(self, snapshot_id: str) -> Path:
        if not re.fullmatch(r'[0-9a-f]{32}', snapshot_id):
            raise AuditError('Invalid snapshot identifier')
        return self._directory / f'{snapshot_id}.json'

    def _decode(self, raw: str, expected_id: str) -> ConfigurationSnapshot:
        try:
            data = json.loads(raw)
            if (type(data['schema_version']) is not int or data['schema_version'] not in (1, 2)
                    or data['id'] != expected_id or data['provider'] != 'vk'
                    or data['scope'] not in {'bucket_configuration_only', 'bucket_and_selected_objects'}):
                raise ValueError
            keys = tuple(data.get('object_keys', ()))
            if data.get('resource_namespace') is not None and not isinstance(data['resource_namespace'], str):
                raise ValueError
            CollectionOptions(keys)
            version = data['schema_version']
            if version == 1 and (keys or data['scope'] != 'bucket_configuration_only'):
                raise ValueError
            if version == 2 and data['scope'] != ('bucket_and_selected_objects' if keys else 'bucket_configuration_only'):
                raise ValueError
            if data['limitations'] != list(LIMITATIONS if version == 1 else collection_limitations(keys)):
                raise ValueError
            resource = Resource(**data['resource'])
            if not all(isinstance(value, str) and value for value in (resource.id, resource.name)):
                raise ValueError
            collected_at = datetime.fromisoformat(data['collected_at'])
            if collected_at.tzinfo is None or collected_at > self._clock() + timedelta(minutes=5):
                raise ValueError
            observations = tuple(ConfigurationObservation(**item) for item in data['observations'])
            names = {x.name for x in observations}
            required = CONFIGURATION_FIELDS | {f'object_acl:{key}' for key in keys}
            allowed = required | ({'anonymous_list', 'anonymous_write', 'anonymous_delete'} |
                                  {f'anonymous_read:{key}' for key in keys} if version == 2 else set())
            if len(observations) != len(names) or not required <= names or not names <= allowed:
                raise ValueError
            for item in observations:
                if item.status not in OBSERVATION_STATUSES or not isinstance(item.source, str):
                    raise ValueError
                validate_observation(item)
            expected_status = 'complete_for_scope' if collection_complete(observations) else 'partial'
            if data['collection_status'] != expected_status:
                raise ValueError
            return ConfigurationSnapshot(**(data | {'resource': resource,
                'limitations': tuple(data['limitations']), 'observations': observations, 'object_keys': keys}))
        except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
            raise AuditError('Invalid saved configuration snapshot') from None

    def save(self, snapshot: ConfigurationSnapshot) -> None:
        path = self._path(snapshot.id)
        raw = json.dumps(asdict(snapshot), ensure_ascii=False, allow_nan=False)
        self._decode(raw, snapshot.id)
        if len(raw.encode('utf-8')) > self.MAX_BYTES:
            raise AuditError('Configuration snapshot exceeds storage size limit')
        if self._directory.is_symlink():
            raise AuditError('Invalid snapshot storage directory')
        self._directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._directory.chmod(0o700)
        self._purge_expired()
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8',
                                             dir=self._directory, delete=False) as file:
                temporary = Path(file.name)
                file.write(raw)
                file.flush()
                os.fsync(file.fileno())
            os.replace(temporary, path)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def _read(self, path: Path) -> ConfigurationSnapshot:
        if path.is_symlink() or path.stat().st_size > self.MAX_BYTES:
            raise AuditError('Invalid saved configuration snapshot')
        return self._decode(path.read_text(encoding='utf-8'), path.stem)

    def get(self, snapshot_id: str) -> ConfigurationSnapshot:
        path = self._path(snapshot_id)
        try:
            snapshot = self._read(path)
        except FileNotFoundError:
            raise AuditError('Configuration snapshot not found') from None
        except UnicodeError:
            raise AuditError('Invalid saved configuration snapshot') from None
        if self._expired(snapshot):
            raise AuditError('Configuration snapshot expired')
        return snapshot

    def _expired(self, snapshot: ConfigurationSnapshot) -> bool:
        return self._clock() - datetime.fromisoformat(snapshot.collected_at) >= self.RETENTION

    def _purge_expired(self) -> None:
        for path in self._directory.glob('*.json'):
            if not re.fullmatch(r'[0-9a-f]{32}', path.stem) or path.is_symlink():
                continue
            try:
                snapshot = self._read(path)
            except (AuditError, FileNotFoundError, UnicodeError):
                continue
            if self._expired(snapshot):
                path.unlink(missing_ok=True)
