"""Версионированные приватные сводки scan: атомарное сохранение и строгое чтение без сети."""
from dataclasses import asdict, fields, is_dataclass
from pathlib import Path
from types import UnionType
from typing import get_args, get_origin, get_type_hints, Union
import json
import os
import re
import tempfile

from cloud_audit.errors import AuditError
from cloud_audit.models.scanning import ScanRun
from cloud_audit.rules.external import external_findings
from cloud_audit.configuration.policy import parse_audit_policy


def decode_value(value, annotation):
    """Восстанавливает только известные dataclass/tuple/скаляры со строгими типами, не исполняя JSON."""
    origin = get_origin(annotation)
    if origin in (UnionType, Union):
        for choice in get_args(annotation):
            try:
                return decode_value(value, choice)
            except (TypeError, ValueError):
                pass
        raise ValueError
    if origin is tuple:
        if not isinstance(value, list):
            raise ValueError
        return tuple(decode_value(item, get_args(annotation)[0]) for item in value)
    if is_dataclass(annotation):
        if not isinstance(value, dict) or set(value) - {f.name for f in fields(annotation)}:
            raise ValueError
        hints = get_type_hints(annotation)
        return annotation(**{key: decode_value(item, hints[key]) for key, item in value.items()})
    if type(value) is not annotation:
        raise ValueError
    return value


class JsonScanRepository:
    """Сохраняет общую сводку отдельно от SQLite-отчётов бакетов, без изменения прежней схемы БД."""
    MAX_BYTES = 32 * 1024 * 1024

    def __init__(self, directory: Path):
        """Принимает выделенный приватный каталог сводок."""
        self.directory = directory

    def _path(self, identifier):
        """Проверяет UUID до построения пути."""
        if not isinstance(identifier, str) or not re.fullmatch(r'[0-9a-f]{32}', identifier):
            raise AuditError('Invalid scan identifier')
        return self.directory / (identifier + '.json')

    def save(self, run: ScanRun):
        """Атомарно публикует новый файл 0600 без перезаписи другого результата с тем же ID."""
        path = self._path(run.id)
        raw = json.dumps(asdict(run), ensure_ascii=False, allow_nan=False)
        self._validate(decode_value(json.loads(raw), ScanRun))
        if len(raw.encode('utf-8')) > self.MAX_BYTES:
            raise AuditError('Scan report exceeds storage size limit')
        if self.directory.is_symlink():
            raise AuditError('Invalid scan storage directory')
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.directory.chmod(0o700)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=self.directory, delete=False) as file:
                temporary = Path(file.name)
                file.write(raw)
                file.flush()
                os.fsync(file.fileno())
            try:
                os.link(temporary, path)
            except FileExistsError:
                if self.get(run.id) != run:
                    raise AuditError('Conflicting scan identifier') from None
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def get(self, identifier):
        """Читает и проверяет форму/версию/вложенные типы; повреждённые сводки не становятся пустым успехом."""
        path = self._path(identifier)
        try:
            if path.is_symlink() or path.stat().st_size > self.MAX_BYTES:
                raise ValueError
            run = decode_value(json.loads(path.read_text(encoding='utf-8')), ScanRun)
            if run.id != identifier:
                raise ValueError
            self._validate(run)
            return run
        except (ValueError, TypeError, KeyError, UnicodeError, FileNotFoundError, RecursionError):
            raise AuditError('Invalid or missing scan report') from None

    @staticmethod
    def _validate(run):
        """Проверяет согласованность сохранённых выводов с пробами и контекстом, а не только тип JSON."""
        for row in run.buckets:
            if row.target is None or row.target.name != row.bucket:
                raise ValueError('Missing scan target context')
            parse_audit_policy(json.loads(json.dumps(asdict(row.target.policy))))
            if (row.internal_status in {'complete', 'incomplete'}) != (row.internal_report_id is not None):
                raise ValueError('Inconsistent internal report reference')
            if row.external is None:
                if row.external_status != 'failed' or row.external_findings:
                    raise ValueError('Missing external evidence')
                continue
            if row.external_status == 'failed':
                raise ValueError('Contradictory external status')
            for probe in row.external.probes:
                if probe.operation == 'delete' and probe.outcome == 'allowed' and probe.verification != 'current_object_absent':
                    raise ValueError('Unverified delete cannot confirm access')
            expected = external_findings(row.external.probes, row.target.policy)
            actual = {f.rule_id: f for f in row.external_findings}
            if len(actual) != len(row.external_findings) or set(actual) != {f.rule_id for f in expected}:
                raise ValueError('Invalid external rule set')
            for finding in expected:
                saved = actual[finding.rule_id]
                if saved.status != finding.status or saved.risk != finding.risk or not saved.evidence:
                    raise ValueError('Inconsistent external finding')
