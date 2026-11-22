"""
Транзакционная история SQLite: неизменяемые ID, полные отчёты, failed-запуски без находок, фильтры и
явный импорт JSON.
"""
from collections import Counter
from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sqlite3
from uuid import uuid4

from cloud_audit.errors import AuditError
from cloud_audit.models.resources import Resource
from cloud_audit.models.history import HistoryEntry, HistoryPage, HistoryQuery
from cloud_audit.models.security import FINDING_STATUSES, SecurityReport
from cloud_audit.storage.json_reports import JsonReportRepository, decode_report


SCHEMA = '''
CREATE TABLE IF NOT EXISTS runs (
 id TEXT PRIMARY KEY, mode TEXT NOT NULL, resource_id TEXT NOT NULL, resource_name TEXT NOT NULL,
 observed_at TEXT, recorded_at TEXT NOT NULL, run_status TEXT NOT NULL,
 parameters TEXT NOT NULL, payload TEXT, error_code TEXT
);
CREATE TABLE IF NOT EXISTS run_rules (
 run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE, rule_id TEXT NOT NULL,
 position INTEGER NOT NULL, status TEXT, severity TEXT, PRIMARY KEY(run_id, rule_id)
);
CREATE INDEX IF NOT EXISTS runs_resource_time ON runs(mode, resource_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS rules_filters ON run_rules(rule_id, severity, status, run_id);
'''


def utc(value):
    """Приводит ISO-время с timezone к UTC для устойчивой сортировки в SQLite."""
    return datetime.fromisoformat(value).astimezone(timezone.utc).isoformat()


class SqliteReportRepository:
    """Основной репозиторий отчётов и истории, включая отдельные неудачные запуски."""
    MAX_REPORT_BYTES = 32 * 1024 * 1024

    def __init__(self, path: Path, legacy: JsonReportRepository | None = None):
        """
        Сохраняет переданные зависимости и параметры экземпляра; конкретные внешние действия
        выполняются отдельными методами.
        """
        self._path = path
        self._legacy = legacy

    @contextmanager
    def _connection(self):
        """
        Создаёт приватную БД, проверяет user_version, включает FK, открывает транзакцию и всегда
        закрывает соединение; sqlite-ошибки скрывает за OSError.
        """
        connection = None
        try:
            self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            self._path.parent.chmod(0o700)
            if self._path.is_symlink():
                raise AuditError('Invalid history database path')
            descriptor = os.open(self._path, os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0), 0o600)
            try:
                os.fchmod(descriptor, 0o600)
            finally:
                os.close(descriptor)
            connection = sqlite3.connect(self._path, timeout=5)
            connection.execute('PRAGMA foreign_keys=ON')
            version = connection.execute('PRAGMA user_version').fetchone()[0]
            if version not in (0, 1):
                raise AuditError('Unsupported history database version')
            if version == 0:
                connection.executescript(SCHEMA)
                connection.execute('PRAGMA user_version=1')
                connection.commit()
            with connection:
                yield connection
        except sqlite3.Error:
            raise OSError('Cannot access audit history database') from None
        finally:
            if connection is not None:
                connection.close()

    def _identifier(self, value):
        """Требует строковый UUID hex; некорректный ID отклоняет до запроса."""
        if not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{32}', value):
            raise AuditError('Invalid report identifier')

    def save(self, report) -> None:
        """Сохраняет канонический отчёт через общую транзакционную реализацию _save."""
        self._save(report)

    def _save(self, report) -> bool:
        """
        Проверяет лимит 32 МиБ/схему, сохраняет runs+run_rules атомарно; одинаковый ID/JSON
        идемпотентен, конфликт запрещён.
        """
        self._identifier(report.id)
        payload = json.dumps(asdict(report), ensure_ascii=False, sort_keys=True, allow_nan=False)
        if len(payload.encode('utf-8')) > self.MAX_REPORT_BYTES:
            raise AuditError('Report exceeds history storage size limit')
        decoded = decode_report(json.loads(payload), report.id)
        now = datetime.now(timezone.utc).isoformat()
        security = isinstance(decoded, SecurityReport)
        observed = utc(decoded.snapshot_collected_at) if security else None
        recorded = utc(decoded.evaluated_at) if security else now
        status = decoded.evaluation_status if security else 'demo'
        parameters = ({'snapshot_id': decoded.snapshot_id, 'scope': decoded.scope,
                       'object_keys': decoded.object_keys, 'policy': asdict(decoded.policy),
                       'ruleset_version': decoded.ruleset_version,
                       'resource_namespace': decoded.resource_namespace} if security else {'mode': 'demo'})
        with self._connection() as connection:
            existing = connection.execute('SELECT payload FROM runs WHERE id=?', (report.id,)).fetchone()
            if existing is not None:
                if existing[0] != payload:
                    raise AuditError('Conflicting report identifier; history cannot be overwritten')
                return False
            connection.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?,?,?)',
                (decoded.id, decoded.mode, decoded.resource.id, decoded.resource.name, observed, recorded,
                 status, json.dumps(parameters, ensure_ascii=False), payload, None))
            connection.executemany('INSERT INTO run_rules VALUES(?,?,?,?,?)',
                ((decoded.id, item.rule_id, index, item.status, item.risk.level if security else 'unknown')
                 for index, item in enumerate(decoded.results)))
        return True

    def get(self, report_id):
        """
        Читает и проверяет полный отчёт из БД; при отсутствии ID обращается к legacy, failed без
        payload отклоняет.
        """
        self._identifier(report_id)
        with self._connection() as connection:
            row = connection.execute('SELECT payload FROM runs WHERE id=?', (report_id,)).fetchone()
        if row is None:
            if self._legacy is not None:
                return self._legacy.get(report_id)
            raise AuditError('Report not found')
        if row[0] is None:
            raise AuditError('This audit run failed and has no security report')
        try:
            return decode_report(json.loads(row[0]), report_id)
        except (ValueError, TypeError, RecursionError):
            raise AuditError('Invalid stored history report') from None

    def record_failure(self, resource_id, selected_rules, object_keys, error_code, resource_namespace=None):
        """
        Записывает безопасную категорию сбоя, выбранные правила/объекты/namespace, без находок и без
        фиктивного отчёта.
        """
        if error_code not in {'cloud_request_failed', 'snapshot_storage_failed'}:
            raise AuditError('Invalid audit failure category')
        identifier = uuid4().hex
        now = datetime.now(timezone.utc).isoformat()
        parameters = json.dumps({'object_keys': object_keys, 'selected_rules': selected_rules,
                                 'resource_namespace': resource_namespace}, ensure_ascii=False)
        with self._connection() as connection:
            connection.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?,?,?)',
                (identifier, 'vk', resource_id, resource_id, None, now, 'failed', parameters, None, error_code))
            connection.executemany('INSERT INTO run_rules VALUES(?,?,?,?,?)',
                ((identifier, rule_id, index, None, None) for index, rule_id in enumerate(dict.fromkeys(selected_rules))))
        return identifier

    def history(self, query: HistoryQuery) -> HistoryPage:
        """
        Валидирует фильтры/пагинацию, применяет параметры SQL к одной находке, возвращает total,
        полный счётчик статусов и страницу.
        """
        if (type(query.limit) is not int or not 1 <= query.limit <= 500 or type(query.offset) is not int or query.offset < 0
                or query.mode not in {None, 'vk', 'demo'}
                or query.severity not in {None, 'none', 'unknown', 'low', 'medium', 'high', 'critical'}
                or query.finding_status not in FINDING_STATUSES | {None, 'simulated'}
                or query.run_status not in {None, 'complete', 'incomplete', 'failed', 'demo'}):
            raise AuditError('Invalid history filter or pagination')
        clauses, values = [], []
        for column, value in (('resource_id', query.resource_id), ('mode', query.mode), ('run_status', query.run_status)):
            if value is not None:
                clauses.append(f'r.{column}=?')
                values.append(value)
        filters = []
        for column, value in (('rule_id', query.rule_id), ('severity', query.severity), ('status', query.finding_status)):
            if value is not None:
                filters.append(f'f.{column}=?')
                values.append(value)
        if filters:
            clauses.append('EXISTS(SELECT 1 FROM run_rules f WHERE f.run_id=r.id AND ' + ' AND '.join(filters) + ')')
        where = ' WHERE ' + ' AND '.join(clauses) if clauses else ''
        entries = []
        with self._connection() as connection:
            total = connection.execute('SELECT count(*) FROM runs r' + where, values).fetchone()[0]
            rows = connection.execute('SELECT r.id,r.mode,r.resource_id,r.resource_name,r.observed_at,r.recorded_at,r.run_status,r.error_code,r.parameters '
                'FROM runs r' + where + ' ORDER BY COALESCE(r.observed_at,r.recorded_at) DESC,r.recorded_at DESC,r.id DESC LIMIT ? OFFSET ?',
                (*values, query.limit, query.offset)).fetchall()
            for row in rows:
                try:
                    namespace = json.loads(row[8]).get('resource_namespace')
                except (ValueError, TypeError, AttributeError):
                    raise AuditError('Invalid history metadata') from None
                findings = connection.execute('SELECT rule_id,status FROM run_rules WHERE run_id=? ORDER BY position', (row[0],)).fetchall()
                entries.append(HistoryEntry(row[0], row[1], Resource(row[2], row[3]), row[4], row[5], row[6],
                    tuple(item[0] for item in findings), dict(Counter(item[1] for item in findings if item[1] is not None)), row[7], namespace))
        return HistoryPage(tuple(entries), total, query.limit, query.offset)

    def import_legacy(self):
        """
        Явно импортирует совместимые UUID-JSON, оставляя источники; повторный импорт идемпотентен,
        повреждённые/конфликтующие ID перечисляет в skipped.
        """
        imported, skipped = 0, []
        if self._legacy is None:
            return {'imported': 0, 'skipped': [], 'source_files_deleted': False}
        for identifier in self._legacy.identifiers():
            try:
                imported += self._save(self._legacy.get(identifier))
            except AuditError:
                skipped.append(identifier)
        return {'imported': imported, 'skipped': skipped, 'source_files_deleted': False}
