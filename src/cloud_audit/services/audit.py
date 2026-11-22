"""
Запускает движок, объединяет ограничения, формирует SecurityReport v3 и сохраняет его через
интерфейс репозитория.
"""
from datetime import datetime, timezone
from uuid import uuid4

from cloud_audit.interfaces import SecurityReportRepository
from cloud_audit.rules.engine import RuleEngine
from cloud_audit.models.security import AuditPolicy, SecurityReport, CURRENT_RULESET_VERSION
from cloud_audit.models.snapshot import ConfigurationSnapshot


class SecurityAuditService:
    """Формирует и сохраняет настоящий отчёт на основании снимка и результатов движка."""
    def __init__(self, engine: RuleEngine, reports: SecurityReportRepository):
        """
        Сохраняет переданные зависимости и параметры экземпляра; конкретные внешние действия
        выполняются отдельными методами.
        """
        self._engine = engine
        self._reports = reports

    def audit(self, snapshot: ConfigurationSnapshot, policy: AuditPolicy,
              selected: tuple[str, ...] = ()) -> SecurityReport:
        """
        Выполняет правила, объединяет ограничения/ошибки уборки, создаёт v3 с
        UUID/временем/namespace/версией и сохраняет.
        """
        results = self._engine.evaluate(snapshot, policy, selected)
        limitations = tuple(x for x in snapshot.limitations if x != 'security_not_assessed')
        limitations = tuple(dict.fromkeys((*limitations, *(value for result in results for value in result.limitations))))
        cleanup_failed = any(isinstance(item.data, dict) and item.data.get('cleanup_failed') for item in snapshot.observations)
        if cleanup_failed:
            limitations += ('probe_cleanup_failed',)
        report = SecurityReport(uuid4().hex, 3, snapshot.provider, snapshot.resource,
            snapshot.id, snapshot.collected_at, datetime.now(timezone.utc).isoformat(),
            snapshot.scope, (*limitations, 'only_selected_rules_evaluated'), snapshot.collection_status,
            'incomplete' if cleanup_failed or any(x.status == 'insufficient_data' for x in results) else 'complete',
            policy, results, snapshot.object_keys, CURRENT_RULESET_VERSION, snapshot.resource_namespace)
        self._reports.save(report)
        return report
