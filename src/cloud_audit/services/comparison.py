"""
Сравнивает ресурс, контекст, охват и результаты; требует новых сопоставимых доказательств, чтобы
объявить устранение.
"""
from dataclasses import replace
from datetime import datetime
import json

from cloud_audit.errors import AuditError
from cloud_audit.models.history import FindingChange, ReportComparison, ComparisonContext
from cloud_audit.models.security import SecurityReport


OPEN = {'confirmed_violation', 'potential_risk'}


def runtime_proofs(finding, outcome):
    """
    Извлекает из evidence время и точные цели allowed/2xx или denied/403; некорректные
    доказательства не учитывает.
    """
    proofs = {}
    source = {'anonymous-read': 'anonymous_get_object', 'anonymous-list': 'anonymous_list_objects_v2',
              'anonymous-write': 'anonymous_put_object', 'anonymous-delete': 'anonymous_delete_object'}.get(finding.rule_id)
    for evidence in finding.evidence:
        if evidence.source != source or evidence.observation_status != 'available':
            continue
        try:
            data = json.loads(evidence.value)
            status = data['http_status']
            if data['outcome'] != outcome or type(status) is not int:
                continue
            if outcome == 'allowed' and not 200 <= status < 300 or outcome == 'denied' and status != 403:
                continue
            at = datetime.fromisoformat(data['checked_at'])
            if at.tzinfo is None:
                continue
            proofs[data.get('object_key', '__bucket__')] = at
        except (ValueError, TypeError, KeyError, AttributeError):
            continue
    return proofs


class ReportComparisonService:
    """Чистая логика сравнения; не обращается к сети или БД."""
    def compare(self, before: SecurityReport, after: SecurityReport) -> ReportComparison:
        """
        Проверяет идентичность/namespace/версию/охват/политику/время и классифицирует переходы;
        confirmed anonymous resolved требует точных новых отказов.
        """
        if not isinstance(before, SecurityReport) or not isinstance(after, SecurityReport):
            raise AuditError('Only security reports can be compared')
        reasons = []
        if before.mode != after.mode or before.resource.id != after.resource.id:
            reasons.append('resource_identity_changed')
        if not before.resource_namespace or before.resource_namespace != after.resource_namespace:
            reasons.append('resource_namespace_unknown_or_changed')
        if before.scope != after.scope or set(before.object_keys) != set(after.object_keys):
            reasons.append('coverage_changed')
        if replace(before.policy, exceptions=()) != replace(after.policy, exceptions=()):
            reasons.append('audit_policy_changed')
        if not before.ruleset_version or before.ruleset_version != after.ruleset_version:
            reasons.append('ruleset_version_unknown_or_changed')
        if datetime.fromisoformat(after.snapshot_collected_at) < datetime.fromisoformat(before.snapshot_collected_at):
            reasons.append('observation_time_reversed')
        if 'probe_cleanup_failed' in after.limitations:
            reasons.append('probe_cleanup_failed')
        old = {row.rule_id: row for row in before.results}
        new = {row.rule_id: row for row in after.results}
        changes = []
        for rule_id in dict.fromkeys((*old, *new)):
            previous, current = old.get(rule_id), new.get(rule_id)
            change, reason = 'unverified', 'rule_not_executed_in_both_runs'
            if reasons:
                reason = ', '.join(reasons)
            elif previous is not None and current is not None:
                if previous.status in OPEN and current.status in OPEN:
                    change, reason = 'persisted', 'Finding remains, including accepted exceptions'
                elif previous.status == 'passed' and current.status in OPEN:
                    if before.snapshot_id == after.snapshot_id or datetime.fromisoformat(after.snapshot_collected_at) <= datetime.fromisoformat(before.snapshot_collected_at):
                        reason = 'new_observation_required'
                    else:
                        change, reason = 'new', 'Previously checked rule now reports a finding'
                elif previous.status in OPEN and current.status == 'passed':
                    if (before.snapshot_id == after.snapshot_id or datetime.fromisoformat(after.snapshot_collected_at)
                            <= datetime.fromisoformat(before.snapshot_collected_at)):
                        reason = 'new_observation_required'
                    elif rule_id.startswith('anonymous-') and previous.status == 'confirmed_violation':
                        allowed, denied = runtime_proofs(previous, 'allowed'), runtime_proofs(current, 'denied')
                        if allowed and all(key in denied and denied[key] > at for key, at in allowed.items()):
                            change, reason = 'resolved', 'New unsigned requests deny the previously accessible targets'
                        else:
                            reason = 'matching_new_unsigned_denial_required'
                    else:
                        change, reason = 'resolved', 'Fresh comparable evidence no longer reports the finding'
                elif previous.status == current.status and current.status in {'passed', 'not_applicable'}:
                    change, reason = 'unchanged', 'Result unchanged; not a remediation event'
                else:
                    reason = 'insufficient_or_inapplicable_result'
            changes.append(FindingChange(rule_id, change, reason, previous, current))
        def context(report):
            """Копирует provenance, охват, политику и статусы отчёта в отдельный ComparisonContext."""
            return ComparisonContext(report.snapshot_id, report.resource_namespace, report.ruleset_version,
                report.scope, report.object_keys, report.policy, report.collection_status, report.evaluation_status)
        return ReportComparison(before.id, after.id, before.resource, after.resource,
            before.snapshot_collected_at, after.snapshot_collected_at, not reasons, tuple(reasons), tuple(changes),
            context(before), context(after))
