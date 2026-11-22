"""Оценка только наблюдавшихся unsigned-операций, без предположений о полной конфигурации."""
from dataclasses import asdict
import json

from cloud_audit.models.security import Evidence, Finding
from cloud_audit.rules.risk import RiskModel


def external_findings(probes, policy):
    """Группирует пробы четырёх операций; отказ относится только к проверенным целям, пропуск не даёт passed."""
    findings = []
    for operation in ('list', 'read', 'write', 'delete'):
        rows = [p for p in probes if p.operation == operation]
        allowed = any(p.outcome == 'allowed' for p in rows)
        status = ('confirmed_violation' if allowed else 'passed' if rows and all(p.outcome == 'denied' for p in rows)
                  else 'insufficient_data')
        evidence = tuple(Evidence(operation, 'unsigned_request', p.outcome, json.dumps(asdict(p), sort_keys=True)) for p in rows)
        if not evidence:
            evidence = (Evidence(operation, 'scope', 'not_tested', None),)
        findings.append(Finding('anonymous-' + operation, status,
            'Unsigned access confirmed for a recorded target' if allowed else 'Only recorded requests were denied' if status == 'passed' else 'Access was not determined for this operation',
            evidence, RiskModel().assess(status, policy.data_sensitivity, (operation,), 'public_confirmed' if allowed else 'unknown'),
            'Remove unintended public policy/ACL grants for this operation; preserve required application access.',
            'Repeat the same unsigned operation on an approved artificial target after the change.',
            limitations=('only_tested_requests', 'no_global_safety_claim')))
    return tuple(findings)
