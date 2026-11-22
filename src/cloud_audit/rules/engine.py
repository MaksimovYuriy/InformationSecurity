"""
Выполняет зарегистрированные правила над снимком: выбор, применимость, обязательные данные и
документированные исключения.
"""
from dataclasses import replace
from datetime import datetime, timezone

from cloud_audit.errors import AuditError
from cloud_audit.rules.risk import RiskModel
from cloud_audit.interfaces import SecurityRule
from cloud_audit.models.security import AuditPolicy, Evidence, Finding
from cloud_audit.models.snapshot import ConfigurationSnapshot


class RuleEngine:
    """Универсальный исполнитель правил, не зависящий от облачного SDK и формата хранения."""
    def __init__(self, rules: tuple[SecurityRule, ...]):
        """
        Сохраняет переданные зависимости и параметры экземпляра; конкретные внешние действия
        выполняются отдельными методами.
        """
        self._rules = {rule.id: rule for rule in rules}
        if len(self._rules) != len(rules):
            raise ValueError('Duplicate rule identifiers')

    def select(self, selected: tuple[str, ...]) -> tuple[SecurityRule, ...]:
        """
        Выбирает все или уникальные запрошенные ID в порядке запроса; неизвестные ID и пустой реестр
        отклоняет AuditError.
        """
        identifiers = tuple(dict.fromkeys(selected)) if selected else tuple(self._rules)
        if not identifiers or any(identifier not in self._rules for identifier in identifiers):
            raise AuditError('Unknown rule identifier')
        return tuple(self._rules[identifier] for identifier in identifiers)

    def evaluate(self, snapshot: ConfigurationSnapshot, policy: AuditPolicy,
                 selected: tuple[str, ...] = ()) -> tuple[Finding, ...]:
        """
        Для каждого правила проверяет применимость/данные, выполняет алгоритм и добавляет
        действующее исключение, не скрывая находку.
        """
        rules = self.select(selected)
        if any(item.rule_id not in self._rules for item in policy.exceptions):
            raise AuditError('Unknown rule identifier in exception policy')
        observations = {item.name: item for item in snapshot.observations}
        results = []
        for rule in rules:
            if not rule.applicable(snapshot, policy):
                result = Finding(rule.id, 'not_applicable', 'Rule does not apply to this scope', (),
                    RiskModel().assess('not_applicable', policy.data_sensitivity), '', '')
            elif any(name not in observations or observations[name].status not in {'available', 'absent'}
                     for name in rule.required_data):
                evidence = tuple(Evidence(name,
                    observations[name].source if name in observations else 'not_collected',
                    observations[name].status if name in observations else 'missing', None)
                    for name in rule.required_data)
                result = Finding(rule.id, 'insufficient_data', 'Required configuration data is unavailable',
                    evidence, RiskModel().assess('insufficient_data', policy.data_sensitivity),
                    'Obtain the required configuration with read-only permissions; do not infer safety.',
                    'Collect a new snapshot and rerun the rule.')
            else:
                result = rule.evaluate(snapshot, policy)
            if result.status in {'confirmed_violation', 'potential_risk'}:
                for exception in policy.exceptions:
                    if (exception.resource_id == snapshot.resource.id and exception.rule_id == rule.id
                            and (exception.expires_at is None or datetime.fromisoformat(exception.expires_at)
                                 > datetime.fromisoformat(snapshot.collected_at))):
                        # Compare expiry with evaluation time as well: old evidence cannot revive an exception.
                        if exception.expires_at and datetime.fromisoformat(exception.expires_at) <= datetime.now(timezone.utc):
                            continue
                        result = replace(result, exception_reason=exception.reason)
                        break
            results.append(result)
        return tuple(results)
