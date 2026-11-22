"""
Консервативно оценивает анонимные read/list/write/delete по выбранным целям, поддерживаемым
политикам, ACL и unsigned-пробам.
"""
from dataclasses import dataclass
import json
import re

from cloud_audit.rules.risk import RiskModel
from cloud_audit.models.security import AuditPolicy, Evidence, Finding
from cloud_audit.models.snapshot import ConfigurationSnapshot


ALL_USERS = 'http://acs.amazonaws.com/groups/global/AllUsers'
ACTIONS = {'read': 's3:GetObject', 'list': 's3:ListBucket',
           'write': 's3:PutObject', 'delete': 's3:DeleteObject'}


def matches(pattern: str, value: str) -> bool:
    # IAM has * and ?, not the [] character classes of shell fnmatch.
    """
    Сопоставляет IAM-маски * и ? через экранированное регулярное выражение; [] не трактуются как
    shell-классы.
    """
    return re.fullmatch(re.escape(pattern).replace(r'\*', '.*').replace(r'\?', '.'), value, re.DOTALL) is not None


def strings(value):
    """
    Приводит строку или непустой список строк политики к списку; некорректную форму отклоняет
    ValueError.
    """
    values = [value] if isinstance(value, str) else value
    if not isinstance(values, list) or not values or any(not isinstance(x, str) for x in values):
        raise ValueError
    return values


@dataclass(frozen=True)
class PolicyDecision:
    """Решение поддерживаемой части политики: отдельные признаки Allow, Deny и неизвестности."""
    allow: bool = False
    deny: bool = False
    unknown: bool = False


def policy_decision(observation, action: str, resource: str) -> PolicyDecision:
    """
    Рассматривает подходящие Action/Resource/Principal; сохраняет неизвестность Condition/Not*,
    различает Allow и безусловный Deny.
    """
    if observation is None or observation.status not in {'available', 'absent'}:
        return PolicyDecision(unknown=True)
    if observation.status == 'absent':
        return PolicyDecision()
    allow = deny = unknown = False
    try:
        document = observation.data['document']
        statements = document['Statement']
        statements = [statements] if isinstance(statements, dict) else statements
        if not isinstance(statements, list):
            raise ValueError
        for row in statements:
            try:
                if 'NotAction' not in row and not any(matches(x.lower(), action.lower()) for x in strings(row['Action'])):
                    continue
                if 'NotResource' not in row and not any(matches(x, resource) for x in strings(row['Resource'])):
                    continue
                principal = row.get('Principal')
                if isinstance(principal, dict):
                    if set(principal) != {'AWS'}:
                        raise ValueError
                    principal = principal['AWS']
                if 'NotPrincipal' not in row and '*' not in strings(principal):
                    continue
                if set(row) - {'Sid', 'Effect', 'Principal', 'Action', 'Resource'}:
                    # Conditions and all Not* elements are intentionally unresolved.
                    unknown = True
                    continue
                if row['Effect'] == 'Deny':
                    deny = True
                elif row['Effect'] == 'Allow':
                    allow = True
                else:
                    unknown = True
            except (KeyError, TypeError, ValueError, AttributeError):
                unknown = True
    except (KeyError, TypeError, ValueError, AttributeError):
        unknown = True
    return PolicyDecision(allow, deny, unknown)


def acl_allows(observation, permissions: set[str]) -> bool | None:
    """Ищет нужные разрешения только у AllUsers; возвращает None, если ACL нельзя надёжно интерпретировать."""
    if observation is None or observation.status != 'available':
        return None
    try:
        grants = observation.data['grants']
        if not isinstance(grants, list):
            return None
        return any(row['principal_type'] == 'Group' and row['principal'] == ALL_USERS
                   and row['permission'] in permissions for row in grants)
    except (KeyError, TypeError):
        return None


class PublicAccessRule:
    """
    Параметризованная проверка одной анонимной операции; подтверждение запросом отделено от
    предположения по настройкам.
    """
    required_data = ()  # Sources interact: a single unavailable source must not mask positive runtime evidence.
    recommendation = ('Remove unintended anonymous Allow statements and AllUsers ACL grants for this operation. '
                      'Keep explicit approved exceptions documented; check bucket and object ACL separately.')
    verification = ('Collect fresh configuration and repeat an unsigned request on the same artificial object '
                    'or bucket listing. A 403 proves denial only for that request, not every object or client.')

    def __init__(self, operation: str):
        """
        Сохраняет переданные зависимости и параметры экземпляра; конкретные внешние действия
        выполняются отдельными методами.
        """
        if operation not in ACTIONS:
            raise ValueError('Unknown public access operation')
        self.operation = operation
        self.id = f'anonymous-{operation}'

    def applicable(self, snapshot: ConfigurationSnapshot, policy: AuditPolicy) -> bool:
        """
        Проверяет поддерживаемый scope снимка; при неприменимости движок формирует not_applicable
        без выполнения алгоритма.
        """
        return snapshot.scope in {'bucket_configuration_only', 'bucket_and_selected_objects'}

    def evaluate(self, snapshot: ConfigurationSnapshot, policy: AuditPolicy) -> Finding:
        """
        Положительная unsigned-проба подтверждает доступ; иначе сопоставляет политики/ACL/запреты по
        каждой цели; неполноту не превращает в passed.
        """
        fields = {item.name: item for item in snapshot.observations}
        evidence = []
        outcomes = []
        targets = (None,) if self.operation == 'list' else snapshot.object_keys
        probe_names = ([f'anonymous_read:{key}' for key in targets] if self.operation == 'read'
                       else [f'anonymous_{self.operation}'])
        positive = False
        failed_probe = False
        limitations = ['only_selected_targets_and_supported_policy_subset']
        for name in probe_names:
            item = fields.get(name)
            if item is None:
                continue
            outcome = item.data.get('outcome') if isinstance(item.data, dict) else None
            evidence.append(Evidence(name, item.source, item.status, json.dumps(item.data, sort_keys=True)))
            positive |= outcome == 'allowed'
            failed_probe |= outcome not in {'allowed', 'denied'}
        for key in targets:
            resource = f'arn:aws:s3:::{snapshot.resource.id}' + (f'/{key}' if key is not None else '')
            decision = policy_decision(fields.get('bucket_policy'), ACTIONS[self.operation], resource)
            if decision.unknown:
                limitations.append('policy_data_or_conditions_not_resolved')
            acl_name = f'object_acl:{key}' if self.operation == 'read' else 'bucket_acl'
            permissions = {'READ', 'FULL_CONTROL'} if self.operation in {'read', 'list'} else {'WRITE', 'FULL_CONTROL'}
            acl = acl_allows(fields.get(acl_name), permissions)
            ownership = fields.get('ownership_controls')
            mode = ownership.data.get('object_ownership') if ownership and ownership.status == 'available' else None
            block = fields.get('public_access_block')
            controls = block.data if block and block.status == 'available' else {}
            if mode == 'BucketOwnerEnforced' or controls.get('ignore_public_acls') is True:
                acl = False
            elif mode not in {'BucketOwnerPreferred', 'ObjectWriter'} and acl is True:
                acl = None
            for name in ('bucket_policy', acl_name, 'ownership_controls', 'public_access_block'):
                item = fields.get(name)
                if item:
                    evidence.append(Evidence(name, item.source, item.status,
                        json.dumps(item.data, sort_keys=True) if item.data is not None else None))
            if decision.deny:
                outcomes.append('denied')
            elif decision.allow or acl is True:
                outcomes.append('uncertain_allow' if decision.unknown else 'allowed_by_configuration')
            elif decision.unknown or acl is None:
                outcomes.append('unknown')
            else:
                outcomes.append('denied')
        if positive:
            status = 'confirmed_violation'
            explanation = 'An unsigned request succeeded for the recorded operation and target; runtime evidence overrides configuration assumptions.'
        elif any(value in {'allowed_by_configuration', 'uncertain_allow'} for value in outcomes):
            status = 'potential_risk'
            explanation = ('Anonymous permission or unresolved restrictions found in configuration. '
                           'Public reachability is not confirmed; controls, conditions or probe results may restrict access.')
        elif not outcomes or 'unknown' in outcomes or failed_probe:
            status = 'insufficient_data'
            explanation = 'Anonymous access cannot be resolved for the selected scope; no conclusion of safety is made.'
        else:
            status = 'passed'
            explanation = ('No anonymous permission found in the supported configuration subset for the selected targets. '
                           'This does not establish safety for unselected objects, versions, or other request contexts.')
        if not evidence:
            evidence.append(Evidence('selected_object_keys', 'scope', 'missing', None))
        if not any(name in fields for name in probe_names):
            limitations.append('anonymous_requests_not_performed')
        if self.operation in {'write', 'delete'} and any(name in fields for name in probe_names):
            limitations.append('mutation_probes_use_generated_objects_only')
        # Deduplicate repeated bucket-level evidence across selected objects.
        evidence = tuple(dict.fromkeys(evidence))
        risk = RiskModel().assess(status, policy.data_sensitivity, (self.operation,),
                                  'public_confirmed' if positive else 'unknown')
        return Finding(self.id, status, explanation, evidence, risk, self.recommendation, self.verification,
                       limitations=tuple(dict.fromkeys(limitations)))
