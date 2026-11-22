"""Правила внешних субъектов, превышения заданной модели необходимых прав и отключения ACL."""
from cloud_audit.rules.access_grants import inventory, project_id, subject_covers
from cloud_audit.rules.risk import RiskModel
from cloud_audit.models.security import Evidence, Finding


BASE_LIMITS = ('only_explicit_grants_in_selected_scope', 'implicit_internal_permissions_not_evaluated',
               'conditions_and_unmapped_actions_not_evaluated', 'grants_are_not_runtime_access_confirmation')


def result(rule, snapshot, policy, status, explanation, evidence, operations=(), limitations=()):
    """
    Собирает Finding правила управления доступом, общие ограничения, риск и уникальные операции;
    обеспечивает минимальное доказательство.
    """
    if not evidence:
        evidence = (Evidence('configuration', 'scope', 'missing', None),)
    base = BASE_LIMITS if rule.id != 'bucket-acl-disabled' else ()
    return Finding(rule.id, status, explanation, tuple(evidence),
        RiskModel().assess(status, policy.data_sensitivity, tuple(sorted(set(operations)))),
        rule.recommendation, rule.verification, limitations=tuple(dict.fromkeys((*base, *limitations))))


class GovernanceRule:
    """Общая проверка применимости правил управления доступом к поддерживаемому охвату."""
    required_data = ()
    def applicable(self, snapshot, policy):
        """
        Проверяет поддерживаемый scope снимка; при неприменимости движок формирует not_applicable
        без выполнения алгоритма.
        """
        return snapshot.scope in {'bucket_configuration_only', 'bucket_and_selected_objects'}


class ExternalAccessRule(GovernanceRule):
    """Выявляет явные гранты неутверждённым внешним субъектам, с учётом доверия и запретов."""
    id = 'unapproved-external-access'
    recommendation = ('In VK Cloud review the named principals in the bucket policy and the bucket/object ACLs. '
                      'Remove unintended grants or document specific approved project/account identifiers; '
                      'do not remove the owner or required application access without checking dependencies.')
    verification = ('Collect fresh settings, supply trusted_project_ids and allowed_external_accounts, '
                    'and rerun this rule. Validate actual access separately with the affected subject.')

    def evaluate(self, snapshot, policy):
        """
        Исключает анонимные/доверенные/разрешённые и запрещённые гранты; внешние явные права дают
        potential_risk, недостающий контекст — insufficient_data.
        """
        data = inventory(snapshot)
        unknown = list(data.unknown)
        unexpected = []
        operations = []
        for row in data.grants:
            if row.subject == '*' or data.denied(row):
                continue
            project = project_id(row.subject)
            if (row.subject == data.owner_id or row.subject in policy.trusted_project_ids
                    or project in policy.trusted_project_ids):
                continue
            if row.subject in policy.allowed_external_accounts or project in policy.allowed_external_accounts:
                continue
            if row.source == 'get_bucket_policy' and not policy.trusted_project_ids:
                unknown.append('trusted_project_context_missing')
                continue
            unexpected.append(row.subject)
            operations.append(row.operation)
        if unexpected:
            status, explanation = 'potential_risk', 'Unapproved explicit grants found for: ' + ', '.join(sorted(set(unexpected)))
        elif unknown:
            status, explanation = 'insufficient_data', 'External access cannot be fully classified in the selected scope'
        else:
            status, explanation = 'passed', 'No unapproved named external grants found in the supported selected scope'
        return result(self, snapshot, policy, status, explanation, data.evidence, operations, unknown)


class ExcessPermissionsRule(GovernanceRule):
    """Сравнивает наблюдаемые явные операции с пользовательской baseline; не выводит её из текущих прав."""
    id = 'excess-explicit-permissions'
    recommendation = ('In VK Cloud narrow policy Action/Resource and ACL permissions to the required_permissions '
                      'baseline for each subject. Bucket WRITE also grants deletion; FULL_CONTROL includes ACL changes. '
                      'Confirm application requirements before removing access.')
    verification = ('Record required operations for each exact subject, collect fresh policy/ACL data and rerun. '
                    'Check required application actions separately; this rule does not test missing necessary access.')

    def evaluate(self, snapshot, policy):
        """
        Для заданных субъектов сравнивает явные операции с required_permissions; превышение даёт
        risk, неполнота не позволяет заявить least privilege.
        """
        data = inventory(snapshot)
        unknown = list(data.unknown)
        excess = []
        operations = []
        if not policy.required_permissions:
            unknown.append('required_permissions_baseline_missing')
        for requirement in policy.required_permissions:
            if not any(subject_covers(row.subject, requirement.subject) for row in (*data.grants, *data.denies)):
                unknown.append('configured_subject_not_observed')
            if project_id(requirement.subject) is not None and not policy.trusted_project_ids:
                unknown.append('trusted_project_context_missing')
            if requirement.subject == data.owner_id or project_id(requirement.subject) in policy.trusted_project_ids or requirement.subject in policy.trusted_project_ids:
                unknown.append('implicit_internal_permissions_not_evaluated')
            for row in data.for_subject(requirement.subject):
                if row.operation not in requirement.operations:
                    excess.append(f'{requirement.subject}: {row.operation} on {row.resource}')
                    operations.append(row.operation)
        if excess:
            status, explanation = 'potential_risk', 'Explicit permissions exceed the baseline: ' + '; '.join(sorted(set(excess)))
        elif unknown:
            status, explanation = 'insufficient_data', 'Least privilege cannot be established for the supplied subjects and scope'
        else:
            status, explanation = 'passed', 'No excessive explicit permissions found for the configured subjects in this scope'
        return result(self, snapshot, policy, status, explanation, data.evidence, operations, unknown)


class AclDisabledRule(GovernanceRule):
    """Проверяет BucketOwnerEnforced и учитывает обязательность отключения ACL в политике аудита."""
    id = 'bucket-acl-disabled'
    required_data = ('ownership_controls',)
    recommendation = ('In VK Cloud review applications that depend on ACLs, migrate required permissions to bucket '
                      'policies, then disable ACLs (BucketOwnerEnforced). This reduces accidental ACL publication '
                      'but does not prevent public access through policies.')
    verification = ('Collect fresh Ownership Controls and confirm BucketOwnerEnforced; rerun anonymous access rules '
                    'and application access checks after the migration.')

    def evaluate(self, snapshot, policy):
        """
        Сопоставляет Ownership Controls и required_controls: Enforced passed, Preferred/Writer risk
        или нарушение baseline, неизвестное insufficient_data.
        """
        item = next(x for x in snapshot.observations if x.name == 'ownership_controls')
        value = item.data.get('object_ownership') if isinstance(item.data, dict) else None
        if not isinstance(value, str):
            value = None
        if value == 'BucketOwnerEnforced':
            status, explanation = 'passed', 'ACLs are disabled; public policies remain a separate risk'
        elif value in ('BucketOwnerPreferred', 'ObjectWriter'):
            status = 'confirmed_violation' if 'acl_disabled' in policy.required_controls else 'potential_risk'
            explanation = 'ACLs can grant access, including accidental publication; this does not prove a current public grant'
        else:
            status, explanation = 'insufficient_data', 'Ownership Controls state is unknown'
        return result(self, snapshot, policy, status, explanation,
                      (Evidence('ownership_controls.object_ownership', item.source, item.status, value),),
                      ('write_acl',), ('public_policies_remain_possible', 'application_acl_compatibility_not_tested'))
