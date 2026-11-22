"""Проверяет состояние версионирования и сопоставляет его с обязательностью контроля восстановления."""
from cloud_audit.rules.risk import RiskModel
from cloud_audit.models.security import AuditPolicy, Evidence, Finding
from cloud_audit.models.snapshot import ConfigurationSnapshot


class VersioningRule:
    """
    Проверка включённого версионирования, не гарантия резервного копирования или отсутствия
    публичного доступа.
    """
    id = 'bucket-versioning-enabled'
    required_data = ('versioning',)
    recommendation = ('In VK Cloud, open the training bucket settings and enable versioning '
                      'if required by the recovery policy. Review retention and storage costs; '
                      'existing lost versions cannot be recovered by enabling versioning later.')
    verification = ('Collect a new snapshot and confirm GetBucketVersioning Status=Enabled; '
                    'repeat this rule. Test recovery separately on artificial objects.')

    def applicable(self, snapshot: ConfigurationSnapshot, policy: AuditPolicy) -> bool:
        """
        Проверяет поддерживаемый scope снимка; при неприменимости движок формирует not_applicable
        без выполнения алгоритма.
        """
        return snapshot.scope in {'bucket_configuration_only', 'bucket_and_selected_objects'}

    def evaluate(self, snapshot: ConfigurationSnapshot, policy: AuditPolicy) -> Finding:
        """
        Enabled даёт passed; Disabled/Suspended — нарушение обязательного versioning либо
        potential_risk; неизвестное значение — insufficient_data.
        """
        observation = next(item for item in snapshot.observations if item.name == 'versioning')
        value = observation.data.get('status') if isinstance(observation.data, dict) else None
        if not isinstance(value, str) or value not in {'Enabled', 'Disabled', 'Suspended'}:
            status = 'insufficient_data'
            explanation = 'Versioning response does not contain a recognized state'
            value = None
        elif value == 'Enabled':
            status = 'passed'
            explanation = 'Bucket versioning is enabled; this does not establish complete recoverability'
        else:
            status = 'confirmed_violation' if 'versioning' in policy.required_controls else 'potential_risk'
            explanation = (f'Bucket versioning is {value}; new writes do not preserve a new version. '
                           'This is a configuration finding, not evidence of actual data loss.')
        return Finding(self.id, status, explanation,
                       (Evidence('versioning.status', observation.source, observation.status, value),),
                       RiskModel().assess(status, policy.data_sensitivity, ('overwrite', 'delete')),
                       self.recommendation, self.verification)
