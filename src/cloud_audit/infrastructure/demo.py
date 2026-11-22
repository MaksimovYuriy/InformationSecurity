from cloud_audit.application.audit import AuditError
from cloud_audit.domain.audit import Resource, RuleResult


class DemoProvider:
    """Fixed fixtures, not a security rule engine or a cloud connection."""
    mode = 'demo'
    audit_available = True
    connection_message = 'Simulated connection; no cloud contacted'

    def connect(self) -> None:
        pass

    def resources(self) -> tuple[Resource, ...]:
        return (Resource('demo-public', 'Demo public bucket'),
                Resource('demo-private', 'Demo private bucket'))

    def preview(self, resource: Resource, rules: tuple[str, ...]) -> tuple[RuleResult, ...]:
        selected = rules or ('demo-public-read',)
        if any(rule != 'demo-public-read' for rule in selected):
            raise AuditError('Unknown demo rule; available: demo-public-read')
        return tuple(RuleResult(rule, 'simulated',
                               'Fixture: public read' if resource.id == 'demo-public'
                               else 'Fixture: private resource') for rule in dict.fromkeys(selected))
