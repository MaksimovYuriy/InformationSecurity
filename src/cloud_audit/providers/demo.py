"""
Фиксированный демонстрационный профиль без сети; результаты всегда simulated и не являются оценкой
безопасности.
"""
from cloud_audit.errors import AuditError
from cloud_audit.models.resources import Resource, RuleResult


class DemoProvider:
    """Fixed fixtures, not a security rule engine or a cloud connection."""
    mode = 'demo'
    connection_message = 'Simulated connection; no cloud contacted'

    def connect(self) -> None:
        """Демонстрационная операция без сетевых запросов и изменения состояния."""
        pass

    def resources(self) -> tuple[Resource, ...]:
        """Возвращает два фиксированных ресурса demo-public/demo-private."""
        return (Resource('demo-public', 'Demo public bucket'),
                Resource('demo-private', 'Demo private bucket'))

    def preview(self, resource: Resource, rules: tuple[str, ...]) -> tuple[RuleResult, ...]:
        """
        Разрешает только demo-public-read и возвращает simulated с описанием фикстуры; неизвестные
        ID отклоняет.
        """
        selected = rules or ('demo-public-read',)
        if any(rule != 'demo-public-read' for rule in selected):
            raise AuditError('Unknown demo rule; available: demo-public-read')
        return tuple(RuleResult(rule, 'simulated',
                               'Fixture: public read' if resource.id == 'demo-public'
                               else 'Fixture: private resource') for rule in dict.fromkeys(selected))
