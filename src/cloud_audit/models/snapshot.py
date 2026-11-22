"""Факты конфигурации до оценки безопасности: выбранный охват, наблюдения, параметры проб и полнота сбора."""
from dataclasses import dataclass

from cloud_audit.models.resources import Resource


CONFIGURATION_FIELDS = frozenset({
    'bucket_acl', 'bucket_policy', 'public_access_block', 'ownership_controls',
    'versioning', 'logging', 'encryption', 'object_lock',
})
OBSERVATION_STATUSES = frozenset({'available', 'absent', 'access_denied', 'unsupported', 'error', 'not_found'})
LIMITATIONS = ('object_acl_not_collected', 'object_contents_not_collected',
               'account_controls_not_collected', 'security_not_assessed',
               'sequential_requests_not_atomic')


@dataclass(frozen=True)
class CollectionOptions:
    """Охват до 20 уникальных объектов и явные разрешения на unsigned и мутационные пробы."""
    object_keys: tuple[str, ...] = ()
    probe_anonymous: bool = False
    allow_write_probes: bool = False

    def __post_init__(self):
        """
        Проверяет максимум 20 уникальных непустых ключей до 1024 байт и зависимость write-проб от
        probe_anonymous.
        """
        if (len(self.object_keys) > 20 or len(set(self.object_keys)) != len(self.object_keys)
                or any(not isinstance(key, str) or not key or len(key.encode('utf-8')) > 1024
                       for key in self.object_keys)
                or self.allow_write_probes and not self.probe_anonymous):
            raise ValueError('Invalid object scope or probe options')


def collection_limitations(keys: tuple[str, ...]):
    """
    Формирует ограничения выбранного охвата, отсутствия содержимого/контролей аккаунта и
    неатомарности сбора.
    """
    return ('only_selected_objects_collected' if keys else 'object_acl_not_collected',
            'object_contents_not_stored', 'account_controls_not_collected',
            'security_not_assessed', 'sequential_requests_not_atomic')


def collection_complete(observations):
    """Возвращает полноту только при available/absent и определённых результатах проб без ошибки уборки."""
    return all(item.status in {'available', 'absent'}
               and (not item.name.startswith('anonymous_') or
                    item.data.get('outcome') in {'allowed', 'denied'} and not item.data.get('cleanup_failed'))
               for item in observations)


@dataclass(frozen=True)
class ConfigurationObservation:
    """
    Один факт, полученный из API: источник, статус, нормализованные данные или безопасная причина
    недоступности.
    """
    name: str
    source: str
    status: str
    data: dict | None
    reason: str | None = None


@dataclass(frozen=True)
class ConfigurationSnapshot:
    """Сохранённый вход аудита: ресурс, начало сбора, наблюдения, охват, namespace и ограничения."""
    id: str
    schema_version: int
    provider: str
    resource: Resource
    collected_at: str
    scope: str
    limitations: tuple[str, ...]
    collection_status: str
    observations: tuple[ConfigurationObservation, ...]
    object_keys: tuple[str, ...] = ()
    resource_namespace: str | None = None
