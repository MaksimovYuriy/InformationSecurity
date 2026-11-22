"""Внешний этап: unsigned List/Get и отдельно разрешённые искусственные Write/Delete."""
from dataclasses import replace
from cloud_audit.models.scanning import ExternalResult, ProbeResult
from cloud_audit.providers.anonymous import AnonymousProber
from cloud_audit.providers.discovery import ObjectEnumerator
from cloud_audit.providers.mutations import MutationProber
from datetime import datetime, timezone


class ExternalInspector:
    """Не требует ключей; переданный signed-клиент применяется только для подготовки/уборки мутаций."""
    def __init__(self, anonymous, namespace, signed=None):
        """Сохраняет разделённые клиенты и идентичность endpoint."""
        self.anonymous, self.namespace, self.signed = anonymous, namespace, signed
        self.prober = AnonymousProber(anonymous)

    @classmethod
    def from_settings(cls, settings, signed=None):
        """Использует существующую фабрику UNSIGNED с пустыми credentials, даже если ключи заданы в окружении."""
        prober = AnonymousProber.from_settings(settings)
        return cls(prober._anonymous, settings.endpoint_url.rstrip('/').lower(), signed)

    def inspect(self, target, limit):
        """Сначала List/Get, затем только явно разрешённые мутации выбранного бакета."""
        discovery, listing = ObjectEnumerator(self.anonymous, 'anonymous').list(target.name, limit)
        combined = tuple(dict.fromkeys((*target.object_keys, *discovery.keys)))
        keys = combined[:limit]
        if len(combined) > limit:
            discovery = replace(discovery, status='limited', error_code='combined_scope_limit')
        probes = (listing, *self.read_objects(target.name, keys))
        if target.allow_mutations:
            probes += MutationProber(self.anonymous, self.signed).run(target.name, allow_residue=target.allow_residue)
        else:
            probes += tuple(ProbeResult(op, None, 'not_tested', None, datetime.now(timezone.utc).isoformat(), reason='mutation_not_enabled') for op in ('write', 'delete'))
        return ExternalResult(probes, discovery)

    def read_objects(self, bucket, keys):
        """GET Range bytes=0-0 каждого выбранного ключа, без повторного List или мутаций."""
        results = []
        for key in keys:
            fact = self.prober._probe('anonymous_read:' + key, 'anonymous_get_object',
                lambda key=key: self.anonymous.get_object(Bucket=bucket, Key=key, Range='bytes=0-0'), key)
            code = fact.data['http_status']
            results.append(ProbeResult('read', key, fact.data['outcome'], code if type(code) is int and 100 <= code < 600 else None, fact.data['checked_at']))
        return tuple(results)
