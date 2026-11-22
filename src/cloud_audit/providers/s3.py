"""Подписанный S3-адаптер: подключение, список бакетов, сбор настроек и включаемые явно анонимные пробы."""
import logging

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from botocore.parsers import ResponseParserError

from cloud_audit.errors import AuditError
from cloud_audit.models.resources import Resource
from cloud_audit.models.snapshot import ConfigurationObservation, CollectionOptions
from cloud_audit.models.settings import S3Settings


class S3Provider:
    """Облачный профиль vk с подписанным клиентом, namespace и отдельным адаптером unsigned-проб."""
    mode = 'vk'
    connection_message = 'Authenticated bucket listing succeeded; security not assessed'

    def __init__(self, client, anonymous_prober=None, namespace=None):
        """
        Сохраняет переданные зависимости и параметры экземпляра; конкретные внешние действия
        выполняются отдельными методами.
        """
        self._client = client
        self._anonymous_prober = anonymous_prober
        self.namespace = namespace

    @classmethod
    def from_settings(cls, settings: S3Settings):
        # SDK DEBUG logs contain signed request headers and must never be emitted.
        """
        Создаёт подписанный path-style boto3-клиент с тайм-аутами 5/10 с, тремя попытками и
        отдельный unsigned-клиент; подавляет SDK DEBUG.
        """
        for name in ('boto3', 'botocore', 's3transfer', 'urllib3'):
            logging.getLogger(name).setLevel(logging.CRITICAL)
        client = boto3.session.Session().client(
            's3', endpoint_url=settings.endpoint_url, region_name=settings.region,
            aws_access_key_id=settings.access_key, aws_secret_access_key=settings.secret_key,
            config=Config(signature_version='s3v4', connect_timeout=5, read_timeout=10,
                          retries={'mode': 'standard', 'total_max_attempts': 3},
                          s3={'addressing_style': 'path'}))
        from cloud_audit.providers.anonymous import AnonymousProber
        return cls(client, AnonymousProber.from_settings(settings, client), settings.endpoint_url.rstrip('/').lower())

    def connect(self) -> None:
        """Проверяет авторизованное перечисление бакетов через resources; это не оценка их безопасности."""
        self.resources()

    def resources(self) -> tuple[Resource, ...]:
        """
        Обходит страницы ListBuckets, удаляет дубликаты, обнаруживает зацикливание; ошибки SDK
        преобразует в безопасный AuditError.
        """
        resources = {}
        token = None
        seen = set()
        try:
            while True:
                page = self._client.list_buckets(**({'ContinuationToken': token} if token else {}))
                buckets = page['Buckets']
                if not isinstance(buckets, list):
                    raise ValueError
                for bucket in buckets:
                    name = bucket['Name']
                    if not isinstance(name, str) or not name:
                        raise ValueError
                    resources[name] = Resource(name, name)
                token = page.get('ContinuationToken')
                if not token:
                    break
                if not isinstance(token, str) or token in seen:
                    raise ValueError
                seen.add(token)
        except ClientError as error:
            code = error.response.get('Error', {}).get('Code', '')
            if code in {'AccessDenied', '403', 'AllAccessDisabled'}:
                message = 'Cloud access denied; bucket listing permission required'
            elif code in {'InvalidAccessKeyId', 'SignatureDoesNotMatch', 'ExpiredToken', 'InvalidToken'}:
                message = 'Cloud credentials rejected'
            elif code in {'NoSuchBucket', 'NotFound', '404'}:
                message = 'Cloud resource not found'
            elif code in {'SlowDown', 'Throttling', 'ThrottlingException', 'TooManyRequests', '429'}:
                message = 'Cloud API rate limit exceeded; retry later'
            else:
                message = 'Cloud service request failed'
            raise AuditError(message) from None
        except (BotoCoreError, ResponseParserError):
            raise AuditError('Cloud SDK or network error; check connectivity and endpoint') from None
        except (KeyError, TypeError, ValueError):
            raise AuditError('Invalid cloud response or pagination') from None
        return tuple(resources.values())

    def collect(self, resource: Resource, options: CollectionOptions | None = None) -> tuple[ConfigurationObservation, ...]:
        """
        Собирает настройки и при явных флагах пробы; мутации требуют подтверждённого отсутствия
        Object Lock.
        """
        from cloud_audit.providers.collection import S3ConfigurationCollector
        result = S3ConfigurationCollector(self._client).collect(resource, options)
        if options and options.probe_anonymous:
            if self._anonymous_prober is None:
                raise AuditError('Anonymous probe adapter is not configured')
            if options.allow_write_probes:
                lock = next(x for x in result if x.name == 'object_lock')
                if lock.status != 'absent':
                    raise AuditError('Write probes require confirmed absence of Object Lock for cleanup')
            result += self._anonymous_prober.read_only(resource.id, options.object_keys)
            if options.allow_write_probes:
                result += self._anonymous_prober.mutations(resource.id, enabled=True)
        return result

    def discover_objects(self, bucket, limit):
        """Перечисляет ограниченные ключи подписанным клиентом; не читает содержимое объектов."""
        from cloud_audit.providers.discovery import ObjectEnumerator
        return ObjectEnumerator(self._client, 'authenticated').list(bucket, limit)[0]
