"""
Отдельный unsigned-клиент для ограниченных проб; запись/удаление разрешены только на новых
искусственных ключах с уборкой.
"""
from datetime import datetime, timezone
import logging
from uuid import uuid4

import boto3
from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from botocore.parsers import ResponseParserError

from cloud_audit.models.snapshot import ConfigurationObservation


class AnonymousProber:
    """Выполняет независимые анонимные запросы и изолированные мутационные пробы с очисткой."""
    def __init__(self, anonymous_client, fixture_client=None):
        """
        Сохраняет переданные зависимости и параметры экземпляра; конкретные внешние действия
        выполняются отдельными методами.
        """
        self._anonymous = anonymous_client
        self._fixtures = fixture_client

    @classmethod
    def from_settings(cls, settings, fixture_client=None):
        """
        Создаёт клиента с signature_version=UNSIGNED, пустыми ключами и одной попыткой; ключи
        окружения не используются.
        """
        for name in ('boto3', 'botocore', 's3transfer', 'urllib3'):
            logging.getLogger(name).setLevel(logging.CRITICAL)
        client = boto3.session.Session().client('s3', endpoint_url=settings.endpoint_url,
            region_name=settings.region, aws_access_key_id='', aws_secret_access_key='',
            config=Config(signature_version=UNSIGNED, connect_timeout=5, read_timeout=10,
                          retries={'mode': 'standard', 'total_max_attempts': 1},
                          s3={'addressing_style': 'path'}))
        return cls(client, fixture_client)

    def _probe(self, name, source, operation, key=None):
        """
        Выполняет запрос, ограниченно читает и закрывает Body; сохраняет только outcome, HTTP-код,
        время и ключ.
        """
        status_code = None
        try:
            response = operation()
            status_code = response.get('ResponseMetadata', {}).get('HTTPStatusCode')
            body = response.get('Body')
            if body is not None:
                try:
                    body.read(1)
                finally:
                    body.close()
            outcome = 'allowed' if type(status_code) is int and 200 <= status_code < 300 else 'error'
        except ClientError as error:
            status_code = error.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
            code = error.response.get('Error', {}).get('Code')
            outcome = ('denied' if status_code == 403 and code in {'AccessDenied', '403'} else
                       'not_found' if code in {'NoSuchKey', 'NoSuchBucket', 'NotFound'} else 'error')
        except (ResponseParserError, BotoCoreError, OSError, ValueError, TypeError):
            outcome = 'error'
        data = {'outcome': outcome, 'http_status': status_code,
                'checked_at': datetime.now(timezone.utc).isoformat()}
        if key is not None:
            data['object_key'] = key
        return ConfigurationObservation(name, source, 'available', data)

    def read_only(self, bucket: str, keys: tuple[str, ...]):
        """Проверяет ListObjectsV2 MaxKeys=1 и GET Range bytes=0-0 для каждого выбранного объекта."""
        result = [self._probe('anonymous_list', 'anonymous_list_objects_v2',
            lambda: self._anonymous.list_objects_v2(Bucket=bucket, MaxKeys=1))]
        for key in keys:
            result.append(self._probe(f'anonymous_read:{key}', 'anonymous_get_object',
                lambda key=key: self._anonymous.get_object(Bucket=bucket, Key=key, Range='bytes=0-0'), key))
        return tuple(result)

    def mutations(self, bucket: str, *, enabled: bool = False):
        """
        Проверяет только новые UUID-ключи, предварительно перечисляет версии, выполняет put/delete и
        удаляет точные версии/маркеры; отмечает cleanup_failed.
        """
        if not enabled:
            raise ValueError('Write probes require explicit opt-in')
        if self._fixtures is None:
            raise ValueError('A fixture client is required')
        # Require version enumeration before creating anything; cleanup must include delete markers.
        prefix = f'_cloud-audit-probe/{uuid4().hex}/'
        results = []
        for operation in ('write', 'delete'):
            key = prefix + operation + '.txt'
            outcome = None
            cleanup_ok = True
            attempted = False
            try:
                initial = self._fixtures.list_object_versions(Bucket=bucket, Prefix=key, MaxKeys=100)
                if initial.get('IsTruncated') or any(row.get('Key') == key for row in
                        (*initial.get('Versions', []), *initial.get('DeleteMarkers', []))):
                    raise ValueError('Probe target is not empty')
                attempted = True
                if operation == 'delete':
                    self._fixtures.put_object(Bucket=bucket, Key=key, Body=b'cloud-audit disposable probe\n', IfNoneMatch='*')
                    call = lambda: self._anonymous.delete_object(Bucket=bucket, Key=key)
                else:
                    call = lambda: self._anonymous.put_object(Bucket=bucket, Key=key,
                        Body=b'cloud-audit disposable probe\n', IfNoneMatch='*')
                outcome = self._probe(f'anonymous_{operation}', f'anonymous_{"put" if operation == "write" else "delete"}_object', call, key)
            except (ResponseParserError, BotoCoreError, ClientError, OSError, ValueError, TypeError):
                outcome = ConfigurationObservation(f'anonymous_{operation}',
                    f'anonymous_{"put" if operation == "write" else "delete"}_object', 'available',
                    {'outcome': 'error', 'http_status': None, 'object_key': key,
                     'checked_at': datetime.now(timezone.utc).isoformat()})
            finally:
                try:
                    page = (self._fixtures.list_object_versions(Bucket=bucket, Prefix=key, MaxKeys=100)
                            if attempted else {})
                    if page.get('IsTruncated'):
                        raise ValueError('Cleanup enumeration incomplete')
                    for version in (*page.get('Versions', []), *page.get('DeleteMarkers', [])):
                        if version.get('Key') == key:
                            self._fixtures.delete_object(Bucket=bucket, Key=key, VersionId=version['VersionId'])
                except (ResponseParserError, BotoCoreError, ClientError, OSError, ValueError, KeyError, TypeError):
                    cleanup_ok = False
            if not cleanup_ok:
                # Keep successful access evidence, but explicitly report cleanup failure.
                outcome.data['cleanup_failed'] = True
            results.append(outcome)
        return tuple(results)
