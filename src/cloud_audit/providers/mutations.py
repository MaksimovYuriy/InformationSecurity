"""Изолированные unsigned PUT/DELETE с отдельными signed-подготовкой, подтверждением и уборкой."""
from dataclasses import replace
from datetime import datetime, timezone
from uuid import uuid4

from botocore.exceptions import BotoCoreError, ClientError
from botocore.parsers import ResponseParserError
from cloud_audit.models.scanning import ProbeResult

ERRORS = (BotoCoreError, ClientError, ResponseParserError, OSError, ValueError, TypeError, KeyError, AttributeError)


class MutationProber:
    """Работает только со своими случайными ключами; неподтверждённый эффект не становится allowed."""
    def __init__(self, anonymous, signed=None):
        """Разделяет клиента проверочных запросов и клиента подготовки/уборки."""
        self.anonymous, self.signed = anonymous, signed
        self.versioning_status = None

    def run(self, bucket, *, allow_residue=False):
        """Проверяет две независимые цели; без ключей требует согласия на возможные неудалённые файлы."""
        if self.signed is None and not allow_residue:
            raise ValueError('Unsigned mutations require residue acceptance')
        prefix = '_cloud-audit-probe/' + uuid4().hex + '/'
        if self.signed is not None and not self._ready(bucket):
            return tuple(self._result(op, prefix + op + '.txt', 'not_tested', reason='cleanup_preconditions_unavailable') for op in ('write', 'delete'))
        return tuple(self._one(bucket, prefix + op + '.txt', op) for op in ('write', 'delete'))

    def _ready(self, bucket):
        """Мутации с ключами требуют известного состояния версионирования и подтверждённого отсутствия Object Lock."""
        try:
            version = self.signed.get_bucket_versioning(Bucket=bucket)
            self.versioning_status = version.get('Status', 'Disabled')
            if self.versioning_status not in {'Enabled', 'Suspended', 'Disabled'}:
                return False
        except ERRORS:
            return False
        try:
            self.signed.get_object_lock_configuration(Bucket=bucket)
        except ClientError as exc:
            return exc.response.get('Error', {}).get('Code') == 'ObjectLockConfigurationNotFoundError'
        except ERRORS:
            return False
        return False

    def _result(self, operation, key, outcome, code=None, **kwargs):
        """Создаёт приватное по составу доказательство без исходных сообщений SDK."""
        return ProbeResult(operation, key, outcome, code, datetime.now(timezone.utc).isoformat(), **kwargs)

    def _request(self, operation, key, call):
        """Выполняет только проверочный unsigned-запрос и классифицирует HTTP-ответ; возвращает также метаданные для уборки."""
        try:
            response = call()
            code = response.get('ResponseMetadata', {}).get('HTTPStatusCode')
            result = self._result(operation, key, 'allowed' if type(code) is int and 200 <= code < 300 else 'error',
                                  code if type(code) is int and 100 <= code < 600 else None)
            return result, response
        except ClientError as exc:
            code = exc.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
            denied = code == 403 and exc.response.get('Error', {}).get('Code') in {'AccessDenied', '403'}
            return self._result(operation, key, 'denied' if denied else 'error', code if type(code) is int and 100 <= code < 600 else None), {}
        except ERRORS:
            return self._result(operation, key, 'error', reason='unsigned_request_failed'), {}

    def _one(self, bucket, key, operation):
        """Проверяет отсутствие старых версий, готовит собственную цель и подтверждает удаление до уборки."""
        client = self.signed or self.anonymous
        token = uuid4().hex
        created, marker_ids, attempted = False, set(), False
        result = self._result(operation, key, 'not_tested', reason='target_preparation_failed')
        try:
            if self.signed is not None:
                initial = self.signed.list_object_versions(Bucket=bucket, Prefix=key, MaxKeys=100)
                if initial.get('IsTruncated') or any(row.get('Key') == key for row in (*initial.get('Versions', []), *initial.get('DeleteMarkers', []))):
                    return self._result(operation, key, 'not_tested', reason='target_not_empty_or_enumeration_incomplete')
            if operation == 'delete':
                attempted = True
                prepared = client.put_object(Bucket=bucket, Key=key, Body=b'cloud-audit artificial delete target\n',
                                             Metadata={'cloud-audit-probe': token}, IfNoneMatch='*')
                code = prepared.get('ResponseMetadata', {}).get('HTTPStatusCode')
                if type(code) is not int or not 200 <= code < 300:
                    raise ValueError
                created = True
                # A denied HEAD means the effect cannot be independently established, even after a 204 DELETE.
                present = self._present(client, bucket, key) is True
                attempted = True
                result, response = self._request(operation, key, lambda: self.anonymous.delete_object(Bucket=bucket, Key=key))
                if response.get('VersionId'):
                    marker_ids.add(response['VersionId'])
                if result.outcome == 'allowed':
                    absent = self._present(client, bucket, key) is False
                    result = replace(result, outcome='allowed' if present and absent else 'unverified',
                                     verification='current_object_absent' if present and absent else 'delete_effect_not_verified')
            else:
                attempted = True
                result, response = self._request(operation, key, lambda: self.anonymous.put_object(Bucket=bucket, Key=key,
                    Body=b'cloud-audit artificial write target\n', Metadata={'cloud-audit-probe': token}, IfNoneMatch='*'))
                created = result.outcome == 'allowed'
                if created:
                    result = replace(result, verification='unsigned_put_accepted')
        except ERRORS:
            result = self._result(operation, key, 'not_tested' if not attempted else 'error', reason='preparation_or_verification_failed')
        finally:
            cleanup = self._cleanup(bucket, key, token, marker_ids, created, attempted)
        return replace(result, preparation='authenticated' if operation == 'delete' and self.signed else 'anonymous' if operation == 'delete' else 'none', cleanup=cleanup)

    def _present(self, client, bucket, key):
        """Возвращает True при HEAD 2xx, False только при точном 404 объекта, иначе неизвестность."""
        try:
            code = client.head_object(Bucket=bucket, Key=key).get('ResponseMetadata', {}).get('HTTPStatusCode')
            return True if type(code) is int and 200 <= code < 300 else None
        except ClientError as exc:
            code = exc.response.get('Error', {}).get('Code')
            return False if code in {'NoSuchKey', '404', 'NotFound'} and exc.response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 404 else None
        except ERRORS:
            return None

    def _cleanup(self, bucket, key, token, marker_ids, created, attempted):
        """Удаляет только версии с меткой нашей пробы и известные маркеры; неизвестный остаток явно сохраняется в отчёте."""
        if not created and not attempted:
            return 'not_needed'
        if self.signed is None:
            try:
                if created:
                    self.anonymous.delete_object(Bucket=bucket, Key=key)
            except ERRORS:
                pass
            # Without signed version enumeration, even a successful DELETE does not prove complete cleanup.
            return 'residue' if created else 'unknown'
        try:
            page = self.signed.list_object_versions(Bucket=bucket, Prefix=key, MaxKeys=100)
            if page.get('IsTruncated'):
                return 'unknown'
            unknown = False
            for row in page.get('Versions', []):
                if row.get('Key') != key:
                    continue
                current = self.versioning_status == 'Disabled' and row['VersionId'] == 'null' and row.get('IsLatest') is True
                version_args = {} if current else {'VersionId': row['VersionId']}
                head = self.signed.head_object(Bucket=bucket, Key=key, **version_args)
                if {name.lower(): value for name, value in head.get('Metadata', {}).items()}.get('cloud-audit-probe') == token:
                    self.signed.delete_object(Bucket=bucket, Key=key, **version_args)
                else:
                    unknown = True
            for row in page.get('DeleteMarkers', []):
                if row.get('Key') == key:
                    if row.get('VersionId') in marker_ids:
                        self.signed.delete_object(Bucket=bucket, Key=key, VersionId=row['VersionId'])
                    else:
                        unknown = True
            remaining = self.signed.list_object_versions(Bucket=bucket, Prefix=key, MaxKeys=100)
            if remaining.get('IsTruncated') or any(row.get('Key') == key for row in (*remaining.get('Versions', []), *remaining.get('DeleteMarkers', []))):
                unknown = True
            if created and self._present(self.signed, bucket, key) is not False:
                unknown = True
            return 'unknown' if unknown else 'cleaned'
        except ERRORS:
            return 'unknown'
