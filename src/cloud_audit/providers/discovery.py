"""Постраничный список объектов с пределами объёма и запросов; ошибка не становится пустым успехом."""
from datetime import datetime, timezone
from botocore.exceptions import BotoCoreError, ClientError
from botocore.parsers import ResponseParserError

from cloud_audit.models.scanning import ObjectDiscovery, ProbeResult


class ObjectEnumerator:
    """Использует переданный signed/unsigned клиент; возвращает охват и факт самого List-запроса."""
    def __init__(self, client, source):
        """Фиксирует клиент и вид авторизации для доказательств."""
        self.client, self.source = client, source

    def list(self, bucket, limit):
        """Читает до limit уникальных ключей и максимум 20 страниц, обнаруживая неверные токены/ответы."""
        keys, tokens, token, code, allowed = [], set(), None, None, False
        status, error, outcome = 'complete', None, 'error'
        unseen = False
        try:
            if type(limit) is not int or not 1 <= limit <= 20:
                raise ValueError
            for _ in range(20):
                page = self.client.list_objects_v2(Bucket=bucket, MaxKeys=limit-len(keys), **({'ContinuationToken': token} if token else {}))
                code = page.get('ResponseMetadata', {}).get('HTTPStatusCode')
                if type(code) is not int or not 200 <= code < 300:
                    raise ValueError
                allowed, outcome = True, 'allowed'
                contents = page.get('Contents', [])
                if not isinstance(contents, list) or type(page.get('IsTruncated', False)) is not bool:
                    raise ValueError
                for item in contents:
                    key = item['Key']
                    if not isinstance(key, str) or not key or len(key.encode('utf-8')) > 1024:
                        raise ValueError
                    if key not in keys:
                        if len(keys) < limit:
                            keys.append(key)
                        else:
                            unseen = True
                if not page.get('IsTruncated', False):
                    if unseen:
                        status = 'limited'
                    break
                if len(keys) == limit:
                    status = 'limited'
                    break
                token = page.get('NextContinuationToken')
                if not isinstance(token, str) or not token or token in tokens:
                    raise ValueError
                tokens.add(token)
            else:
                status, error = 'limited', 'page_limit_reached'
        except ClientError as exc:
            code = exc.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
            raw = exc.response.get('Error', {}).get('Code')
            denied = code == 403 and raw in {'AccessDenied', '403'}
            error = 'access_denied' if denied else 'resource_not_found' if raw == 'NoSuchBucket' else 'request_failed'
            status, outcome = 'failed', 'allowed' if allowed else 'denied' if denied else 'error'
            if allowed:
                code = 200
        except (BotoCoreError, ResponseParserError, OSError, ValueError, KeyError, TypeError, AttributeError):
            status, error, outcome = 'failed', 'invalid_response_or_network', 'allowed' if allowed else 'error'
            if allowed:
                code = 200
        proof = ProbeResult('list', None, outcome, code if type(code) is int and 100 <= code < 600 else None,
                            datetime.now(timezone.utc).isoformat())
        return ObjectDiscovery(tuple(keys), status, self.source, limit, error), proof
