"""Isolated VK Cloud read/list fixture. Creates only artificial data; always attempts cleanup."""
import argparse
import json
import os
from pathlib import Path
from uuid import uuid4
from time import sleep

from botocore.exceptions import ClientError, BotoCoreError
from botocore.parsers import ResponseParserError
from cloud_audit.rules.registry import default_rules
from cloud_audit.rules.engine import RuleEngine
from cloud_audit.services.audit import SecurityAuditService
from cloud_audit.services.snapshots import SnapshotService
from cloud_audit.models.security import AuditPolicy
from cloud_audit.models.snapshot import CollectionOptions
from cloud_audit.configuration.environment import load_s3_settings
from cloud_audit.configuration.dotenv import load_environment
from cloud_audit.providers.s3 import S3Provider
from cloud_audit.storage.snapshots import JsonSnapshotRepository
from cloud_audit.storage.json_reports import JsonReportRepository
from cloud_audit.storage.sqlite import SqliteReportRepository
from cloud_audit.storage.state import LocalStateStorage


def main():
    """Создаёт только новый искусственный стенд, проверяет private/public/private и всегда пытается удалить созданные ресурсы; возвращает 0 либо 2."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-training-fixture', action='store_true', required=True,
                        help='Create a temporary bucket and briefly publish only synthetic read/list data')
    parser.parse_args()
    provider = S3Provider.from_settings(load_s3_settings(load_environment(os.environ)))
    client = provider._client
    bucket = f'cloud-audit-lab-{uuid4().hex}'
    key = 'synthetic-read-fixture.txt'
    state = Path('.state')
    LocalStateStorage(state).prepare()
    snapshots = JsonSnapshotRepository(state / 'data' / 'snapshots')
    reports = SqliteReportRepository(state / 'data' / 'audit.sqlite3', legacy=JsonReportRepository(state / 'data'))
    service = SecurityAuditService(RuleEngine(default_rules()), reports)
    owned = False
    successful = False
    stages = []
    def run_stage(name):
        """Собирает свежий снимок с unsigned read/list, выполняет четыре анонимных правила и сохраняет безопасную сводку стадии."""
        data = SnapshotService(provider, snapshots).collect(bucket, CollectionOptions((key,), True))
        report = service.audit(data, AuditPolicy(), ('anonymous-read', 'anonymous-list', 'anonymous-write', 'anonymous-delete'))
        states = {row.rule_id: row.status for row in report.results}
        outcomes = {row.name: row.data['outcome'] for row in data.observations if row.name.startswith('anonymous_')}
        result = {'stage': name, 'report_id': report.id, 'snapshot_id': data.id,
                  'findings': states, 'anonymous_requests': outcomes}
        # Synthetic key is fixed and contains no private data.
        stages.append(result)
        print(json.dumps(result), flush=True)
        return states, outcomes
    def verify_stage(name, opened=False):
        """Собирает до пяти свежих наблюдений с паузой секунду; сохраняет каждую попытку и не подменяет ожидаемое состояние фактическим."""
        for attempt in range(5):
            states, probes = run_stage(name)
            expected = {
                'anonymous-read': 'confirmed_violation' if opened else 'passed',
                'anonymous-list': 'confirmed_violation' if opened else 'passed',
                'anonymous-write': 'passed', 'anonymous-delete': 'passed',
            }
            if states == expected and probes and all(value == ('allowed' if opened else 'denied') for value in probes.values()):
                return
            if attempt < 4:
                sleep(1)
        raise ValueError('Fixture stage did not reach the expected state within five attempts')

    try:
        client.create_bucket(Bucket=bucket, ACL='private')
        owned = True
        client.put_object(Bucket=bucket, Key=key, Body=b'cloud-audit synthetic fixture only\n', ACL='private')
        verify_stage('closed_before')
        arn = f'arn:aws:s3:::{bucket}'
        policy = {'Version': '2012-10-17', 'Statement': [
            {'Sid': 'SyntheticReadOnly', 'Effect': 'Allow', 'Principal': '*',
             'Action': 's3:GetObject', 'Resource': arn + '/' + key},
            {'Sid': 'SyntheticListOnly', 'Effect': 'Allow', 'Principal': '*',
             'Action': 's3:ListBucket', 'Resource': arn}]}
        client.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
        verify_stage('public_read_list', opened=True)
        client.delete_bucket_policy(Bucket=bucket)
        verify_stage('closed_after')
        successful = True
    except (ClientError, BotoCoreError, ResponseParserError, ValueError, OSError):
        print('Fixture verification failed; raw cloud details withheld', flush=True)
    finally:
        cleanup_ok = True
        if owned:
            # Each cleanup step is attempted even if a previous one failed.
            actions = (
                lambda: client.delete_bucket_policy(Bucket=bucket),
                lambda: client.put_bucket_acl(Bucket=bucket, ACL='private'),
                lambda: client.put_object_acl(Bucket=bucket, Key=key, ACL='private'),
                lambda: client.delete_object(Bucket=bucket, Key=key),
                lambda: client.delete_bucket(Bucket=bucket),
            )
            for action in actions:
                try:
                    action()
                except ClientError as error:
                    if error.response.get('Error', {}).get('Code') not in {
                            'NoSuchBucketPolicy', 'NoSuchKey', 'NoSuchBucket', 'NotFound'}:
                        cleanup_ok = False
                except (ResponseParserError, BotoCoreError, OSError):
                    cleanup_ok = False
        summary = {'success': successful, 'cleanup_ok': cleanup_ok, 'fixture_bucket': bucket,
                   'stage_count': len({item['stage'] for item in stages}), 'attempt_count': len(stages)}
        # Persist only synthetic fixture identifiers and summaries, never credentials or private contents.
        summary_path = state / 'data' / f'fixture-{uuid4().hex}.json'
        fd = os.open(summary_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as file:
            json.dump(summary | {'stages': stages}, file)
        print(json.dumps(summary | {'summary_path': str(summary_path)}), flush=True)
    return 0 if successful and cleanup_ok else 2


if __name__ == '__main__':
    raise SystemExit(main())
