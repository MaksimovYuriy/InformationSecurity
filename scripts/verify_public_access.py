"""Isolated VK Cloud read/list fixture. Creates only artificial data; always attempts cleanup."""
import argparse
import json
import os
from pathlib import Path
from uuid import uuid4

from botocore.exceptions import ClientError, BotoCoreError
from botocore.parsers import ResponseParserError
from cloud_audit.application.rule_registry import default_rules
from cloud_audit.application.rules import RuleEngine
from cloud_audit.application.security_audit import SecurityAuditService
from cloud_audit.application.snapshot import SnapshotService
from cloud_audit.domain.rules import AuditPolicy
from cloud_audit.domain.snapshot import CollectionOptions
from cloud_audit.infrastructure.configuration import load_s3_settings
from cloud_audit.infrastructure.s3 import S3Provider
from cloud_audit.infrastructure.snapshots import JsonSnapshotRepository
from cloud_audit.infrastructure.reports import JsonReportRepository
from cloud_audit.infrastructure.history import SqliteReportRepository
from cloud_audit.infrastructure.storage import LocalStateStorage


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-training-fixture', action='store_true', required=True,
                        help='Create a temporary bucket and briefly publish only synthetic read/list data')
    parser.parse_args()
    provider = S3Provider.from_settings(load_s3_settings(os.environ))
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
    try:
        client.create_bucket(Bucket=bucket, ACL='private')
        owned = True
        client.put_object(Bucket=bucket, Key=key, Body=b'cloud-audit synthetic fixture only\n', ACL='private')
        closed, probes = run_stage('closed_before')
        if any(value != 'passed' for value in closed.values()) or any(value != 'denied' for value in probes.values()):
            raise ValueError('Closed baseline did not match expectations')
        arn = f'arn:aws:s3:::{bucket}'
        policy = {'Version': '2012-10-17', 'Statement': [
            {'Sid': 'SyntheticReadOnly', 'Effect': 'Allow', 'Principal': '*',
             'Action': 's3:GetObject', 'Resource': arn + '/' + key},
            {'Sid': 'SyntheticListOnly', 'Effect': 'Allow', 'Principal': '*',
             'Action': 's3:ListBucket', 'Resource': arn}]}
        client.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
        opened, probes = run_stage('public_read_list')
        if (opened['anonymous-read'] != 'confirmed_violation' or opened['anonymous-list'] != 'confirmed_violation'
                or any(value != 'allowed' for value in probes.values())):
            raise ValueError('Public fixture did not match expectations')
        client.delete_bucket_policy(Bucket=bucket)
        closed, probes = run_stage('closed_after')
        if any(value != 'passed' for value in closed.values()) or any(value != 'denied' for value in probes.values()):
            raise ValueError('Closure did not match expectations')
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
                   'stage_count': len(stages)}
        # Persist only synthetic fixture identifiers and summaries, never credentials or private contents.
        summary_path = state / 'data' / f'fixture-{uuid4().hex}.json'
        fd = os.open(summary_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as file:
            json.dump(summary | {'stages': stages}, file)
        print(json.dumps(summary | {'summary_path': str(summary_path)}), flush=True)
    return 0 if successful and cleanup_ok else 2


if __name__ == '__main__':
    raise SystemExit(main())
