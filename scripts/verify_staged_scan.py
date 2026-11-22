"""Изолированный трёхбакетный стенд scan: закрыто/публично/закрыто, только искусственные данные."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from time import perf_counter, sleep
from uuid import uuid4

from botocore.exceptions import BotoCoreError, ClientError
from botocore.parsers import ResponseParserError
from cloud_audit.configuration.environment import load_s3_settings
from cloud_audit.configuration.dotenv import load_environment
from cloud_audit.providers.s3 import S3Provider
from cloud_audit.reports.formatting import write_document
from cloud_audit.storage.state import LocalStateStorage


ERRORS = (ClientError, BotoCoreError, ResponseParserError, OSError, ValueError, KeyError, TypeError)


def cleanup_fixture(client, owned):
    """Закрывает и удаляет только успешно созданные этим запуском бакеты, продолжая после ошибок."""
    success = True
    for bucket in owned:
        try:
            client.delete_bucket_policy(Bucket=bucket)
        except ClientError as exc:
            if exc.response.get('Error', {}).get('Code') not in {'NoSuchBucketPolicy', 'NoSuchBucket', 'NotFound'}:
                success = False
        except ERRORS:
            success = False
        try:
            page = client.list_object_versions(Bucket=bucket, MaxKeys=1000)
            if page.get('IsTruncated'):
                raise ValueError('Fixture cleanup scope incomplete')
            for item in (*page.get('Versions', []), *page.get('DeleteMarkers', [])):
                client.delete_object(Bucket=bucket, Key=item['Key'], VersionId=item['VersionId'])
        except ERRORS:
            success = False
        try:
            client.delete_bucket(Bucket=bucket)
        except ERRORS:
            success = False
    return success


def public_phase_confirmed(attempts, names, key):
    """Подтверждает существование каждой публичной операции по отдельным исходным запускам, не создавая объединённого фиктивного отчёта."""
    observed = set()
    for attempt in attempts:
        if attempt['label'] != 'public':
            continue
        for row in attempt['buckets']:
            if row['bucket'] not in names:
                continue
            index = names.index(row['bucket'])
            for proof in row['probes']:
                op, outcome = proof['operation'], proof['outcome']
                if op == 'read' and proof['target'] != key:
                    continue
                if index == 0 and outcome == 'allowed':
                    return False
                if index == 1 and op in {'write', 'delete'}:
                    if proof['cleanup'] != 'cleaned' or op == 'delete' and proof['verification'] != 'current_object_absent':
                        continue
                observed.add((index, op, outcome))
    required = {(0,'list','denied'),(0,'read','denied'),(1,'list','allowed'),(1,'read','allowed'),
                (1,'write','allowed'),(1,'delete','allowed'),(2,'list','denied'),(2,'read','allowed')}
    return required <= observed


def main():
    """Создаёт отдельный стенд с явным флагом, запускает реальный CLI и записывает приватную сводку всех попыток."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-training-fixture', action='store_true', required=True)
    parser.parse_args()
    configuration = load_environment(os.environ)
    provider = S3Provider.from_settings(load_s3_settings(configuration))
    client = provider._client
    state = Path(configuration.get('CLOUD_AUDIT_STATE_DIR', '.state'))
    LocalStateStorage(state).prepare()
    nonce = uuid4().hex
    names = tuple('cloud-audit-stage-' + nonce[:20] + '-' + suffix for suffix in ('closed', 'public', 'object'))
    owned, attempts = [], []
    success, error = False, None
    key = 'synthetic-staged-fixture.txt'
    targets = state / 'data' / ('staged-targets-' + nonce + '.json')
    readonly = state / 'data' / ('staged-readonly-' + nonce + '.json')
    residue = state / 'data' / ('staged-residue-' + nonce + '.json')
    def invoke(label, file, unsigned=False):
        """Запускает публичный CLI отдельным процессом; сохраняет только контролируемые факты и идентификаторы."""
        env = dict(configuration)
        if unsigned:
            env = {k: v for k, v in env.items() if not k.startswith('AWS_')}
        started = perf_counter()
        process = subprocess.run([sys.executable, '-m', 'cloud_audit', '--no-env-file', 'scan', '--targets', str(file), '--max-objects', '3'],
                                 capture_output=True, text=True, env=env, timeout=180)
        if process.returncode not in (0, 3):
            raise ValueError('Scan CLI failed; raw response withheld')
        run = json.loads(process.stdout)
        summary = {'label': label, 'scan_id': run['id'], 'exit_code': process.returncode,
                   'seconds': round(perf_counter()-started, 3), 'buckets': []}
        for row in run['buckets']:
            summary['buckets'].append({'bucket': row['bucket'], 'internal_status': row['internal_status'],
                'report_id': row['internal_report_id'], 'probes': [
                    {k: p[k] for k in ('operation', 'target', 'outcome', 'verification', 'cleanup')} for p in row['external']['probes']]})
        attempts.append(summary)
        return run

    def matches(run, opened):
        """Требует реальные исходы запросов, а не только наличие разрешающих настроек."""
        if len(run['buckets']) != 3:
            return False
        for index, row in enumerate(run['buckets']):
            if row['internal_report_id'] is None:
                return False
            probes = row['external']['probes']
            expected_read = 'allowed' if opened and index in (1, 2) else 'denied'
            expected_list = 'allowed' if opened and index == 1 else 'denied'
            if next(p for p in probes if p['operation'] == 'list')['outcome'] != expected_list:
                return False
            if next(p for p in probes if p['operation'] == 'read')['outcome'] != expected_read:
                return False
            if index == 1:
                for operation in ('write', 'delete'):
                    p = next(p for p in probes if p['operation'] == operation)
                    if p['outcome'] != ('allowed' if opened else 'denied') or p['cleanup'] not in {'cleaned', 'not_needed'}:
                        return False
        return True

    def settled(label, opened):
        """Даёт политике до пяти ограниченных попыток применения, не скрывая неуспешные наблюдения."""
        for attempt in range(5):
            run = invoke(label, targets)
            if (public_phase_confirmed(attempts, names, key) if opened else matches(run, False)):
                return run
            if attempt < 4:
                sleep(1)
        raise ValueError('Fixture did not settle within five scans')

    started = perf_counter()
    try:
        for bucket in names:
            client.create_bucket(Bucket=bucket, ACL='private')
            owned.append(bucket)
            client.put_object(Bucket=bucket, Key=key, Body=b'artificial staged audit fixture only\n', ACL='private')
        plain = {'buckets': [{'name': name, 'objects': [key]} for name in names]}
        configured = {'buckets': [dict(row, allow_mutations=True) if i == 1 else row for i, row in enumerate(plain['buckets'])]}
        anonymous_mutation = {'buckets': [dict(row, allow_mutations=True, allow_residue=True) if i == 1 else row for i, row in enumerate(plain['buckets'])]}
        for path, data in ((targets, configured), (readonly, plain), (residue, anonymous_mutation)):
            write_document(path, json.dumps(data))
        settled('closed_before', False)
        arn = 'arn:aws:s3:::' + names[1]
        policy = {'Version': '2012-10-17', 'Statement': [
            {'Effect': 'Allow', 'Principal': '*', 'Action': 's3:ListBucket', 'Resource': arn},
            {'Effect': 'Allow', 'Principal': '*', 'Action': 's3:GetObject', 'Resource': [arn+'/'+key, arn+'/_cloud-audit-probe/*']},
            {'Effect': 'Allow', 'Principal': '*', 'Action': ['s3:PutObject', 's3:DeleteObject'], 'Resource': arn+'/_cloud-audit-probe/*'}]}
        client.put_bucket_policy(Bucket=names[1], Policy=json.dumps(policy))
        client.put_object_acl(Bucket=names[2], Key=key, ACL='public-read')
        settled('public', True)
        run = invoke('unsigned_readonly', readonly, unsigned=True)
        if run['authenticated'] or any(row['internal_status'] != 'skipped' for row in run['buckets']):
            raise ValueError('Unsigned mode unexpectedly ran authenticated stage')
        for attempt in range(5):
            run = invoke('unsigned_mutations_with_residue_acceptance', residue, unsigned=True)
            probes = run['buckets'][1]['external']['probes']
            if any(p['operation']=='write' and p['outcome']=='allowed' and p['cleanup']=='residue' for p in probes):
                break
            if attempt < 4:
                sleep(1)
        else:
            raise ValueError('Unsigned mutation evidence did not match expectations')
        client.delete_bucket_policy(Bucket=names[1])
        client.put_object_acl(Bucket=names[2], Key=key, ACL='private')
        settled('closed_after', False)
        success = True
    except ERRORS:
        error = 'staged_fixture_verification_failed'
    except subprocess.TimeoutExpired:
        error = 'staged_fixture_timeout'
    finally:
        cleanup = cleanup_fixture(client, owned)
        summary = {'success': success, 'cleanup_ok': cleanup, 'seconds': round(perf_counter()-started, 3),
                   'owned_buckets': owned, 'attempts': attempts, 'error_code': error}
        path = state / 'data' / ('staged-fixture-' + nonce + '.json')
        write_document(path, json.dumps(summary, indent=2))
        print(json.dumps({'success': success, 'cleanup_ok': cleanup, 'seconds': summary['seconds'],
                          'attempts': len(attempts), 'summary_path': str(path)}))
    return 0 if success and cleanup else 2


if __name__ == '__main__':
    raise SystemExit(main())
