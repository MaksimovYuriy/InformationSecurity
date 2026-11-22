"""
Консольный интерфейс и сборка зависимостей: выбирает сценарий, создаёт адаптеры, выводит результат и
код завершения.
"""
import argparse
from dataclasses import asdict
import json
import logging
import os
from pathlib import Path

from cloud_audit import __version__
from cloud_audit.errors import AuditError
from cloud_audit.services.profiles import ProfileService
from cloud_audit.services.environment import EnvironmentService
from cloud_audit.services.snapshots import SnapshotService
from cloud_audit.rules.engine import RuleEngine
from cloud_audit.services.audit import SecurityAuditService
from cloud_audit.rules.registry import default_rules
from cloud_audit.models.snapshot import CollectionOptions
from cloud_audit.models.history import HistoryQuery
from cloud_audit.models.security import FINDING_STATUSES
from cloud_audit.services.history import AuditHistoryService
from cloud_audit.configuration.policy import load_audit_policy
from cloud_audit.errors import ConfigurationError
from cloud_audit.configuration.environment import load_settings, load_s3_settings
from cloud_audit.providers.demo import DemoProvider
from cloud_audit.storage.json_reports import JsonReportRepository
from cloud_audit.storage.state import LocalStateStorage
from cloud_audit.storage.snapshots import JsonSnapshotRepository
from cloud_audit.storage.sqlite import SqliteReportRepository
from cloud_audit.reports.formatting import report_view, render_markdown, write_document


def build_parser() -> argparse.ArgumentParser:
    """
    Описывает команды, взаимоисключающий выбор ресурса/снимка, форматы, фильтры и флаги проб;
    --help/--version не требуют состояния.
    """
    parser = argparse.ArgumentParser(description='Cloud storage audit')
    parser.add_argument('--version', action='version', version=__version__)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('check', help='Check local environment')
    for name in ('connection', 'resources', 'audit', 'report', 'collect', 'snapshot', 'history', 'compare', 'import-reports'):
        command = commands.add_parser(name)
        command.add_argument('--format', choices=('json', 'text', 'markdown') if name in ('report', 'history', 'compare')
                             else ('json', 'text'), default='json')
        if name in ('connection', 'resources', 'audit', 'collect'):
            command.add_argument('--profile', choices=('vk',) if name == 'collect' else ('demo', 'vk'),
                                 default='vk' if name == 'collect' else 'demo')
        if name == 'collect':
            command.add_argument('--resource', required=True)
        if name == 'audit':
            target = command.add_mutually_exclusive_group(required=True)
            target.add_argument('--resource')
            target.add_argument('--snapshot')
            command.add_argument('--rules', nargs='+', default=[])
            command.add_argument('--policy', type=Path)
        if name in ('audit', 'collect'):
            command.add_argument('--objects', nargs='+', default=[])
            command.add_argument('--probe-anonymous', action='store_true')
            command.add_argument('--allow-write-probes', action='store_true')
        if name == 'report':
            command.add_argument('report_id')
        if name == 'snapshot':
            command.add_argument('snapshot_id')
        if name in ('report', 'history'):
            command.add_argument('--rule')
            command.add_argument('--severity', choices=('none', 'unknown', 'low', 'medium', 'high', 'critical'))
            command.add_argument('--status', choices=tuple(sorted(FINDING_STATUSES | {'simulated'})))
        if name in ('report', 'history', 'compare'):
            command.add_argument('--output', type=Path)
        if name == 'history':
            command.add_argument('--resource')
            command.add_argument('--profile', choices=('vk', 'demo', 'all'), default='vk')
            command.add_argument('--run-status', choices=('complete', 'incomplete', 'failed', 'demo'))
            command.add_argument('--limit', type=int, default=50)
            command.add_argument('--offset', type=int, default=0)
        if name == 'compare':
            command.add_argument('before_id')
            command.add_argument('after_id')
    from cloud_audit.scan_cli import add_scan_commands
    add_scan_commands(commands)
    return parser


def main() -> int:
    """
    Разбирает аргументы CLI, загружает настройки, собирает реализации интерфейсов, выполняет
    выбранную команду и возвращает 0/1/2/3; секреты не выводит.
    """
    parser = build_parser()
    args = parser.parse_args()
    try:
        options = None
        if args.command in ('audit', 'collect') and (args.objects or args.probe_anonymous or args.allow_write_probes):
            if (args.profile != 'vk' or getattr(args, 'snapshot', None)):
                raise AuditError('Object selection and probes require a live VK resource')
            try:
                options = CollectionOptions(tuple(dict.fromkeys(args.objects)), args.probe_anonymous,
                                            args.allow_write_probes)
            except ValueError:
                raise AuditError('Invalid probe options: at most 20 explicit keys; write probes require --probe-anonymous') from None
        settings = load_settings(os.environ)
        logging.basicConfig(level=settings.log_level, format='%(levelname)s %(message)s')
        environment = EnvironmentService(settings, LocalStateStorage(settings.state_dir)).check()
        provider = DemoProvider()
        if (args.command in ('connection', 'resources', 'audit', 'collect') and getattr(args, 'profile', 'demo') == 'vk'
                and not (args.command == 'audit' and args.snapshot)):
            from cloud_audit.providers.s3 import S3Provider
            provider = S3Provider.from_settings(load_s3_settings(os.environ))
        reports = SqliteReportRepository(settings.state_dir / 'data' / 'audit.sqlite3',
                                        legacy=JsonReportRepository(settings.state_dir / 'data'))
        service = ProfileService(provider, reports)
        history = AuditHistoryService(reports)
        snapshots = JsonSnapshotRepository(settings.state_dir / 'data' / 'snapshots')
        if args.command in ('scan', 'scan-report'):
            from cloud_audit.scan_cli import execute_scan
            output = execute_scan(args, settings, reports, snapshots)
        elif args.command == 'check':
            output = {'version': __version__, **asdict(environment)}
        elif args.command == 'connection':
            output = service.connection()
        elif args.command == 'resources':
            output = {'mode': provider.mode, 'resources': [asdict(item) for item in service.resources()]}
        elif args.command == 'audit':
            if args.profile == 'demo':
                if args.snapshot or args.policy:
                    raise AuditError('Snapshot and policy options require --profile vk')
                output = asdict(service.simulate(args.resource, tuple(args.rules)))
            else:
                engine = RuleEngine(default_rules())
                engine.select(tuple(args.rules))
                policy = load_audit_policy(args.policy)
                if args.snapshot:
                    snapshot = snapshots.get(args.snapshot)
                else:
                    try:
                        snapshot = SnapshotService(provider, snapshots).collect(args.resource, options)
                    except AuditError as error:
                        identifier = reports.record_failure(args.resource, tuple(rule.id for rule in engine.select(tuple(args.rules))),
                            options.object_keys if options else (), 'cloud_request_failed', provider.namespace)
                        raise AuditError(f'Audit failed; run {identifier} recorded: {error}') from None
                    except OSError:
                        reports.record_failure(args.resource, tuple(rule.id for rule in engine.select(tuple(args.rules))),
                            options.object_keys if options else (), 'snapshot_storage_failed', provider.namespace)
                        raise
                output = asdict(SecurityAuditService(engine, reports).audit(snapshot, policy, tuple(args.rules)))
        elif args.command == 'collect':
            output = asdict(SnapshotService(provider, snapshots).collect(args.resource, options))
        elif args.command == 'snapshot':
            output = asdict(snapshots.get(args.snapshot_id))
        elif args.command == 'history':
            output = asdict(history.history(HistoryQuery(args.resource, args.rule, args.severity, args.status,
                None if args.profile == 'all' else args.profile, args.run_status, args.limit, args.offset)))
        elif args.command == 'compare':
            output = asdict(history.compare(args.before_id, args.after_id))
        elif args.command == 'import-reports':
            output = reports.import_legacy()
        else:
            output = report_view(service.report(args.report_id), rule_id=args.rule, severity=args.severity, status=args.status)
        if getattr(args, 'output', None):
            content = render_markdown(output) if args.format == 'markdown' else json.dumps(output, indent=2, ensure_ascii=False) + '\n'
            write_document(args.output, content)
    except (ConfigurationError, AuditError) as error:
        parser.exit(2, f'Configuration or request error: {error}\n')
    except OSError:
        parser.exit(1, 'Environment error: cannot access local state\n')
    if getattr(args, 'output', None):
        print(json.dumps({'saved_to': str(args.output)}, ensure_ascii=False))
    elif getattr(args, 'format', 'json') == 'markdown':
        print(render_markdown(output), end='')
    elif getattr(args, 'format', 'json') == 'text':
        if args.command in ('scan', 'scan-report'):
            print('STAGED STORAGE SCAN — see evidence and scope')
        elif args.command in ('history', 'compare', 'import-reports'):
            print('LOCAL AUDIT HISTORY')
        elif args.command in ('collect', 'snapshot'):
            print('VK CLOUD — bucket configuration only; security not assessed')
        elif 'evaluation_status' in output:
            print('VK CLOUD — selected security rules; see scope and limitations')
        else:
            print('DEMO — simulated data; no cloud security assessment performed'
                  if output.get('mode', 'demo') == 'demo'
                  else 'VK CLOUD — live connection; security not assessed')
        print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        print(json.dumps(output, ensure_ascii=False))
    if args.command in ('scan', 'scan-report'):
        return 3 if output['incomplete'] else 0
    if 'evaluation_status' in output:
        return 3 if output['evaluation_status'] == 'incomplete' else 0
    if args.command == 'compare':
        return 3 if not output['comparable'] or any(row['change'] == 'unverified' for row in output['changes']) else 0
    if args.command == 'import-reports' and output['skipped']:
        return 3
    return 3 if output.get('collection_status') == 'partial' else 0
