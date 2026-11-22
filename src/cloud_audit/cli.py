import argparse
from dataclasses import asdict
import json
import logging
import os
from pathlib import Path

from cloud_audit import __version__
from cloud_audit.application.audit import AuditError, AuditService
from cloud_audit.application.environment import EnvironmentService
from cloud_audit.application.snapshot import SnapshotService
from cloud_audit.application.rules import RuleEngine
from cloud_audit.application.security_audit import SecurityAuditService
from cloud_audit.application.rule_registry import default_rules
from cloud_audit.domain.snapshot import CollectionOptions
from cloud_audit.infrastructure.audit_policy import load_audit_policy
from cloud_audit.infrastructure.configuration import ConfigurationError, load_settings, load_s3_settings
from cloud_audit.infrastructure.demo import DemoProvider
from cloud_audit.infrastructure.reports import JsonReportRepository
from cloud_audit.infrastructure.storage import LocalStateStorage
from cloud_audit.infrastructure.snapshots import JsonSnapshotRepository


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Cloud storage audit')
    parser.add_argument('--version', action='version', version=__version__)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('check', help='Check local environment')
    for name in ('connection', 'resources', 'audit', 'report', 'collect', 'snapshot'):
        command = commands.add_parser(name)
        command.add_argument('--format', choices=('json', 'text'), default='json')
        if name not in ('report', 'snapshot'):
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
    return parser


def main() -> int:
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
        if (getattr(args, 'profile', 'demo') == 'vk'
                and not (args.command == 'audit' and args.snapshot)):
            from cloud_audit.infrastructure.s3 import S3Provider
            provider = S3Provider.from_settings(load_s3_settings(os.environ))
        service = AuditService(provider, JsonReportRepository(settings.state_dir / 'data'))
        snapshots = JsonSnapshotRepository(settings.state_dir / 'data' / 'snapshots')
        if args.command == 'check':
            output = {'version': __version__, **asdict(environment)}
        elif args.command == 'connection':
            output = service.connection()
        elif args.command == 'resources':
            output = {'mode': provider.mode, 'resources': [asdict(item) for item in service.resources()]}
        elif args.command == 'audit':
            if args.profile == 'demo':
                if args.snapshot or args.policy:
                    raise AuditError('Snapshot and policy options require --profile vk')
                output = asdict(service.audit(args.resource, tuple(args.rules)))
            else:
                engine = RuleEngine(default_rules())
                engine.select(tuple(args.rules))
                policy = load_audit_policy(args.policy)
                snapshot = (snapshots.get(args.snapshot) if args.snapshot
                            else SnapshotService(provider, snapshots).collect(args.resource, options))
                output = asdict(SecurityAuditService(engine, JsonReportRepository(
                    settings.state_dir / 'data')).audit(snapshot, policy, tuple(args.rules)))
        elif args.command == 'collect':
            output = asdict(SnapshotService(provider, snapshots).collect(args.resource, options))
        elif args.command == 'snapshot':
            output = asdict(snapshots.get(args.snapshot_id))
        else:
            output = asdict(service.report(args.report_id))
    except (ConfigurationError, AuditError) as error:
        parser.exit(2, f'Configuration or request error: {error}\n')
    except OSError:
        parser.exit(1, 'Environment error: cannot access local state\n')
    if getattr(args, 'format', 'json') == 'text':
        if args.command in ('collect', 'snapshot'):
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
    if 'evaluation_status' in output:
        return 3 if output['evaluation_status'] == 'incomplete' else 0
    return 3 if output.get('collection_status') == 'partial' else 0
