import argparse
from dataclasses import asdict
import json
import logging
import os

from cloud_audit import __version__
from cloud_audit.application.audit import AuditError, AuditService
from cloud_audit.application.environment import EnvironmentService
from cloud_audit.application.snapshot import SnapshotService
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
        if name in ('audit', 'collect'):
            command.add_argument('--resource', required=True)
        if name == 'audit':
            command.add_argument('--rules', nargs='+', default=[])
        if name == 'report':
            command.add_argument('report_id')
        if name == 'snapshot':
            command.add_argument('snapshot_id')
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        settings = load_settings(os.environ)
        logging.basicConfig(level=settings.log_level, format='%(levelname)s %(message)s')
        environment = EnvironmentService(settings, LocalStateStorage(settings.state_dir)).check()
        provider = DemoProvider()
        if getattr(args, 'profile', 'demo') == 'vk':
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
            output = asdict(service.audit(args.resource, tuple(args.rules)))
        elif args.command == 'collect':
            output = asdict(SnapshotService(provider, snapshots).collect(args.resource))
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
        else:
            print('DEMO — simulated data; no cloud security assessment performed'
                  if output.get('mode', 'demo') == 'demo'
                  else 'VK CLOUD — live connection; security not assessed')
        print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        print(json.dumps(output, ensure_ascii=False))
    return 3 if output.get('collection_status') == 'partial' else 0
