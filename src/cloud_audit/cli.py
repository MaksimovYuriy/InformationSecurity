import argparse
from dataclasses import asdict
import json
import logging
import os

from cloud_audit import __version__
from cloud_audit.application.audit import AuditError, AuditService
from cloud_audit.application.environment import EnvironmentService
from cloud_audit.infrastructure.configuration import ConfigurationError, load_settings
from cloud_audit.infrastructure.demo import DemoProvider
from cloud_audit.infrastructure.reports import JsonReportRepository
from cloud_audit.infrastructure.storage import LocalStateStorage


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Cloud storage audit (demo only)')
    parser.add_argument('--version', action='version', version=__version__)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('check', help='Check local environment')
    for name in ('connection', 'resources', 'audit', 'report'):
        command = commands.add_parser(name)
        command.add_argument('--format', choices=('json', 'text'), default='json')
        if name != 'report':
            command.add_argument('--profile', choices=('demo',), default='demo')
        if name == 'audit':
            command.add_argument('--resource', required=True)
            command.add_argument('--rules', nargs='+', default=[])
        if name == 'report':
            command.add_argument('report_id')
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        settings = load_settings(os.environ)
        logging.basicConfig(level=settings.log_level, format='%(levelname)s %(message)s')
        environment = EnvironmentService(settings, LocalStateStorage(settings.state_dir)).check()
        service = AuditService(DemoProvider(), JsonReportRepository(settings.state_dir / 'data'))
        if args.command == 'check':
            output = {'version': __version__, **asdict(environment)}
        elif args.command == 'connection':
            output = service.connection()
        elif args.command == 'resources':
            output = {'mode': 'demo', 'resources': [asdict(item) for item in service.resources()]}
        elif args.command == 'audit':
            output = asdict(service.audit(args.resource, tuple(args.rules)))
        else:
            output = asdict(service.report(args.report_id))
    except (ConfigurationError, AuditError) as error:
        parser.exit(2, f'Configuration or request error: {error}\n')
    except OSError:
        parser.exit(1, 'Environment error: cannot access local state\n')
    if getattr(args, 'format', 'json') == 'text':
        print('DEMO — simulated data; no cloud security assessment performed')
        print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        print(json.dumps(output, ensure_ascii=False))
    return 0
