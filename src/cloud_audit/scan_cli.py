"""Аргументы и сборка зависимостей ступенчатого scan, отдельно от прежних одиночных команд."""
from dataclasses import asdict
from pathlib import Path

from cloud_audit.configuration.environment import load_scan_settings
from cloud_audit.configuration.policy import load_audit_policy
from cloud_audit.configuration.targets import load_targets
from cloud_audit.errors import AuditError
from cloud_audit.models.scanning import ScanTarget
from cloud_audit.providers.external import ExternalInspector
from cloud_audit.providers.s3 import S3Provider
from cloud_audit.rules.engine import RuleEngine
from cloud_audit.rules.registry import default_rules
from cloud_audit.services.audit import SecurityAuditService
from cloud_audit.services.scanning import ScanService
from cloud_audit.services.snapshots import SnapshotService
from cloud_audit.storage.scans import JsonScanRepository


def add_scan_commands(commands):
    """Добавляет три взаимоисключающих источника целей и отдельное офлайн-чтение сводки."""
    scan = commands.add_parser('scan', help='Staged anonymous and optional authenticated scan')
    target = scan.add_mutually_exclusive_group(required=True)
    target.add_argument('--buckets', nargs='+')
    target.add_argument('--all-buckets', action='store_true')
    target.add_argument('--targets', type=Path)
    scan.add_argument('--max-objects', type=int, default=20)
    scan.add_argument('--external-only', action='store_true')
    scan.add_argument('--mutation-buckets', nargs='+', default=[])
    scan.add_argument('--allow-residue', action='store_true')
    scan.add_argument('--policy', type=Path)
    saved = commands.add_parser('scan-report', help='Read an aggregate scan report offline')
    saved.add_argument('scan_id')
    for command in (scan, saved):
        command.add_argument('--format', choices=('json', 'text', 'markdown'), default='json')
        command.add_argument('--output', type=Path)


def execute_scan(args, settings, reports, snapshots, configuration):
    """Создаёт signed-клиента только при полной паре ключей; внешний клиент всегда UNSIGNED."""
    runs = JsonScanRepository(settings.state_dir / 'data' / 'scans')
    if args.command == 'scan-report':
        run = runs.get(args.scan_id)
    else:
        connection, authenticated = load_scan_settings(configuration, external_only=args.external_only)
        if args.all_buckets and not authenticated:
            raise AuditError('All-bucket selection requires credentials')
        if not 1 <= args.max_objects <= 20:
            raise AuditError('Object limit must be between 1 and 20')
        if args.allow_residue and not args.mutation_buckets:
            raise AuditError('Residue acceptance requires explicit mutation bucket names')
        try:
            targets = load_targets(args.targets) if args.targets else tuple(ScanTarget(name) for name in dict.fromkeys(args.buckets or ()))
        except ValueError:
            raise AuditError('Invalid scan bucket name or scope') from None
        if not args.all_buckets and set(args.mutation_buckets) - {t.name for t in targets}:
            raise AuditError('Mutation permission is outside the selected bucket scope')
        policy = load_audit_policy(args.policy) if args.policy else None
        # Reject unaccepted anonymous residue before constructing clients or making requests.
        if not authenticated and any(t.allow_mutations and not t.allow_residue for t in targets):
            raise AuditError('Unsigned-only mutations require per-bucket residue acceptance')
        if not authenticated and args.mutation_buckets and not args.allow_residue:
            raise AuditError('Unsigned-only mutations require --allow-residue')
        provider = S3Provider.from_settings(connection) if authenticated else None
        external = ExternalInspector.from_settings(connection, provider._client if provider is not None else None)
        scan = ScanService(external, runs, provider, SnapshotService(provider, snapshots) if provider else None,
                           SecurityAuditService(RuleEngine(default_rules()), reports) if provider else None)
        run = scan.run(targets, all_buckets=args.all_buckets, max_objects=args.max_objects,
                       external_only=args.external_only, mutation_buckets=tuple(args.mutation_buckets), allow_residue=args.allow_residue,
                       selection_source='file' if args.targets else 'explicit', default_policy=policy)
    return dict(asdict(run), incomplete=run.incomplete)
