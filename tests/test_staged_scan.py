"""A scan chooses buckets, runs independent stages and preserves partial results."""
from datetime import datetime, timezone
from types import SimpleNamespace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from cloud_audit.models.scanning import ScanTarget, ExternalResult, ObjectDiscovery, ProbeResult
from cloud_audit.services.scanning import ScanService
from cloud_audit.configuration.targets import parse_targets
from cloud_audit.errors import AuditError, ConfigurationError


def external(keys=()):
    return ExternalResult((), ObjectDiscovery(keys, 'complete', 'anonymous', 20))


class StagedScanTests(unittest.TestCase):
    def test_explicit_targets_do_not_require_listing_permission_and_continue_on_error(self):
        inspector = Mock(namespace='https://example.invalid')
        inspector.inspect.side_effect = [AuditError('failed'), external()]
        repo = Mock()
        run = ScanService(inspector, repo).run((ScanTarget('first'), ScanTarget('second')))
        self.assertEqual(len(run.buckets), 2)
        self.assertEqual(run.buckets[0].external_status, 'failed')
        self.assertEqual(run.buckets[1].external_status, 'complete')
        self.assertEqual(run.buckets[1].internal_status, 'skipped')
        repo.save.assert_called_once_with(run)

    def test_internal_stage_runs_even_when_external_listing_is_denied(self):
        inspector = Mock(namespace='https://example.invalid')
        inspector.inspect.return_value = ExternalResult((), ObjectDiscovery((), 'failed', 'anonymous', 20, 'access_denied'))
        inspector.read_objects.return_value = ()
        provider = Mock()
        provider.discover_objects.return_value = ObjectDiscovery(('inside.txt',), 'complete', 'authenticated', 20)
        snapshots = Mock()
        snapshots.collect.return_value = SimpleNamespace()
        audits = Mock()
        audits.audit.return_value = SimpleNamespace(id='a'*32, evaluation_status='complete')
        run = ScanService(inspector, Mock(), provider, snapshots, audits).run((ScanTarget('first'),))
        self.assertEqual(run.buckets[0].internal_report_id, 'a'*32)
        provider.resources.assert_not_called()
        inspector.read_objects.assert_called_once_with('first', ('inside.txt',))

    def test_all_buckets_requires_credentials_and_listing_failure_is_saved(self):
        inspector = Mock(namespace='https://example.invalid')
        with self.assertRaises(AuditError):
            ScanService(inspector, Mock()).run((), all_buckets=True)
        provider = Mock()
        provider.resources.side_effect = AuditError('denied')
        run = ScanService(inspector, Mock(), provider).run((), all_buckets=True)
        self.assertEqual(run.selection_status, 'failed')
        self.assertEqual(run.buckets, ())

    def test_targets_are_strict_per_bucket_and_duplicates_rejected(self):
        targets = parse_targets({'buckets': [{'name': 'first', 'objects': ['one.txt'], 'allow_mutations': True},
                                            {'name': 'second', 'objects': ['two.txt']}]})
        self.assertEqual(targets[0].object_keys, ('one.txt',))
        self.assertFalse(targets[1].allow_mutations)
        for raw in ({'buckets': [{'name': 'first'}, {'name': 'first'}]},
                    {'buckets': [{'name': 'first', 'secret': 'not-allowed'}]},
                    {'buckets': [{'name': 'first', 'allow_mutations': 'yes'}]}):
            with self.subTest(raw=raw), self.assertRaises(ConfigurationError):
                parse_targets(raw)

    def test_all_buckets_mutations_only_apply_to_explicit_permission_names(self):
        inspector = Mock(namespace='https://example.invalid')
        inspector.inspect.return_value = external()
        inspector.read_objects.return_value = ()
        provider = Mock()
        provider.resources.return_value = (SimpleNamespace(id='first'), SimpleNamespace(id='second'))
        provider.discover_objects.return_value = ObjectDiscovery((), 'complete', 'authenticated', 20)
        snapshots, audits = Mock(), Mock()
        audits.audit.return_value = SimpleNamespace(id='a'*32, evaluation_status='complete')
        run = ScanService(inspector, Mock(), provider, snapshots, audits).run((), all_buckets=True, mutation_buckets=('second',))
        self.assertEqual([call.args[0].allow_mutations for call in inspector.inspect.call_args_list], [False, True])
        self.assertEqual(len(run.buckets), 2)

    def test_fresh_combined_snapshot_keeps_external_facts_for_offline_audit(self):
        from dataclasses import replace
        from cloud_audit.services.snapshots import SnapshotService
        from cloud_audit.storage.snapshots import JsonSnapshotRepository
        from cloud_audit.models.snapshot import ConfigurationObservation
        from audit_fixtures import configured_client
        from cloud_audit.providers.s3 import S3Provider
        with tempfile.TemporaryDirectory() as directory:
            repo = JsonSnapshotRepository(Path(directory))
            service = SnapshotService(S3Provider(configured_client(), namespace='https://example.invalid'), repo)
            snapshot = service.collect('first')
            fact = ConfigurationObservation('anonymous_list', 'anonymous_list_objects_v2', 'available',
                {'outcome': 'allowed', 'http_status': 200, 'checked_at': snapshot.collected_at})
            enriched = service.enrich(replace(snapshot, schema_version=2), (fact,))
            self.assertNotEqual(enriched.id, snapshot.id)
            self.assertEqual(repo.get(enriched.id).observations[-1], fact)

    def test_recovered_get_evidence_is_not_lost_after_an_external_stage_error(self):
        inspector = Mock(namespace='https://example.invalid')
        inspector.inspect.side_effect = AuditError('external failed')
        probe = ProbeResult('read', 'inside.txt', 'allowed', 206, datetime.now(timezone.utc).isoformat())
        inspector.read_objects.return_value = (probe,)
        provider = Mock()
        provider.discover_objects.return_value = ObjectDiscovery(('inside.txt',), 'complete', 'authenticated', 20)
        audits = Mock()
        audits.audit.return_value = SimpleNamespace(id='a'*32, evaluation_status='complete')
        run = ScanService(inspector, Mock(), provider, Mock(), audits).run((ScanTarget('first'),))
        self.assertEqual(run.buckets[0].external_status, 'incomplete')
        self.assertEqual(run.buckets[0].external.probes, (probe,))
        self.assertEqual(next(f for f in run.buckets[0].external_findings if f.rule_id == 'anonymous-read').status, 'confirmed_violation')

    def test_common_policy_applies_to_discovered_buckets_too(self):
        from cloud_audit.models.security import AuditPolicy
        inspector = Mock(namespace='https://example.invalid')
        inspector.inspect.return_value = external()
        inspector.read_objects.return_value = ()
        provider = Mock()
        provider.resources.return_value = (SimpleNamespace(id='first'),)
        provider.discover_objects.return_value = ObjectDiscovery((), 'complete', 'authenticated', 20)
        audits = Mock()
        audits.audit.return_value = SimpleNamespace(id='a'*32, evaluation_status='complete')
        policy = AuditPolicy(data_sensitivity='high')
        run = ScanService(inspector, Mock(), provider, Mock(), audits).run((), all_buckets=True, default_policy=policy)
        self.assertEqual(run.buckets[0].target.policy, policy)
        self.assertEqual(audits.audit.call_args.args[1], policy)
