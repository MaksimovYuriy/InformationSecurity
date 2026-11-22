from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from cloud_audit.application.audit import AuditError
from cloud_audit.application.rules import RuleEngine
from cloud_audit.application.security_audit import SecurityAuditService
from cloud_audit.domain.rules import AuditPolicy
from cloud_audit.domain.versioning import VersioningRule
from cloud_audit.infrastructure.reports import JsonReportRepository
from cloud_audit.infrastructure.snapshots import JsonSnapshotRepository
from test_rule_engine import snapshot


class ReviewRegressionTests(unittest.TestCase):
    def test_invalid_utf8_report_is_a_controlled_error(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = JsonReportRepository(Path(directory))
            (Path(directory) / ('a' * 32 + '.json')).write_bytes(b'\xff')
            with self.assertRaises(AuditError):
                repo.get('a' * 32)

    def test_report_cannot_claim_passed_without_observed_enabled_value(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = JsonReportRepository(Path(directory))
            report = SecurityAuditService(RuleEngine((VersioningRule(),)), repo).audit(snapshot('Enabled'), AuditPolicy())
            path = Path(directory) / (report.id + '.json')
            data = json.loads(path.read_text())
            data['results'][0]['evidence'][0]['value'] = 'Disabled'
            path.write_text(json.dumps(data))
            with self.assertRaises(AuditError):
                repo.get(report.id)

    def test_future_snapshot_timestamp_cannot_bypass_retention(self):
        from test_configuration_snapshot import configured_client
        from cloud_audit.application.snapshot import SnapshotService
        from cloud_audit.infrastructure.s3_configuration import S3ConfigurationCollector
        now = datetime.now(timezone.utc)
        data = SnapshotService(S3ConfigurationCollector(configured_client()), Mock()).collect('lab')
        data = replace(data, collected_at=(now + timedelta(days=30)).isoformat())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / (data.id + '.json')
            path.write_text(json.dumps(asdict(data)))
            with self.assertRaises(AuditError):
                JsonSnapshotRepository(Path(directory)).get(data.id)


class MalformedSdkResponseTests(unittest.TestCase):
    def test_invalid_xml_is_a_sanitized_error_for_all_cloud_read_paths(self):
        from botocore.parsers import ResponseParserError
        from cloud_audit.domain.audit import Resource
        from cloud_audit.infrastructure.anonymous import AnonymousProber
        from cloud_audit.infrastructure.s3 import S3Provider
        from cloud_audit.infrastructure.s3_configuration import S3ConfigurationCollector
        from test_configuration_snapshot import configured_client
        client = configured_client()
        client.get_bucket_acl.side_effect = ResponseParserError('SECRET raw XML')
        fields = {x.name: x for x in S3ConfigurationCollector(client).collect(Resource('lab', 'lab'))}
        self.assertEqual(fields['bucket_acl'].status, 'error')
        client.list_objects_v2.side_effect = ResponseParserError('SECRET raw XML')
        self.assertEqual(AnonymousProber(client).read_only('lab', ())[0].data['outcome'], 'error')
        client.list_buckets.side_effect = ResponseParserError('SECRET raw XML')
        with self.assertRaises(AuditError) as caught:
            S3Provider(client).resources()
        self.assertNotIn('SECRET', str(caught.exception))
