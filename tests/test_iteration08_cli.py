import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cloud_audit.domain.history import HistoryQuery
from cloud_audit.infrastructure.history import SqliteReportRepository
from cloud_audit.infrastructure.reports import JsonReportRepository
from test_iteration08_comparison import version_report


class Iteration08CliTests(unittest.TestCase):
    def cli(self, root, *arguments):
        return subprocess.run([sys.executable, '-m', 'cloud_audit', *arguments], capture_output=True, text=True,
            env=dict(os.environ, CLOUD_AUDIT_STATE_DIR=str(root)))

    def test_import_history_filtered_export_and_comparison_between_processes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = root / 'data'
            data.mkdir()
            before, after = version_report('Disabled'), version_report('Enabled', 1)
            legacy = JsonReportRepository(data)
            legacy.save(before)
            legacy.save(after)
            imported = self.cli(root, 'import-reports')
            self.assertEqual(imported.returncode, 0, imported.stderr)
            self.assertEqual(json.loads(imported.stdout)['imported'], 2)
            history = self.cli(root, 'history', '--rule', 'bucket-versioning-enabled', '--severity', 'medium')
            self.assertEqual(history.returncode, 0, history.stderr)
            self.assertEqual(json.loads(history.stdout)['total'], 1)
            comparison = self.cli(root, 'compare', before.id, after.id)
            self.assertEqual(comparison.returncode, 0, comparison.stderr)
            self.assertEqual(json.loads(comparison.stdout)['changes'][0]['change'], 'resolved')
            target = root / 'report.md'
            exported = self.cli(root, 'report', before.id, '--format', 'markdown', '--output', str(target))
            self.assertEqual(exported.returncode, 0, exported.stderr)
            self.assertIn('Recommendation', target.read_text())
            filtered = self.cli(root, 'report', before.id, '--severity', 'high')
            view = json.loads(filtered.stdout)
            self.assertTrue(view['is_filtered_view'])
            self.assertEqual(view['results'], [])
            canonical = self.cli(root, 'report', before.id)
            self.assertEqual(len(json.loads(canonical.stdout)['results']), 1)

    def test_failed_run_is_visible_and_cannot_be_compared_as_clean_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = SqliteReportRepository(root / 'data' / 'audit.sqlite3')
            report = version_report('Disabled')
            repo.save(report)
            failed = repo.record_failure('lab', ('bucket-versioning-enabled',), (), 'cloud_request_failed')
            result = self.cli(root, 'history', '--run-status', 'failed')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['entries'][0]['run_status'], 'failed')
            comparison = self.cli(root, 'compare', report.id, failed)
            self.assertEqual(comparison.returncode, 2)
            self.assertNotIn('resolved', comparison.stdout)


class Iteration08FailedAuditTests(unittest.TestCase):
    def test_cloud_failure_is_recorded_by_live_cli_without_a_clean_report(self):
        import contextlib
        import io
        from unittest.mock import patch
        from cloud_audit.cli import main
        from cloud_audit.infrastructure.s3 import S3Provider
        from test_configuration_snapshot import configured_client, failure
        client = configured_client()
        client.get_bucket_acl.side_effect = failure('NoSuchBucket')
        provider = S3Provider(client, namespace='https://example.invalid')
        with tempfile.TemporaryDirectory() as directory, \
             patch.dict(os.environ, {'CLOUD_AUDIT_STATE_DIR': directory, 'AWS_ACCESS_KEY_ID': 'fake', 'AWS_SECRET_ACCESS_KEY': 'fake'}), \
             patch('sys.argv', ['cloud-audit', 'audit', '--profile', 'vk', '--resource', 'missing']), \
             patch.object(S3Provider, 'from_settings', return_value=provider), \
             contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            try:
                main()
            finally:
                repo = SqliteReportRepository(Path(directory) / 'data' / 'audit.sqlite3')
                page = repo.history(HistoryQuery(run_status='failed'))
                self.assertEqual(page.total, 1)
                self.assertEqual(page.entries[0].status_counts, {})
                self.assertEqual(page.entries[0].error_code, 'cloud_request_failed')
        self.assertEqual(caught.exception.code, 2)
