from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

from cloud_audit.reports.formatting import report_view, render_markdown, write_document
from audit_fixtures import version_report


class FormattingTests(unittest.TestCase):
    def test_filtered_view_is_explicit_and_does_not_change_original_report(self):
        report = version_report('Disabled')
        view = report_view(report, severity='high')
        self.assertEqual(view['results'], [])
        self.assertTrue(view['is_filtered_view'])
        self.assertEqual(view['full_result_count'], 1)
        self.assertEqual(report.results[0].status, 'confirmed_violation')
        self.assertEqual(view['evaluation_status'], report.evaluation_status)

    def test_markdown_has_evidence_recommendation_time_and_escapes_cloud_content(self):
        report = version_report('Disabled')
        hostile = replace(report.results[0], explanation='<script>alert(1)</script> [click](javascript:bad)')
        report = replace(report, results=(hostile,))
        markdown = render_markdown(report_view(report))
        self.assertIn(report.snapshot_collected_at, markdown)
        self.assertIn('get_bucket_versioning', markdown)
        self.assertIn('Verification', markdown)
        self.assertIn('Recommendation', markdown)
        self.assertNotIn('<script>', markdown)
        self.assertNotIn('[click](javascript:bad)', markdown)

    def test_document_is_private_and_existing_file_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.md'
            write_document(path, 'report')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(OSError):
                write_document(path, 'replacement')
            self.assertEqual(path.read_text(), 'report')
