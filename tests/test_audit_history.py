from dataclasses import replace
from pathlib import Path
import sqlite3
import tempfile
import unittest

from cloud_audit.errors import AuditError
from cloud_audit.models.history import HistoryQuery
from cloud_audit.storage.sqlite import SqliteReportRepository
from cloud_audit.storage.json_reports import JsonReportRepository
from audit_fixtures import version_report


class StorageTests(unittest.TestCase):
    def test_persists_report_parameters_and_findings_across_connections_with_private_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'audit.sqlite3'
            report = version_report('Disabled')
            SqliteReportRepository(path).save(report)
            other = SqliteReportRepository(path)
            self.assertEqual(other.get(report.id), report)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with sqlite3.connect(path) as connection:
                self.assertEqual(connection.execute('select count(*) from runs').fetchone()[0], 1)
                self.assertEqual(connection.execute('select count(*) from run_rules').fetchone()[0], 1)
            self.assertEqual(other.history(HistoryQuery()).entries[0].resource.id, 'lab')

    def test_filters_match_same_finding_and_support_pagination(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = SqliteReportRepository(Path(directory) / 'audit.sqlite3')
            before, after = version_report('Disabled'), version_report('Enabled', 1)
            repo.save(before)
            repo.save(after)
            page = repo.history(HistoryQuery(rule_id='bucket-versioning-enabled', severity='medium'))
            self.assertEqual([x.id for x in page.entries], [before.id])
            self.assertEqual(repo.history(HistoryQuery(resource_id="lab' OR 1=1 --")).total, 0)
            self.assertEqual(repo.history(HistoryQuery(limit=1)).total, 2)
            self.assertEqual(repo.history(HistoryQuery(limit=1, offset=1)).entries[0].id, before.id)
            with self.assertRaises(AuditError):
                repo.history(HistoryQuery(limit=-1))

    def test_legacy_import_is_explicit_idempotent_and_does_not_delete_json(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = version_report('Disabled')
            legacy = JsonReportRepository(root)
            legacy.save(report)
            repo = SqliteReportRepository(root / 'audit.sqlite3', legacy=legacy)
            self.assertEqual(repo.get(report.id), report)
            self.assertEqual(repo.history(HistoryQuery()).total, 0)
            self.assertEqual(repo.import_legacy()['imported'], 1)
            self.assertEqual(repo.import_legacy()['imported'], 0)
            self.assertTrue((root / (report.id + '.json')).exists())
            self.assertEqual(repo.history(HistoryQuery()).total, 1)

    def test_conflicting_id_is_rejected_and_database_keeps_original(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = SqliteReportRepository(Path(directory) / 'audit.sqlite3')
            before = version_report('Disabled')
            repo.save(before)
            repo.save(before)
            changed = replace(version_report('Enabled', 1), id=before.id)
            with self.assertRaises(AuditError):
                repo.save(changed)
            self.assertEqual(repo.get(before.id), before)

    def test_failed_run_is_recorded_without_fabricated_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = SqliteReportRepository(Path(directory) / 'audit.sqlite3')
            run_id = repo.record_failure('lab', ('anonymous-read',), ('test.txt',), 'cloud_request_failed')
            entry = repo.history(HistoryQuery(run_status='failed')).entries[0]
            self.assertEqual(entry.id, run_id)
            self.assertEqual(entry.run_status, 'failed')
            self.assertEqual(entry.selected_rules, ('anonymous-read',))
            self.assertEqual(entry.status_counts, {})
            with self.assertRaisesRegex(AuditError, 'failed'):
                repo.get(run_id)

    def test_corrupt_database_and_unsupported_version_have_controlled_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'audit.sqlite3'
            path.write_bytes(b'not a database')
            with self.assertRaises(OSError):
                SqliteReportRepository(path).history(HistoryQuery())
            path.unlink()
            with sqlite3.connect(path) as connection:
                connection.execute('pragma user_version=999')
            with self.assertRaises(AuditError):
                SqliteReportRepository(path).history(HistoryQuery())


class TransactionTests(unittest.TestCase):
    def test_database_failure_rolls_back_run_and_findings_without_exposing_sql_message(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'audit.sqlite3'
            repo = SqliteReportRepository(path)
            original = version_report('Enabled')
            repo.save(original)
            with sqlite3.connect(path) as connection:
                connection.execute("CREATE TRIGGER reject_findings BEFORE INSERT ON run_rules BEGIN SELECT RAISE(ABORT, 'SECRET'); END")
            candidate = version_report('Disabled', 1)
            with self.assertRaises(OSError) as caught:
                repo.save(candidate)
            self.assertNotIn('SECRET', str(caught.exception))
            self.assertEqual(repo.history(HistoryQuery()).total, 1)
            self.assertEqual(repo.get(original.id), original)


class HistoryIntegrityTests(unittest.TestCase):
    def test_rule_and_severity_must_match_the_same_finding(self):
        from cloud_audit.rules.risk import RiskModel
        with tempfile.TemporaryDirectory() as directory:
            repo = SqliteReportRepository(Path(directory) / 'audit.sqlite3')
            report = version_report('Disabled')
            other = replace(report.results[0], rule_id='other-rule',
                            risk=RiskModel().assess('confirmed_violation', 'high'))
            repo.save(replace(report, results=(*report.results, other)))
            self.assertEqual(repo.history(HistoryQuery(rule_id='bucket-versioning-enabled', severity='high')).total, 0)
            self.assertEqual(repo.history(HistoryQuery(rule_id='other-rule', severity='high')).total, 1)

    def test_invalid_legacy_file_is_reported_and_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            identifier = 'a' * 32
            (root / (identifier + '.json')).write_text('broken JSON')
            repo = SqliteReportRepository(root / 'audit.sqlite3', legacy=JsonReportRepository(root))
            result = repo.import_legacy()
            self.assertEqual(result['skipped'], [identifier])
            self.assertEqual(repo.history(HistoryQuery()).total, 0)
            self.assertTrue((root / (identifier + '.json')).exists())

    def test_history_path_cannot_follow_a_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'original'
            target.write_text('preserve me')
            link = root / 'audit.sqlite3'
            link.symlink_to(target)
            with self.assertRaises(AuditError):
                SqliteReportRepository(link).history(HistoryQuery())
            self.assertEqual(target.read_text(), 'preserve me')
