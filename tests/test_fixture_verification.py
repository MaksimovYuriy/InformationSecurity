"""Cloud policy changes may settle asynchronously; the training fixture retries within a fixed bound."""
import contextlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts.verify_public_access import main


def stage(opened):
    """Return a synthetic snapshot/report pair for independently confirmed read/list access."""
    allowed = opened == 'open'
    mismatch = opened == 'partial'
    states = {'anonymous-read': 'confirmed_violation' if allowed or mismatch else 'passed',
              'anonymous-list': 'confirmed_violation' if allowed else 'potential_risk' if mismatch else 'passed',
              'anonymous-write': 'passed', 'anonymous-delete': 'passed'}
    data = SimpleNamespace(id='a' * 32, observations=(
        SimpleNamespace(name='anonymous_read:sample', data={'outcome': 'allowed' if allowed or mismatch else 'denied'}),
        SimpleNamespace(name='anonymous_list', data={'outcome': 'allowed' if allowed else 'denied'})))
    report = SimpleNamespace(id='b' * 32, results=tuple(SimpleNamespace(rule_id=key, status=value) for key, value in states.items()))
    return data, report


class FixtureVerificationTests(unittest.TestCase):
    def run_fixture(self, phases):
        pairs = [stage(phase) for phase in phases]
        provider = Mock()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (patch('scripts.verify_public_access.S3Provider.from_settings', return_value=provider),
                  patch('scripts.verify_public_access.load_s3_settings', return_value=Mock()),
                  patch('scripts.verify_public_access.Path', return_value=root),
                  patch('scripts.verify_public_access.SnapshotService') as snapshots,
                  patch('scripts.verify_public_access.SecurityAuditService') as audits,
                  patch('scripts.verify_public_access.sleep', create=True) as sleep,
                  patch('sys.argv', ['fixture', '--run-training-fixture']),
                  contextlib.redirect_stdout(io.StringIO())):
                snapshots.return_value.collect.side_effect = [pair[0] for pair in pairs]
                audits.return_value.audit.side_effect = [pair[1] for pair in pairs]
                code = main()
                summary = json.loads(next((root / 'data').glob('fixture-*.json')).read_text())
                calls = audits.return_value.audit.call_count
            provider._client.delete_bucket.assert_called_once()
            return code, summary, calls, sleep.call_count

    def test_partial_publication_retries_without_losing_attempt_evidence(self):
        code, summary, calls, waits = self.run_fixture(['closed', 'partial', 'open', 'closed'])
        self.assertEqual(code, 0)
        self.assertTrue(summary['success'])
        self.assertTrue(summary['cleanup_ok'])
        self.assertEqual(summary['stage_count'], 3)
        self.assertEqual(summary['attempt_count'], 4)
        self.assertEqual(calls, 4)
        self.assertEqual(waits, 1)

    def test_closure_retries_until_new_unsigned_requests_deny_access(self):
        code, summary, calls, waits = self.run_fixture(['closed', 'open', 'open', 'closed'])
        self.assertEqual(code, 0)
        self.assertEqual(summary['stages'][-1]['anonymous_requests']['anonymous_list'], 'denied')
        self.assertEqual(calls, 4)
        self.assertEqual(waits, 1)

    def test_exhausted_attempts_fail_and_cleanup_is_still_attempted(self):
        code, summary, calls, waits = self.run_fixture(['closed'] + ['partial'] * 5)
        self.assertEqual(code, 2)
        self.assertFalse(summary['success'])
        self.assertTrue(summary['cleanup_ok'])
        self.assertEqual(calls, 6)
        self.assertEqual(waits, 4)
