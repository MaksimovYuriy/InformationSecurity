import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cloud_audit.infrastructure.configuration import ConfigurationError, load_settings
from cloud_audit.application.environment import EnvironmentService
from cloud_audit.infrastructure.storage import LocalStateStorage


class BootstrapTests(unittest.TestCase):
    def test_defaults_are_local_and_safe(self):
        settings = load_settings({})
        self.assertEqual(settings.environment, 'development')
        self.assertEqual(settings.log_level, 'INFO')

    def test_invalid_configuration_does_not_expose_value(self):
        secret = 'sensitive-value'
        with self.assertRaises(ConfigurationError) as error:
            load_settings({'CLOUD_AUDIT_LOG_LEVEL': secret})
        self.assertNotIn(secret, str(error.exception))

    def test_environment_check_creates_private_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = load_settings({'CLOUD_AUDIT_STATE_DIR': directory + '/state'})
            result = EnvironmentService(settings, LocalStateStorage(settings.state_dir)).check()
            self.assertEqual(result.status, 'ok')
            for name in ('data', 'logs'):
                path = Path(directory, 'state', name)
                self.assertTrue(path.is_dir())
                self.assertEqual(path.stat().st_mode & 0o777, 0o700)

    def test_cli_reports_version_and_configuration_without_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            environment = dict(os.environ, CLOUD_AUDIT_STATE_DIR=directory,
                               CLOUD_AUDIT_TOKEN='never-print-this')
            result = subprocess.run([sys.executable, '-m', 'cloud_audit', 'check'],
                                    capture_output=True, text=True, env=environment)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('development', result.stdout)
            self.assertIn('0.1.0', result.stdout)
            self.assertNotIn('never-print-this', result.stdout + result.stderr)

    def test_cli_configuration_error_has_nonzero_exit(self):
        result = subprocess.run([sys.executable, '-m', 'cloud_audit', 'check'],
                                capture_output=True, text=True,
                                env=dict(os.environ, CLOUD_AUDIT_LOG_LEVEL='secret-invalid'))
        self.assertEqual(result.returncode, 2)
        self.assertNotIn('secret-invalid', result.stdout + result.stderr)
