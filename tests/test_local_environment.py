"""Local dotenv is data, never shell code, and installed entry points use the same configuration."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cloud_audit.configuration.dotenv import load_environment
from cloud_audit.errors import ConfigurationError

ROOT = Path(__file__).resolve().parents[1]


class LocalEnvironmentTests(unittest.TestCase):
    def test_optional_file_and_process_environment_take_precedence_without_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'.env'
            original = {'CLOUD_AUDIT_ENV': 'test', 'EMPTY': ''}
            self.assertEqual(load_environment(original, path), original)
            path.write_text('CLOUD_AUDIT_ENV=production\nEMPTY=from-file\nLOCAL=value\n')
            self.assertEqual(load_environment(original, path), dict(original, LOCAL='value'))
            self.assertEqual(original, {'CLOUD_AUDIT_ENV': 'test', 'EMPTY': ''})

    def test_quotes_comments_and_shell_expressions_are_literal(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'.env'
            marker = Path(directory)/'must-not-exist'
            path.write_text('export FIRST="value # literal" # comment\nSECOND=abc#def\nTHIRD=plain # comment\n'
                            + "COMMENT_ONLY= # comment\nSINGLE='literal $FIRST'\nCOMMAND=$(touch " + str(marker) + ')\n')
            env = load_environment({}, path)
            self.assertEqual(env['FIRST'], 'value # literal')
            self.assertEqual(env['SECOND'], 'abc#def')
            self.assertEqual(env['THIRD'], 'plain')
            self.assertEqual(env['COMMENT_ONLY'], '')
            self.assertEqual(env['SINGLE'], 'literal $FIRST')
            self.assertTrue(env['COMMAND'].startswith('$(touch '))
            self.assertFalse(marker.exists())

    def test_invalid_or_oversized_file_never_exposes_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'.env'
            for text in ('SECRET="synthetic-secret', 'invalid synthetic-secret', 'SECRET=x\n' * 10000):
                path.write_text(text)
                with self.subTest(length=len(text)), self.assertRaises(ConfigurationError) as caught:
                    load_environment({}, path)
                self.assertNotIn('synthetic-secret', str(caught.exception))
            with self.assertRaises(ConfigurationError):
                load_environment({}, Path(directory)/'missing', required=True)


class LocalEnvironmentCliTests(unittest.TestCase):
    def cli(self, directory, *args):
        env = {k:v for k,v in os.environ.items() if not k.startswith(('CLOUD_AUDIT_', 'AWS_'))}
        env['PYTHONPATH'] = str(ROOT/'src')
        return subprocess.run([sys.executable, '-m', 'cloud_audit', *args], cwd=directory, env=env,
                              capture_output=True, text=True, timeout=30)

    def test_check_loads_current_directory_file_and_explicit_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'.env').write_text('CLOUD_AUDIT_ENV=test\nCLOUD_AUDIT_STATE_DIR=local-state\nAWS_SECRET_ACCESS_KEY=synthetic-secret\n')
            result = self.cli(directory, 'check')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['environment'], 'test')
            self.assertTrue((root/'local-state/data').is_dir())
            self.assertNotIn('synthetic-secret', result.stdout + result.stderr)
            result = self.cli(directory, '--no-env-file', 'check')
            self.assertEqual(json.loads(result.stdout)['environment'], 'development')
            (root/'custom.env').write_text('CLOUD_AUDIT_ENV=production\n')
            result = self.cli(directory, '--env-file', 'custom.env', 'check')
            self.assertEqual(json.loads(result.stdout)['environment'], 'production')

    def test_help_and_version_ignore_invalid_dotenv_and_missing_explicit_file_is_controlled(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory)/'.env').write_text('invalid synthetic-secret')
            for args in (('--version',), ('--help',), ('scan','--help')):
                result = self.cli(directory, *args)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn('synthetic-secret', result.stdout + result.stderr)
            result = self.cli(directory, '--env-file', 'missing.env', 'check')
            self.assertEqual(result.returncode, 2)
            self.assertNotIn('Traceback', result.stderr)


@unittest.skipUnless(Path(sys.executable).with_name('cloud-audit').exists(), 'Install the package to test its console entry point')
class InstalledCommandTests(unittest.TestCase):
    def run_installed(self, launcher):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'.env').write_text('CLOUD_AUDIT_ENV=test\nCLOUD_AUDIT_STATE_DIR=private-state\n')
            env = {k:v for k,v in os.environ.items() if not k.startswith(('CLOUD_AUDIT_', 'AWS_')) and k != 'PYTHONPATH'}
            env['PATH'] = str(Path(sys.executable).parent) + os.pathsep + env.get('PATH', '')
            process = subprocess.run([launcher, 'check'], cwd=directory, env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertEqual(json.loads(process.stdout)['environment'], 'test')
            self.assertTrue((root/'private-state/data').is_dir())

    def test_installed_command_runs_without_pythonpath(self):
        self.run_installed('cloud-audit')

    def test_project_launcher_runs_without_activation(self):
        self.run_installed(str(ROOT/'cloud-audit'))
