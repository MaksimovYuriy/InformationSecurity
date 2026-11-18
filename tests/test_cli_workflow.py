import json
import os
import subprocess
import sys
import tempfile
import unittest


class ConsoleWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

    def run_cli(self, *arguments):
        return subprocess.run([sys.executable, '-m', 'cloud_audit', *arguments],
                              capture_output=True, text=True,
                              env=dict(os.environ, CLOUD_AUDIT_STATE_DIR=self.directory.name))

    def test_demo_workflow_persists_report_between_processes(self):
        connection = self.run_cli('connection', '--profile', 'demo')
        self.assertEqual(connection.returncode, 0, connection.stderr)
        self.assertEqual(json.loads(connection.stdout)['mode'], 'demo')
        resources = self.run_cli('resources', '--profile', 'demo')
        self.assertEqual(resources.returncode, 0, resources.stderr)
        resource = json.loads(resources.stdout)['resources'][0]['id']
        audit = self.run_cli('audit', '--profile', 'demo', '--resource', resource,
                             '--rules', 'demo-public-read')
        self.assertEqual(audit.returncode, 0, audit.stderr)
        report = json.loads(audit.stdout)
        self.assertEqual(report['mode'], 'demo')
        self.assertEqual(report['results'][0]['status'], 'simulated')
        saved = self.run_cli('report', report['id'])
        self.assertEqual(saved.returncode, 0, saved.stderr)
        self.assertEqual(json.loads(saved.stdout), report)
        text = self.run_cli('report', report['id'], '--format', 'text')
        self.assertEqual(text.returncode, 0, text.stderr)
        self.assertIn('DEMO', text.stdout)

    def test_invalid_inputs_fail_without_traceback(self):
        for arguments in [('resources', '--profile', 'real'),
                          ('audit', '--resource', 'missing'),
                          ('audit', '--resource', 'demo-private', '--rules', 'unknown'),
                          ('report', '../outside'), ('report', 'a' * 32)]:
            with self.subTest(arguments=arguments):
                result = self.run_cli(*arguments)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('Traceback', result.stderr)

    def test_demo_requires_target_and_cli_rejects_unknown_format(self):
        self.assertEqual(self.run_cli('audit').returncode, 2)
        self.assertEqual(self.run_cli('resources', '--format', 'xml').returncode, 2)
