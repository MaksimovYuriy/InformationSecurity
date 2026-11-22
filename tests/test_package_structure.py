"""The package is organized by responsibility and keeps external dependencies at its edges."""
import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / 'src' / 'cloud_audit'


class PackageStructureTests(unittest.TestCase):
    def test_feature_packages_replace_generic_layers(self):
        for name in ('models', 'rules', 'services', 'providers', 'storage', 'configuration', 'reports'):
            with self.subTest(package=name):
                self.assertTrue((PACKAGE / name / '__init__.py').is_file())
        for name in ('application', 'domain', 'infrastructure'):
            self.assertFalse((PACKAGE / name).exists())

    def test_models_and_rules_do_not_import_external_integrations(self):
        for name in ('models', 'rules'):
            for path in (PACKAGE / name).glob('*.py'):
                for node in ast.walk(ast.parse(path.read_text())):
                    modules = ([node.module or ''] if isinstance(node, ast.ImportFrom) else
                               [item.name for item in node.names] if isinstance(node, ast.Import) else [])
                    for module in modules:
                        with self.subTest(file=path.name, dependency=module):
                            self.assertFalse(module.startswith(('boto3', 'botocore', 'sqlite3',
                                'cloud_audit.providers', 'cloud_audit.storage', 'cloud_audit.services',
                                'cloud_audit.configuration', 'cloud_audit.cli')))

    def test_test_names_describe_the_subject(self):
        for path in (ROOT / 'tests').glob('test_*.py'):
            self.assertNotIn('iteration', path.name.lower())
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, (ast.ClassDef, ast.FunctionDef)):
                    self.assertNotIn('iteration', node.name.lower())

    def test_every_source_module_and_definition_has_documentation(self):
        paths = list(PACKAGE.rglob('*.py')) + list((ROOT / 'scripts').glob('*.py'))
        for path in paths:
            tree = ast.parse(path.read_text())
            with self.subTest(module=str(path.relative_to(ROOT))):
                self.assertTrue(ast.get_docstring(tree))
            for node in ast.walk(tree):
                if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                    with self.subTest(module=path.name, definition=node.name):
                        self.assertTrue(ast.get_docstring(node))
