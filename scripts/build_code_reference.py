"""Build the complete source reference from AST and checked-in module/function docstrings."""
import argparse
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'docs' / 'CODE_REFERENCE.md'


def render_module(path: Path) -> list[str]:
    """Describe a source file, its imports, constants, classes, fields and every named function."""
    tree = ast.parse(path.read_text(encoding='utf-8'))
    relative = path.relative_to(ROOT).as_posix()
    lines = [f'## `{relative}`', '', ast.get_docstring(tree) or 'Модуль без описания.', '',
             f'[Исходный файл](../{relative})', '']
    dependencies = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            dependencies.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            dependencies.append('.' * node.level + (node.module or ''))
    if dependencies:
        lines += ['Зависимости: ' + ', '.join(f'`{name}`' for name in dict.fromkeys(dependencies)) + '.', '']

    def definitions(nodes, prefix=''):
        """Recursively render class fields, methods and local named helpers without executing source."""
        for node in nodes:
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                names = [target.id for target in targets if isinstance(target, ast.Name)]
                if not names:
                    continue
                annotation = ': ' + ast.unparse(node.annotation) if isinstance(node, ast.AnnAssign) else ''
                value = ' = ' + ast.unparse(node.value) if node.value is not None else ''
                for name in names:
                    lines.extend([f'Поле/константа `{prefix + name}`:', '', '```python', name + annotation + value, '```', ''])
            elif isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                name = prefix + node.name
                kind = 'Класс' if isinstance(node, ast.ClassDef) else 'Функция/метод'
                lines.extend([f'### {kind} `{name}`', '',
                              f'[Определение](../{relative}#L{node.lineno})', '',
                              ast.get_docstring(node) or 'Описание отсутствует.', ''])
                if isinstance(node, ast.ClassDef):
                    bases = ', '.join(ast.unparse(base) for base in node.bases)
                    if bases:
                        lines.extend(['Базовые классы: `' + bases + '`.', ''])
                    definitions(node.body, name + '.')
                else:
                    signature = f'def {node.name}({ast.unparse(node.args)})'
                    if node.returns:
                        signature += ' -> ' + ast.unparse(node.returns)
                    lines.extend(['```python', signature, '```', ''])
                    # Local named helpers are also documented; ordinary assignments are implementation details.
                    definitions([child for child in node.body if isinstance(child, (ast.FunctionDef, ast.ClassDef))], name + '.')
    definitions(tree.body)
    return lines


def build_reference() -> str:
    """Read only tracked-style Python source locations; configuration and runtime state are never scanned."""
    paths = sorted((ROOT / 'src' / 'cloud_audit').rglob('*.py')) + sorted((ROOT / 'scripts').glob('*.py'))
    lines = ['# Полный справочник исходного кода', '',
             'Справочник включает каждый Python-модуль приложения и каждый поддерживаемый скрипт, все явно объявленные классы, функции, методы, поля моделей и константы. '
             'Он строится из фактического AST и docstring; импорт модулей и обращение к облаку не выполняются. '
             'Локальные переменные и lambda описываются алгоритмом содержащего метода.', '',
             'Причины архитектурных решений: [ARCHITECTURE.md](ARCHITECTURE.md). '
             'Модели и форматы: [DATA_CONTRACTS.md](DATA_CONTRACTS.md). '
             'Правила и порядок сканирования: [SCANNING.md](SCANNING.md).', '',
             'Обновление: `.venv/bin/python scripts/build_code_reference.py`; проверка актуальности: добавить `--check`.', '']
    for path in paths:
        lines.extend(render_module(path))
    return '\n'.join(lines).rstrip() + '\n'


def main() -> int:
    """Regenerate CODE_REFERENCE.md, or return a nonzero code if --check finds it stale."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    content = build_reference()
    if args.check:
        if not TARGET.exists() or TARGET.read_text(encoding='utf-8') != content:
            print('CODE_REFERENCE.md is missing or stale; regenerate it with scripts/build_code_reference.py')
            return 1
        print('Code reference is up to date')
        return 0
    TARGET.write_text(content, encoding='utf-8')
    print('Updated docs/CODE_REFERENCE.md')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
