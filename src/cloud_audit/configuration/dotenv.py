"""Локальный .env как данные: без shell, подстановок и изменения окружения процесса."""
from collections.abc import Mapping
from pathlib import Path
import re

from cloud_audit.errors import ConfigurationError

MAX_BYTES = 64 * 1024


def parse_value(raw: str) -> str:
    """Читает однострочное значение, кавычки и комментарий; $ и backtick остаются обычным текстом."""
    value = raw.strip()
    if not value or value.startswith('#'):
        return ''
    if value[0] not in {'"', "'"}:
        return re.split(r'\s+#', value, maxsplit=1)[0].rstrip()
    quote, result, index = value[0], [], 1
    escapes = {'n': '\n', 'r': '\r', 't': '\t', '\\': '\\', '"': '"'}
    while index < len(value):
        char = value[index]
        if char == quote:
            tail = value[index+1:].strip()
            if tail and not tail.startswith('#'):
                raise ValueError
            return ''.join(result)
        if char == '\\' and quote == '"' and index+1 < len(value):
            next_char = value[index+1]
            if next_char in escapes:
                result.append(escapes[next_char])
                index += 2
                continue
        result.append(char)
        index += 1
    raise ValueError


def load_environment(environment: Mapping[str, str], path: Path | None = Path('.env'), *, required=False) -> dict[str, str]:
    """Объединяет один выбранный файл с окружением; существующие переменные, включая пустые, приоритетны."""
    result = dict(environment)
    if path is None:
        return result
    try:
        with path.open('rb') as file:
            raw = file.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ConfigurationError('Environment file exceeds 64 KiB')
        text = raw.decode('utf-8-sig')
    except FileNotFoundError:
        if required:
            raise ConfigurationError('Environment file not found') from None
        return result
    except (OSError, UnicodeError):
        raise ConfigurationError('Cannot read environment file') from None
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith('#'):
            continue
        match = re.fullmatch(r'(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)', line)
        try:
            if match is None:
                raise ValueError
            value = parse_value(match.group(2))
            if '\0' in value:
                raise ValueError
            result.setdefault(match.group(1), value)
        except ValueError:
            raise ConfigurationError(f'Invalid environment file syntax at line {line_number}') from None
    return result
