"""
Контролируемые ошибки запроса и конфигурации; сообщения не должны раскрывать ключи и исходные ответы
SDK.
"""


class AuditError(ValueError):
    """Invalid audit request, unavailable resource or inconsistent saved evidence."""


class ConfigurationError(ValueError):
    """Invalid configuration; messages never include supplied values."""
