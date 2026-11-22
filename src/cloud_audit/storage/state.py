"""Готовит выделенные каталоги состояния с правами 0700 и проверяет возможность записи."""
from pathlib import Path
import tempfile


class LocalStateStorage:
    """Файловая реализация подготовки выделенного каталога состояния."""
    def __init__(self, root: Path):
        """
        Сохраняет переданные зависимости и параметры экземпляра; конкретные внешние действия
        выполняются отдельными методами.
        """
        self._root = root

    def prepare(self) -> None:
        """
        Создаёт/закрывает root,data,logs до 0700 и проверяет возможность временной записи в каждом
        каталоге.
        """
        for path in (self._root, self._root / 'data', self._root / 'logs'):
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.chmod(0o700)
            with tempfile.TemporaryFile(dir=path):
                pass
