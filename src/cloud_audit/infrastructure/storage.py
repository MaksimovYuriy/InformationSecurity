from pathlib import Path
import tempfile


class LocalStateStorage:
    def __init__(self, root: Path):
        self._root = root

    def prepare(self) -> None:
        for path in (self._root, self._root / 'data', self._root / 'logs'):
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.chmod(0o700)
            with tempfile.TemporaryFile(dir=path):
                pass
