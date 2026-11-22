"""Run only iteration 9 acceptance tests and save a private timing summary."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import time
import unittest
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))


class TimedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.measurements = []

    def startTest(self, test):
        self.started = time.perf_counter()
        self.previous_errors = len(self.errors) + len(self.failures)
        super().startTest(test)

    def stopTest(self, test):
        self.measurements.append({'test': test.id(), 'seconds': round(time.perf_counter() - self.started, 6),
                                  'successful': len(self.errors) + len(self.failures) == self.previous_errors})
        super().stopTest(test)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='New JSON file; existing files are never overwritten')
    args = parser.parse_args()
    os.chdir(ROOT)
    target = args.output or ROOT / '.state' / 'data' / f'iteration09-tests-{uuid4().hex}.json'
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Reserve before running tests, so an invalid target cannot discard the results.
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as output:
        start = time.perf_counter()
        suite = unittest.defaultTestLoader.discover(str(ROOT / 'tests'), pattern='test_iteration09_*.py')
        result = unittest.TextTestRunner(verbosity=2, resultclass=TimedResult).run(suite)
        json.dump({'iteration': 9, 'checked_at': datetime.now(timezone.utc).isoformat(),
                   'pattern': 'test_iteration09_*.py', 'full_suite_run': False,
                   'successful': result.wasSuccessful(), 'test_methods': result.testsRun,
                   'failures': len(result.failures), 'errors': len(result.errors),
                   'seconds': round(time.perf_counter() - start, 6), 'measurements': result.measurements}, output, indent=2)
        output.write('\n')
    print(json.dumps({'summary_path': str(target), 'successful': result.wasSuccessful()}))
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
