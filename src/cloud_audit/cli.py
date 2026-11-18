import argparse
from dataclasses import asdict
import json
import logging
import os

from cloud_audit import __version__
from cloud_audit.application.environment import EnvironmentService
from cloud_audit.infrastructure.configuration import ConfigurationError, load_settings
from cloud_audit.infrastructure.storage import LocalStateStorage


def main() -> int:
    parser = argparse.ArgumentParser(description='Cloud storage audit environment')
    parser.add_argument('--version', action='version', version=__version__)
    parser.add_argument('command', choices=['check'])
    parser.parse_args()
    try:
        settings = load_settings(os.environ)
        logging.basicConfig(level=settings.log_level, format='%(levelname)s %(message)s')
        report = EnvironmentService(settings, LocalStateStorage(settings.state_dir)).check()
    except ConfigurationError as error:
        parser.exit(2, f'Configuration error: {error}\n')
    except OSError:
        parser.exit(1, 'Environment error: cannot prepare private state directories\n')
    print(json.dumps({'version': __version__, **asdict(report)}))
    return 0
