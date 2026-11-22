from dataclasses import asdict
import json
import os
from pathlib import Path
import re
import tempfile

from cloud_audit.application.audit import AuditError
from cloud_audit.domain.audit import AuditReport, Resource, RuleResult
from cloud_audit.domain.rules import SecurityReport
from cloud_audit.infrastructure.security_report_schema import decode_security_report


class JsonReportRepository:
    def __init__(self, directory: Path):
        self._directory = directory

    def _path(self, report_id: str) -> Path:
        if not re.fullmatch(r'[0-9a-f]{32}', report_id):
            raise AuditError('Invalid report identifier')
        return self._directory / f'{report_id}.json'

    def save(self, report: AuditReport | SecurityReport) -> None:
        destination = self._path(report.id)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8',
                                             dir=self._directory, delete=False) as file:
                temporary = Path(file.name)
                json.dump(asdict(report), file)
            os.replace(temporary, destination)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def get(self, report_id: str) -> AuditReport | SecurityReport:
        path = self._path(report_id)
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
            if data.get('mode') == 'vk':
                if data['id'] != report_id:
                    raise ValueError
                return decode_security_report(data)
            report = AuditReport(data['id'], data['mode'], Resource(**data['resource']),
                                 tuple(RuleResult(**item) for item in data['results']))
            if report.id != report_id or report.mode != 'demo':
                raise ValueError
            return report
        except FileNotFoundError:
            raise AuditError('Report not found') from None
        except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
            raise AuditError('Invalid saved report') from None
