"""Human-readable exports; report filtering never changes stored evidence."""
from dataclasses import asdict
from html import escape
import json
import os
from pathlib import Path
import re


def report_view(report, *, rule_id=None, severity=None, status=None):
    data = asdict(report)
    filters = {key: value for key, value in {'rule_id': rule_id, 'severity': severity, 'status': status}.items()
               if value is not None}
    if filters:
        data['is_filtered_view'] = True
        data['view_filters'] = filters
        data['full_result_count'] = len(data['results'])
        data['results'] = [row for row in data['results'] if
            (rule_id is None or row['rule_id'] == rule_id) and
            (severity is None or row.get('risk', {}).get('level', 'unknown') == severity) and
            (status is None or row['status'] == status)]
    return data


def safe(value):
    text = escape(str(value) if value is not None else '—', quote=True).replace('\n', ' ').replace('\r', ' ')
    return re.sub(r'([\\`*_{}\[\]()#!|])', r'\\\1', text)


def code(value):
    text = json.dumps(value, ensure_ascii=False, indent=2)
    longest = max((len(run) for run in re.findall(r'`+', text)), default=0)
    fence = '`' * max(3, longest + 1)
    return f'{fence}json\n{text}\n{fence}'


def render_markdown(data):
    if 'changes' in data:
        lines = ['# Audit comparison', '', f"Before: {safe(data['before_id'])}", '', f"After: {safe(data['after_id'])}",
                 '', f"Observed: {safe(data['before_observed_at'])} → {safe(data['after_observed_at'])}", '',
                 f"Comparable: {safe(data['comparable'])}", '', 'Reasons: ' + safe(', '.join(data['reasons'])), '',
                 '| Rule | Change | Before | After | Reason |', '|---|---|---|---|---|']
        for row in data['changes']:
            lines.append('| ' + ' | '.join(safe(value) for value in (row['rule_id'], row['change'],
                (row['before'] or {}).get('status'), (row['after'] or {}).get('status'), row['reason'])) + ' |')
        lines += ['', '## Scope and policy', '', code({'before': data['before_context'], 'after': data['after_context']})]
        for row in data['changes']:
            lines += ['', '## ' + safe(row['rule_id']), '', code({'before': row['before'], 'after': row['after']})]
        return '\n'.join(lines) + '\n'
    if 'entries' in data:
        lines = ['# Audit history', '', f"Total matching runs: {data['total']}; limit={data['limit']}, offset={data['offset']}", '',
                 '| Run | Namespace | Resource | Observation / recorded time | Status | Findings | Error |', '|---|---|---|---|---|---|---|']
        for row in data['entries']:
            lines.append('| ' + ' | '.join(safe(value) for value in (row['id'], row.get('resource_namespace'), row['resource']['id'],
                row['observed_at'] or row['recorded_at'], row['run_status'], json.dumps(row['status_counts']), row['error_code'])) + ' |')
        return '\n'.join(lines) + '\n'
    if 'results' not in data:
        return '# Audit data\n\n' + code(data) + '\n'
    lines = ['# Cloud audit report', '', f"Report: {safe(data['id'])}", '',
             f"Resource: {safe(data['resource']['id'])}", '', f"Mode: {safe(data['mode'])}", '',
             f"Endpoint namespace: {safe(data.get('resource_namespace'))}", '',
             f"Ruleset version: {safe(data.get('ruleset_version'))}", '',
             f"Observed: {safe(data.get('snapshot_collected_at'))}", '', f"Evaluated: {safe(data.get('evaluated_at'))}", '',
             f"Scope: {safe(data.get('scope', 'demo'))}", '',
             f"Collection: {safe(data.get('collection_status'))}; evaluation: {safe(data.get('evaluation_status'))}", '',
             '## Limitations', '', code(data.get('limitations', []))]
    if data.get('is_filtered_view'):
        lines += ['', f"Filtered view: {len(data['results'])} of {data['full_result_count']} results; stored report unchanged.",
                  '', code(data['view_filters'])]
    lines += ['', '| Rule | Result | Risk | Score | Accepted exception |', '|---|---|---|---|---|']
    for row in data['results']:
        risk = row.get('risk', {})
        lines.append('| ' + ' | '.join(safe(value) for value in (row['rule_id'], row['status'], risk.get('level'),
            risk.get('score'), row.get('exception_reason'))) + ' |')
    for row in data['results']:
        lines += ['', '## ' + safe(row['rule_id']), '', safe(row['explanation']), '',
                  '**Recommendation:** ' + safe(row.get('recommendation')), '',
                  '**Verification:** ' + safe(row.get('verification')), '', '**Evidence:**', '', code(row.get('evidence', [])),
                  '', '**Rule limitations:**', '', code(row.get('limitations', []))]
    if 'policy' in data:
        lines += ['', '## Audit policy', '', code(data['policy'])]
    return '\n'.join(lines) + '\n'


def write_document(path: Path, content: str) -> None:
    # Exclusive creation protects existing reports, configuration and other user files.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as file:
            file.write(content)
            file.flush()
            os.fsync(file.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
