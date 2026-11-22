"""Читаемая общая сводка ступенчатого запуска и полные доказательства каждого бакета."""


def render_scan(data, safe, code):
    """Разделяет статусы операций и внутреннего анализа; выводит ограничения и остаточные цели."""
    lines = ['# Staged storage scan', '', 'Run: ' + safe(data['id']), '', 'Endpoint: ' + safe(data['namespace']), '',
             'Started: ' + safe(data['started_at']), '', 'Completed: ' + safe(data['completed_at']), '',
             'Incomplete: ' + safe(data['incomplete']), '', 'Selection: ' + safe(data['selection_status']), '',
             '| Bucket | List | Get | Write | Delete | Internal | Report |', '|---|---|---|---|---|---|---|']
    for row in data['buckets']:
        states = {item['rule_id']: item['status'] for item in row['external_findings']}
        values = [row['bucket'], *(states.get('anonymous-' + op, 'not_tested') for op in ('list', 'read', 'write', 'delete')),
                  row['internal_status'], row['internal_report_id']]
        lines.append('| ' + ' | '.join(safe(value) for value in values) + ' |')
    lines += ['', '## Selection errors', '', code(data['errors'])]
    for row in data['buckets']:
        lines += ['', '## ' + safe(row['bucket']), '', code(row)]
    return '\n'.join(lines) + '\n'
