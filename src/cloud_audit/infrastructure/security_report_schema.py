"""Reconstruction and consistency checks for version 1 security reports."""
from datetime import datetime
import re

from cloud_audit.domain.audit import Resource
from cloud_audit.domain.rules import Evidence, Finding, RiskAssessment, SecurityReport, FINDING_STATUSES
from cloud_audit.infrastructure.audit_policy import parse_audit_policy


def decode_security_report(data: dict) -> SecurityReport:
    if (type(data['schema_version']) is not int or data['schema_version'] != 1 or data['mode'] != 'vk'
            or not re.fullmatch(r'[0-9a-f]{32}', data['snapshot_id'])
            or data['scope'] != 'bucket_configuration_only'
            or data['collection_status'] not in {'partial', 'complete_for_scope'}):
        raise ValueError
    for key in ('snapshot_collected_at', 'evaluated_at'):
        if datetime.fromisoformat(data[key]).tzinfo is None:
            raise ValueError
    resource = Resource(**data['resource'])
    if not all(isinstance(x, str) and x for x in (resource.id, resource.name)):
        raise ValueError
    policy = parse_audit_policy(data['policy'])
    findings = []
    seen = set()
    for item in data['results']:
        risk = RiskAssessment(**(item['risk'] | {'affected_operations': tuple(item['risk']['affected_operations'])}))
        evidence = tuple(Evidence(**value) for value in item['evidence'])
        finding = Finding(**(item | {'risk': risk, 'evidence': evidence}))
        if not evidence and finding.status != 'not_applicable':
            raise ValueError
        if finding.rule_id in seen or not isinstance(finding.rule_id, str) or finding.status not in FINDING_STATUSES:
            raise ValueError
        seen.add(finding.rule_id)
        if any(not isinstance(x, str) for x in (finding.explanation, finding.recommendation, finding.verification)):
            raise ValueError
        if finding.exception_reason is not None and (
                not isinstance(finding.exception_reason, str) or not finding.exception_reason.strip()
                or finding.status not in {'confirmed_violation', 'potential_risk'}):
            raise ValueError
        if risk.model_version != 1 or not isinstance(risk.rationale, str):
            raise ValueError
        if finding.status == 'insufficient_data':
            if risk.level != 'unknown' or any(x is not None for x in (risk.score, risk.likelihood, risk.impact)):
                raise ValueError
        elif finding.status in {'passed', 'not_applicable'}:
            if risk.level != 'none' or (risk.score, risk.likelihood, risk.impact) != (0, 0, 0):
                raise ValueError
        else:
            if (type(risk.likelihood) is not int or type(risk.impact) is not int
                    or not 1 <= risk.likelihood <= 3 or not 1 <= risk.impact <= 3
                    or risk.score != risk.likelihood * risk.impact):
                raise ValueError
            expected = 'critical' if risk.score == 9 else 'high' if risk.score >= 6 else 'medium' if risk.score >= 3 else 'low'
            if risk.level != expected:
                raise ValueError
        for proof in evidence:
            if (not all(isinstance(x, str) for x in (proof.field, proof.source, proof.observation_status))
                    or proof.value is not None and not isinstance(proof.value, str)):
                raise ValueError
        findings.append(finding)
    if not findings:
        raise ValueError
    expected = 'incomplete' if any(x.status == 'insufficient_data' for x in findings) else 'complete'
    if data['evaluation_status'] != expected:
        raise ValueError
    if not isinstance(data['limitations'], list) or not all(isinstance(x, str) for x in data['limitations']):
        raise ValueError
    return SecurityReport(**(data | {'resource': resource, 'policy': policy,
                                    'results': tuple(findings), 'limitations': tuple(data['limitations'])}))
