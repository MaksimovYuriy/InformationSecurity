"""
Единая порядковая оценка опасности: учитывает чувствительность данных и подтверждение публичного
доступа, не вычисляет статистическую вероятность.
"""
from cloud_audit.models.security import RiskAssessment


class RiskModel:
    """Ordinal, documented prioritization; not a measured incident probability."""
    def assess(self, status: str, sensitivity: str,
               operations: tuple[str, ...] = (), exposure: str = 'unknown') -> RiskAssessment:
        """
        Для passed/n/a возвращает 0; для insufficient_data — unknown; иначе impact 1..3 × likelihood
        2 либо 3 и текстовое обоснование.
        """
        if status in {'passed', 'not_applicable'}:
            return RiskAssessment('none', 0, 0, 0, 'No finding for this rule', operations)
        if status == 'insufficient_data':
            return RiskAssessment('unknown', None, None, None, 'Insufficient evidence; risk not scored', operations)
        impact = {'low': 1, 'medium': 2, 'high': 3, 'unknown': 2}[sensitivity]
        likelihood = 3 if exposure == 'public_confirmed' else 2
        score = impact * likelihood
        level = 'critical' if score == 9 else 'high' if score >= 6 else 'medium' if score >= 3 else 'low'
        measured = ('An unsigned request confirms only the recorded operation and target. '
                    if exposure == 'public_confirmed' else 'Actual granted permissions are not measured. ')
        rationale = (f'Estimated ordinal risk: likelihood={likelihood}, impact={impact}; '
                     f'data_sensitivity={sensitivity}, exposure={exposure}. '
                     + measured + 'Other targets and recovery mechanisms are not assessed.')
        return RiskAssessment(level, score, likelihood, impact, rationale, operations)
