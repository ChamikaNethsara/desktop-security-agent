from config.auditor_config import SEVERITY_WEIGHTS


def calculate_finding_penalty(finding):
    weight = SEVERITY_WEIGHTS.get(finding.severity, 5)

    return (
        weight
        * finding.confidence
        * finding.exposure
        * finding.recurrence
    )


def calculate_risk_score(findings):
    # Initial prototype normalization.
    # Calibrate this formula using evaluation data.
    total_penalty = sum(
        calculate_finding_penalty(finding)
        for finding in findings
    )

    normalized_penalty = min(100, total_penalty)

    return round(max(0, 100 - normalized_penalty), 2)


def get_risk_category(score):
    if score >= 90:
        return "Excellent"
    if score >= 75:
        return "Good"
    if score >= 50:
        return "Moderate"
    if score >= 25:
        return "High Risk"
    return "Critical Risk"