from auditor.findings import Finding
from auditor.risk_score import (
    calculate_risk_score,
    get_risk_category,
)


def test_no_findings_gives_full_score():
    assert calculate_risk_score([]) == 100


def test_critical_finding_reduces_score():
    finding = Finding(
        rule_id="CFG-002",
        title="Privileged container",
        severity="Critical",
        file="test.yaml",
        description="Test finding",
        recommendation="Disable privileged mode",
        evidence="privileged: true",
    )

    assert calculate_risk_score([finding]) < 100


def test_risk_category():
    assert get_risk_category(95) == "Excellent"
    assert get_risk_category(80) == "Good"
    assert get_risk_category(60) == "Moderate"
    assert get_risk_category(30) == "High Risk"
    assert get_risk_category(10) == "Critical Risk"