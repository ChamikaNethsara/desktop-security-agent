from pathlib import Path

from scanner.deduplicator import FindingDeduplicator
from scanner.models import (ConfidenceLevel, SecretCategory, SecretFinding, SecretSeverity)


def create_finding(
        *,
        path: str = "project/.env",
        line_number: int = 1,
        pattern_id: str = "generic_password_assignment"
        ) -> SecretFinding:

    return SecretFinding(
        file_path=Path(path),
        line_number=line_number,
        pattern_id=pattern_id,
        pattern_name="Generic Password Assignment",
        category=SecretCategory.PASSWORD,
        severity=SecretSeverity.HIGH,
        confidence=0.80,
        confidence_level=ConfidenceLevel.CRITICAL,
        regex_score=0.75,
        context_score=0.50,
        entropy_score=1.00,
        is_placeholder=False,
        is_comment=False,
    )


def test_first_finding_is_not_duplicate() -> None:
    deduplicator = FindingDeduplicator()
    finding = create_finding()

    assert deduplicator.is_duplicate(finding) is False


def test_same_finding_is_duplicate() -> None:
    deduplicator = FindingDeduplicator()
    finding = create_finding()

    assert deduplicator.is_duplicate(finding) is False
    assert deduplicator.is_duplicate(finding) is True


def test_different_line_is_not_duplicate() -> None:
    deduplicator = FindingDeduplicator()
    finding_a = create_finding(line_number=1)
    finding_b = create_finding(line_number=2)

    assert deduplicator.is_duplicate(finding_a) is False
    assert deduplicator.is_duplicate(finding_b) is False


def test_different_file_is_not_duplicate() -> None:
    deduplicator = FindingDeduplicator()
    finding_a = create_finding(path="project_a/.env")
    finding_b = create_finding(path="project_b/.env")

    assert deduplicator.is_duplicate(finding_a) is False
    assert deduplicator.is_duplicate(finding_b) is False


def test_contains_returns_correct_state() -> None:
    deduplicator = FindingDeduplicator()
    finding = create_finding()

    assert deduplicator.contains(finding) is False
    deduplicator.add(finding)
    assert deduplicator.contains(finding) is True


def test_clear_removes_all_fingerprints() -> None:
    deduplicator = FindingDeduplicator()
    finding = create_finding()

    deduplicator.add(finding)
    assert len(deduplicator) == 1
    deduplicator.clear()
    
    assert len(deduplicator) == 0
    assert deduplicator.contains(finding) is False