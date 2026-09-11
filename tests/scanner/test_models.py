import pytest
from pathlib import Path
from scanner.models import (SecretCategory, SecretPattern, SecretSeverity)
from scanner.scorer import ConfidenceLevel
from scanner.models import SecretFinding

def test_secret_pattern_creation() -> None:
    pattern = SecretPattern(
        pattern_id="test_pattern",
        name="Test Pattern",
        category=SecretCategory.GENERIC_SECRET,
        regex=r"secret_[A-Za-z0-9]+",
        severity=SecretSeverity.MEDIUM,
        base_confidence=0.80,
    )

    assert pattern.pattern_id == "test_pattern"
    assert pattern.name == "Test Pattern"
    assert pattern.category is SecretCategory.GENERIC_SECRET
    assert pattern.severity is SecretSeverity.MEDIUM
    assert pattern.base_confidence == 0.80


def test_secret_pattern_rejects_invalid_confidence() -> None:
    with pytest.raises(ValueError):
        SecretPattern(
            pattern_id="invalid",
            name="Invalid",
            category=SecretCategory.GENERIC_SECRET,
            regex=r"secret",
            severity=SecretSeverity.MEDIUM,
            base_confidence=1.5,
        )


def test_secret_pattern_is_immutable() -> None:
    pattern = SecretPattern(
        pattern_id="immutable",
        name="Immutable Pattern",
        category=SecretCategory.GENERIC_SECRET,
        regex=r"secret",
        severity=SecretSeverity.LOW,
        base_confidence=0.5,
    )

    with pytest.raises(AttributeError):
        pattern.name = "Changed"


def create_test_finding() -> SecretFinding:
    return SecretFinding(
        file_path=Path("project/.env"),
        line_number=1,
        pattern_id="generic_password_assignment",
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
        description=("Detects values assigned to common password keys.")
    )


def test_secret_finding_creation() -> None:
    finding = create_test_finding()

    assert finding.file_path == Path("project/.env")
    assert finding.line_number == 1
    assert finding.pattern_id == "generic_password_assignment"
    assert finding.category is SecretCategory.PASSWORD
    assert finding.severity is SecretSeverity.HIGH
    assert finding.confidence == 0.80
    assert finding.confidence_level is ConfidenceLevel.CRITICAL


def test_secret_finding_is_immutable() -> None:
    finding = create_test_finding()

    with pytest.raises(AttributeError):
        finding.confidence = 0.20


def test_secret_finding_rejects_invalid_confidence() -> None:
    with pytest.raises(ValueError):
        SecretFinding(
            file_path=Path("project/.env"),
            line_number=1,
            pattern_id="test",
            pattern_name="Test",
            category=SecretCategory.GENERIC_SECRET,
            severity=SecretSeverity.MEDIUM,
            confidence=1.5,
            confidence_level=ConfidenceLevel.CRITICAL,
            regex_score=0.75,
            context_score=0.50,
            entropy_score=1.00,
            is_placeholder=False,
            is_comment=False,
        )


def test_secret_finding_rejects_invalid_line_number() -> None:
    with pytest.raises(ValueError):
        SecretFinding(
            file_path=Path("project/.env"),
            line_number=0,
            pattern_id="test",
            pattern_name="Test",
            category=SecretCategory.GENERIC_SECRET,
            severity=SecretSeverity.MEDIUM,
            confidence=0.50,
            confidence_level=ConfidenceLevel.MEDIUM,
            regex_score=0.75,
            context_score=0.50,
            entropy_score=0.50,
            is_placeholder=False,
            is_comment=False,
        )


def test_secret_finding_rejects_invalid_evidence_scores() -> None:
    with pytest.raises(ValueError):
        SecretFinding(
            file_path=Path("project/.env"),
            line_number=1,
            pattern_id="test",
            pattern_name="Test",
            category=SecretCategory.GENERIC_SECRET,
            severity=SecretSeverity.MEDIUM,
            confidence=0.50,
            confidence_level=ConfidenceLevel.MEDIUM,
            regex_score=2.0,
            context_score=0.50,
            entropy_score=0.50,
            is_placeholder=False,
            is_comment=False,
        )


def test_secret_finding_has_no_secret_value_field() -> None:
    field_names = {
        field.name
        for field in SecretFinding.__dataclass_fields__.values()
    }

    assert "candidate_value" not in field_names
    assert "secret_value" not in field_names
    assert "matched_text" not in field_names
    assert "source_content" not in field_names