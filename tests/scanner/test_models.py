import pytest
from scanner.models import (SecretCategory, SecretPattern, SecretSeverity)

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