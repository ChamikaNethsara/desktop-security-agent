import pytest
from pathlib import Path

from scanner.context import ContextResult
from scanner.entropy import EntropyResult
from scanner.models import (ConfidenceLevel, SecretSeverity)
from scanner.patterns import create_default_pattern_registry
from scanner.scorer import (ConfidenceScoringConfig, ConfidenceScoringEngine)

def make_context(*,  score: float, placeholder: bool = False, comment: bool = False,
                  candidate: str = "SuperSecretPassword123!") -> ContextResult:
    return ContextResult(
        file_path=Path(".env"),
        pattern_id="generic_password_assignment",
        key_name="DATABASE_PASSWORD",
        candidate_value=candidate,
        contextual_score=score,
        is_comment=comment,
        is_placeholder=placeholder,
        indicators=(),
        line_number=1,
    )


def make_entropy(*, high_entropy: bool, entropy: float = 4.0) -> EntropyResult:
    return EntropyResult(
        entropy_bits_per_character=entropy,
        normalized_score=1.0 if high_entropy else 0.0,
        length=20,
        unique_characters=15,
        is_high_entropy=high_entropy,
    )


def test_high_quality_evidence_produces_medium_or_high_confidence():
    registry = create_default_pattern_registry()
    pattern = registry.get("generic_password_assignment")
    scorer = ConfidenceScoringEngine()

    result = scorer.score(
        pattern=pattern,
        context_result=make_context(score=0.8),
        entropy_result=make_entropy(high_entropy=True),
    )

    assert result.confidence >= 0.60
    assert result.level in {
        ConfidenceLevel.MEDIUM,
        ConfidenceLevel.HIGH,
    }


def test_placeholder_significantly_reduces_confidence():
    registry = create_default_pattern_registry()
    pattern = registry.get("generic_password_assignment")
    scorer = ConfidenceScoringEngine()

    result = scorer.score(
        pattern=pattern,
        context_result=make_context(score=0.1, placeholder=True),
        entropy_result=make_entropy(high_entropy=True)
    )

    assert result.confidence < 0.35
    assert result.level == ConfidenceLevel.LOW
    assert result.is_placeholder is True


def test_comment_significantly_reduces_confidence():
    registry = create_default_pattern_registry()
    pattern = registry.get("generic_password_assignment")
    scorer = ConfidenceScoringEngine()

    result = scorer.score(
        pattern=pattern,
        context_result=make_context(score=0.0, comment=True),
        entropy_result=make_entropy(high_entropy=True)
    )

    assert result.confidence < 0.35
    assert result.level == ConfidenceLevel.LOW
    assert result.is_comment is True


def test_low_entropy_reduces_confidence():
    registry = create_default_pattern_registry()
    pattern = registry.get("generic_password_assignment")
    scorer = ConfidenceScoringEngine()

    result = scorer.score(
        pattern=pattern,
        context_result=make_context(score=0.5),
        entropy_result=make_entropy(high_entropy=False, entropy=1.5)
    )

    assert result.entropy_score == 0.0


def test_confidence_is_normalized():
    registry = create_default_pattern_registry()
    pattern = registry.get("generic_password_assignment")
    scorer = ConfidenceScoringEngine()

    result = scorer.score(
        pattern=pattern,
        context_result=make_context(score=1.0),
        entropy_result=make_entropy(high_entropy=True)
    )

    assert 0.0 <= result.confidence <= 1.0


def test_invalid_weights_are_rejected():
    with pytest.raises(ValueError):
        ConfidenceScoringConfig(
            regex_weight=0.5,
            context_weight=0.5,
            entropy_weight=0.5,
        )


def test_invalid_threshold_order_is_rejected():
    with pytest.raises(ValueError):
        ConfidenceScoringConfig(
            low_threshold=0.8,
            medium_threshold=0.6,
            high_threshold=0.9,
        )


def test_severity_is_reduced_for_low_confidence():
    registry = create_default_pattern_registry()
    pattern = registry.get("private_key_pem")
    scorer = ConfidenceScoringEngine()

    result = scorer.score(
        pattern=pattern,
        context_result=make_context(score=0.0, candidate="PRIVATE KEY"),
        entropy_result=make_entropy(high_entropy=False)
    )

    assert result.severity == SecretSeverity.MEDIUM