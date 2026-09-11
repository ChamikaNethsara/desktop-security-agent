from pathlib import Path
import pytest

from scanner.context import ContextDetectionEngine
from scanner.detector import RegexDetectionEngine
from scanner.patterns import create_default_pattern_registry


@pytest.fixture
def detector() -> RegexDetectionEngine:
    return RegexDetectionEngine(create_default_pattern_registry())


@pytest.fixture
def context_engine() -> ContextDetectionEngine:
    return ContextDetectionEngine()


def _get_match(detector: RegexDetectionEngine, content: str,):
    matches = detector.detect(
        content=content,
        file_path=Path(".env"),
    )

    assert len(matches) == 1

    return matches[0]


def test_detect_secret_related_key(detector: RegexDetectionEngine, context_engine: ContextDetectionEngine) -> None:
    content = ('DATABASE_PASSWORD="SuperSecretPassword123!"\n')
    regex_match = _get_match(detector, content)

    result = context_engine.detect(
        content=content,
        regex_match=regex_match,
    )

    assert result.key_name == "DATABASE_PASSWORD"
    assert result.candidate_value == "SuperSecretPassword123!"
    assert result.is_placeholder is False
    assert result.is_comment is False
    assert "secret_related_key" in result.indicators
    assert result.contextual_score > 0.0


def test_detect_placeholder(detector: RegexDetectionEngine, context_engine: ContextDetectionEngine) -> None:
    content = "DATABASE_PASSWORD=CHANGE_ME\n"
    regex_match = _get_match(detector, content)

    result = context_engine.detect(
        content=content,
        regex_match=regex_match,
    )

    assert result.is_placeholder is True
    assert "placeholder_value" in result.indicators


def test_detect_environment_variable_placeholder(detector: RegexDetectionEngine, context_engine: ContextDetectionEngine) -> None:
    content = "DATABASE_PASSWORD=${DATABASE_PASSWORD}\n"
    regex_match = _get_match(detector, content)

    result = context_engine.detect(
        content=content,
        regex_match=regex_match,
    )

    assert result.is_placeholder is True


def test_detect_comment_context(detector: RegexDetectionEngine, context_engine: ContextDetectionEngine) -> None:
    content = ('# DATABASE_PASSWORD="SuperSecretPassword123!"\n')
    regex_match = _get_match(detector, content)

    result = context_engine.detect(
        content=content,
        regex_match=regex_match,
    )

    assert result.is_comment is True
    assert "comment_context" in result.indicators
    assert result.contextual_score == 0.0


def test_remove_surrounding_quotes(detector: RegexDetectionEngine, context_engine: ContextDetectionEngine) -> None:
    content = ('DATABASE_PASSWORD="SuperSecretPassword123!"\n')
    regex_match = _get_match(detector, content)

    result = context_engine.detect(
        content=content,
        regex_match=regex_match,
    )

    assert result.candidate_value == "SuperSecretPassword123!"


def test_example_value_has_lower_context(detector: RegexDetectionEngine, context_engine: ContextDetectionEngine) -> None:
    content = "DATABASE_PASSWORD=example_password\n"
    regex_match = _get_match(detector, content)

    result = context_engine.detect(
        content=content,
        regex_match=regex_match,
    )

    assert "example_or_test_value" in result.indicators
    assert result.contextual_score < 0.5


def test_context_rejects_invalid_content(context_engine: ContextDetectionEngine) -> None:
    with pytest.raises(TypeError):
        context_engine.detect(
            content=None,  # type: ignore[arg-type]
            regex_match=None,  # type: ignore[arg-type]
        )