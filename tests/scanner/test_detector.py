from pathlib import Path
import pytest

from scanner.detector import RegexDetectionEngine
from scanner.models import SecretCategory, SecretSeverity
from scanner.patterns import create_default_pattern_registry


@pytest.fixture
def detector() -> RegexDetectionEngine:
    registry = create_default_pattern_registry()
    return RegexDetectionEngine(registry)


def test_detect_aws_access_key(detector: RegexDetectionEngine) -> None:
    content = """
    AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
    """

    matches = detector.detect(
        content=content,
        file_path=Path(".env"),
    )

    assert len(matches) == 1
    match = matches[0]

    assert match.pattern_id == "aws_access_key_id"
    assert match.pattern_name == "AWS Access Key ID"
    assert match.category is SecretCategory.API_KEY
    assert match.severity is SecretSeverity.HIGH
    assert match.provider == "AWS"
    assert match.matched_text == "AKIAIOSFODNN7EXAMPLE"


def test_detect_password_assignment(detector: RegexDetectionEngine) -> None:
    content = """
    DATABASE_PASSWORD="SuperSecretPassword123!"
    """

    matches = detector.detect(
        content=content,
        file_path=Path(".env"),
    )

    assert len(matches) == 1
    match = matches[0]

    assert match.pattern_id == "generic_password_assignment"
    assert match.category is SecretCategory.PASSWORD
    assert match.severity is SecretSeverity.HIGH
    assert match.line_number == 2


def test_detect_private_key(detector: RegexDetectionEngine) -> None:
    content = """
    -----BEGIN PRIVATE KEY-----
    some-key-data
    -----END PRIVATE KEY-----
    """

    matches = detector.detect(
        content=content,
        file_path=Path("private.pem"),
    )

    assert len(matches) == 1
    match = matches[0]

    assert match.pattern_id == "private_key_pem"
    assert match.category is SecretCategory.PRIVATE_KEY
    assert match.severity is SecretSeverity.CRITICAL
    assert match.line_number == 2


def test_no_match_for_safe_content(detector: RegexDetectionEngine) -> None:
    content = """
    DATABASE_HOST=localhost
    DATABASE_PORT=5432
    DATABASE_USER=test
    """

    matches = detector.detect(
        content=content,
        file_path=Path(".env"),
    )

    assert matches == []


def test_multiple_patterns_are_detected(detector: RegexDetectionEngine) -> None:
    content = """
    AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
    DATABASE_PASSWORD="SuperSecretPassword123!"
    """

    matches = detector.detect(
        content=content,
        file_path=Path(".env"),
    )

    assert len(matches) == 2
    pattern_ids = {match.pattern_id for match in matches}

    assert "aws_access_key_id" in pattern_ids
    assert "generic_password_assignment" in pattern_ids


def test_match_location_is_correct(detector: RegexDetectionEngine) -> None:
    content = (
        "DATABASE_HOST=localhost\n"
        "DATABASE_PASSWORD=SuperSecret123!\n"
    )

    matches = detector.detect(
        content=content,
        file_path=Path(".env"),
    )

    assert len(matches) == 1
    match = matches[0]

    assert match.line_number == 2
    assert match.column_number == 1


def test_detector_rejects_invalid_content_type(detector: RegexDetectionEngine) -> None:
    with pytest.raises(TypeError):
        detector.detect(
            content=None,  # type: ignore[arg-type]
            file_path=Path(".env"),
        )


def test_detector_rejects_invalid_path_type(detector: RegexDetectionEngine) -> None:
    with pytest.raises(TypeError):
        detector.detect(
            content="PASSWORD=test",
            file_path=".env",  # type: ignore[arg-type]
        )