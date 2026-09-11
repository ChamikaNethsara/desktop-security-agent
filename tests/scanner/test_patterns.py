import pytest
from scanner.models import (SecretCategory, SecretPattern, SecretSeverity)
from scanner.patterns import (PatternRegistry, create_default_pattern_registry)


def test_default_registry_contains_patterns() -> None:
    registry = create_default_pattern_registry()

    assert len(registry) > 0


def test_get_pattern_by_id() -> None:
    registry = create_default_pattern_registry()
    pattern = registry.get("aws_access_key_id")

    assert pattern.definition.name == ("AWS Access Key ID")


def test_enabled_patterns() -> None:
    registry = create_default_pattern_registry()
    enabled_patterns = registry.enabled()

    assert len(enabled_patterns) == len(registry)


def test_duplicate_pattern_id_is_rejected() -> None:
    pattern = SecretPattern(
        pattern_id="duplicate",
        name="Duplicate",
        category=SecretCategory.GENERIC_SECRET,
        regex=r"secret",
        severity=SecretSeverity.LOW,
        base_confidence=0.5,
    )

    registry = PatternRegistry()
    registry.register(pattern)

    with pytest.raises(ValueError):
        registry.register(pattern)


def test_invalid_regex_is_rejected() -> None:
    pattern = SecretPattern(
        pattern_id="invalid_regex",
        name="Invalid Regex",
        category=SecretCategory.GENERIC_SECRET,
        regex=r"[",
        severity=SecretSeverity.LOW,
        base_confidence=0.5,
    )

    registry = PatternRegistry()

    with pytest.raises(ValueError):
        registry.register(pattern)


def test_find_patterns_by_provider() -> None:
    registry = create_default_pattern_registry()
    patterns = registry.by_provider("AWS")

    assert len(patterns) >= 1
    for pattern in patterns:
        assert pattern.definition.provider == "AWS"


def test_find_patterns_by_category() -> None:
    registry = create_default_pattern_registry()
    patterns = registry.by_category(SecretCategory.PRIVATE_KEY)

    assert len(patterns) >= 1

def test_aws_regex_is_compiled() -> None:
    registry = create_default_pattern_registry()
    pattern = registry.get("aws_access_key_id")
    match = pattern.compiled_regex.search("AWS_KEY=AKIAIOSFODNN7EXAMPLE")

    assert match is not None

def test_aws_regex_rejects_invalid_key() -> None:
    registry = create_default_pattern_registry()
    pattern = registry.get("aws_access_key_id")
    match = pattern.compiled_regex.search("AWS_KEY=not_an_aws_key")

    assert match is None