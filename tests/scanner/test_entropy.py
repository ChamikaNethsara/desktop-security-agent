import pytest
from scanner.entropy import EntropyEngine


@pytest.fixture
def entropy_engine() -> EntropyEngine:
    return EntropyEngine()


def test_empty_value_has_zero_entropy(entropy_engine: EntropyEngine) -> None:
    result = entropy_engine.calculate("")

    assert result.entropy_bits_per_character == 0.0
    assert result.normalized_score == 0.0
    assert result.length == 0
    assert result.unique_characters == 0
    assert result.is_high_entropy is False


def test_repeated_character_has_zero_entropy(entropy_engine: EntropyEngine) -> None:
    result = entropy_engine.calculate("aaaaaaaaaa")

    assert result.entropy_bits_per_character == 0.0
    assert result.unique_characters == 1
    assert result.is_high_entropy is False


def test_entropy_increases_with_character_diversity(entropy_engine: EntropyEngine,) -> None:
    low = entropy_engine.calculate("aaaaaaaaaaaaaaaa")
    high = entropy_engine.calculate("x9F!kP72@Qz#Lm91")

    assert (high.entropy_bits_per_character > low.entropy_bits_per_character)


def test_entropy_is_normalized(entropy_engine: EntropyEngine) -> None:
    result = entropy_engine.calculate("x9F!kP72@Qz#Lm91")

    assert 0.0 <= result.normalized_score <= 1.0


def test_high_entropy_candidate(entropy_engine: EntropyEngine) -> None:
    result = entropy_engine.calculate("aB3$xY9!qP7@Lm2#Zk8^")

    assert result.is_high_entropy is True


def test_low_entropy_candidate(entropy_engine: EntropyEngine) -> None:
    result = entropy_engine.calculate("password")

    assert result.is_high_entropy is False


def test_length_is_recorded(entropy_engine: EntropyEngine) -> None:
    value = "SuperSecretPassword123!"
    result = entropy_engine.calculate(value)

    assert result.length == len(value)


def test_unique_character_count_is_recorded(entropy_engine: EntropyEngine) -> None:
    value = "aabbcc"
    result = entropy_engine.calculate(value)

    assert result.unique_characters == 3


def test_invalid_value_type_is_rejected(entropy_engine: EntropyEngine) -> None:
    with pytest.raises(TypeError):
        entropy_engine.calculate(None) # type: ignore[arg-type]


def test_invalid_threshold_is_rejected() -> None:
    with pytest.raises(ValueError):
        EntropyEngine(high_entropy_threshold=-1.0)


def test_invalid_maximum_entropy_is_rejected() -> None:
    with pytest.raises(ValueError):
        EntropyEngine(maximum_expected_entropy=0.0)


def test_threshold_cannot_exceed_maximum() -> None:
    with pytest.raises(ValueError):
        EntropyEngine(high_entropy_threshold=7.0, maximum_expected_entropy=6.0)