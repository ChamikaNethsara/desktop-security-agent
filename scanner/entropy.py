from __future__ import annotations

from dataclasses import dataclass
from collections import Counter
import math


@dataclass(frozen=True, slots=True)
class EntropyResult:
    """
    Represents entropy analysis of a candidate value.
    """

    entropy_bits_per_character: float
    normalized_score: float

    length: int
    unique_characters: int
    is_high_entropy: bool


class EntropyEngine:
    """
    Calculates Shannon entropy for candidate secret values.
    """

    def __init__(self, high_entropy_threshold: float = 3.5, maximum_expected_entropy: float = 6.0) -> None:
        # Validate the entropy threshold and maximum entropy value.
        if high_entropy_threshold < 0.0:
            raise ValueError("high_entropy_threshold must be >= 0.")

        if maximum_expected_entropy <= 0.0:
            raise ValueError("maximum_expected_entropy must be > 0.")

        # Ensure the threshold is within the maximum.
        if high_entropy_threshold > maximum_expected_entropy:
            raise ValueError("high_entropy_threshold cannot exceed maximum_expected_entropy.")

        self._high_entropy_threshold = high_entropy_threshold
        self._maximum_expected_entropy = maximum_expected_entropy

    @property
    def high_entropy_threshold(self) -> float:
        return self._high_entropy_threshold

    @property
    def maximum_expected_entropy(self) -> float:
        return self._maximum_expected_entropy

    # Calculate Shannon entropy for a candidate value.
    def calculate(self, value: str) -> EntropyResult:
        if not isinstance(value, str):
            raise TypeError("value must be a string.")

        # Return zero entropy for an empty value.
        if not value:
            return EntropyResult(
                entropy_bits_per_character=0.0,
                normalized_score=0.0,
                length=0,
                unique_characters=0,
                is_high_entropy=False,
            )

        length = len(value)
        frequencies = Counter(value) # Count character frequencies.
        entropy = 0.0

        # Calculate Shannon entropy.
        for count in frequencies.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        normalized_score = min(entropy / self._maximum_expected_entropy, 1.0) # Normalize entropy to a 0.0–1.0 score.
        is_high_entropy = (entropy >= self._high_entropy_threshold)

        # Return the calculated entropy evidence.
        return EntropyResult(
            entropy_bits_per_character=entropy,
            normalized_score=normalized_score,
            length=length,
            unique_characters=len(frequencies),
            is_high_entropy=is_high_entropy,
        )