from __future__ import annotations

from dataclasses import dataclass

from scanner.context import ContextResult
from scanner.entropy import EntropyResult
from scanner.models import (ConfidenceLevel, ConfidenceScore, SecretSeverity)
from scanner.patterns import CompiledSecretPattern


@dataclass(frozen=True, slots=True)
class ConfidenceScoringConfig:
    """
    Configuration for evidence weighting and weights must sum to 1.0.
    """

    regex_weight: float = 0.50
    context_weight: float = 0.30
    entropy_weight: float = 0.20

    low_threshold: float = 0.35
    medium_threshold: float = 0.60
    high_threshold: float = 0.80

    def __post_init__(self) -> None:
        # Calculate the total evidence weight.
        total_weight = (self.regex_weight + self.context_weight + self.entropy_weight)

        # Ensure the weights sum to 1.0.
        if abs(total_weight - 1.0) > 1e-9:
            raise ValueError("Scoring weights must sum to 1.0.")

        # Validate the evidence weights.
        for name, value in (
            ("regex_weight", self.regex_weight),
            ("context_weight", self.context_weight),
            ("entropy_weight", self.entropy_weight),
        ):
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be between 0.0 and 1.0.")

        # Validate the confidence thresholds.
        for name, value in (
            ("low_threshold", self.low_threshold),
            ("medium_threshold", self.medium_threshold),
            ("high_threshold", self.high_threshold),
        ):
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be between 0.0 and 1.0.")

        # Ensure thresholds are strictly increasing.
        if not (self.low_threshold < self.medium_threshold < self.high_threshold):
            raise ValueError("Confidence thresholds must be strictly increasing.")


class ConfidenceScoringEngine:
    """
    Combines regex, contextual, and entropy evidence into a normalized confidence score.
    """

    def __init__(self, config: ConfidenceScoringConfig | None = None) -> None:
        self._config = config or ConfidenceScoringConfig() # Use the default configuration when none is provided.

    def score(self, pattern: CompiledSecretPattern, context_result: ContextResult,
               entropy_result: EntropyResult) -> ConfidenceScore:
        regex_score = self._calculate_regex_score(pattern=pattern)
        context_score = self._clamp(context_result.contextual_score)
        entropy_score = self._calculate_entropy_score(entropy_result=entropy_result)

        # Combine all evidence using configured weights.
        confidence = (
            regex_score * self._config.regex_weight
            + context_score * self._config.context_weight
            + entropy_score * self._config.entropy_weight
        )

        # Reduce confidence for placeholder values and comment matches.
        if context_result.is_placeholder:
            confidence *= 0.25

        if context_result.is_comment:
            confidence *= 0.10

        confidence = self._clamp(confidence) # Keep confidence within the valid range.

        level = self._classify_confidence(confidence)
        severity = self._determine_severity(pattern=pattern, confidence=confidence)

        return ConfidenceScore(
            confidence=confidence,
            level=level,
            regex_score=regex_score,
            context_score=context_score,
            entropy_score=entropy_score,
            is_placeholder=context_result.is_placeholder,
            is_comment=context_result.is_comment,
            severity=severity,
        )


    @staticmethod
    def _calculate_regex_score(pattern: CompiledSecretPattern,) -> float:
        return ConfidenceScoringEngine._clamp(pattern.definition.base_confidence)


    @staticmethod
    def _calculate_entropy_score(entropy_result: EntropyResult,) -> float:
        if not entropy_result.is_high_entropy:
            return 0.0
        
        return 1.0


    def _classify_confidence(self, confidence: float) -> ConfidenceLevel:
        if confidence >= self._config.high_threshold:
            return ConfidenceLevel.HIGH

        if confidence >= self._config.medium_threshold:
            return ConfidenceLevel.MEDIUM

        if confidence >= self._config.low_threshold:
            return ConfidenceLevel.LOW

        return ConfidenceLevel.LOW


    @staticmethod
    def _determine_severity(pattern: CompiledSecretPattern, confidence: float) -> SecretSeverity:
        base_severity = pattern.definition.severity
        if confidence < 0.35:
            return SecretSeverity.LOW

        if confidence < 0.60:
            if base_severity == SecretSeverity.CRITICAL:
                return SecretSeverity.MEDIUM

            if base_severity == SecretSeverity.HIGH:
                return SecretSeverity.MEDIUM
            
            return SecretSeverity.LOW

        if confidence < 0.80:
            if base_severity == SecretSeverity.CRITICAL:
                return SecretSeverity.HIGH
            return base_severity
        
        return base_severity


    @staticmethod
    def _clamp(value: float) -> float:
        return max(0.0, min(1.0, value))

    @property
    def config(self) -> ConfidenceScoringConfig:
        return self._config