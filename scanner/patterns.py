from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from scanner.models import (SecretCategory, SecretPattern, SecretSeverity)


@dataclass(frozen=True, slots=True)
class CompiledSecretPattern:
    """
    Runtime representation of a SecretPattern.
    """
    definition: SecretPattern
    compiled_regex: re.Pattern[str]


class PatternRegistry:
    """
    Central registry of all secret-detection rules.
    """

    def __init__(self, patterns: Iterable[SecretPattern] | None = None) -> None:
        self._patterns: dict[str, CompiledSecretPattern] = {}

        if patterns is not None:
            for pattern in patterns:
                self.register(pattern)


    # Register one detection pattern.
    def register(self, pattern: SecretPattern) -> None:
        if pattern.pattern_id in self._patterns:
            raise ValueError(f"Pattern already registered: {pattern.pattern_id}")

        try:
            compiled_regex = re.compile(pattern.regex, re.IGNORECASE)
        except re.error as exc:
            raise ValueError(f"Invalid regex for pattern '{pattern.pattern_id}': {exc}") from exc

        self._patterns[pattern.pattern_id] = (
            CompiledSecretPattern(
                definition=pattern,
                compiled_regex=compiled_regex,
            )
        )


    def get(self, pattern_id: str) -> CompiledSecretPattern:
        try:
            return self._patterns[pattern_id]
        except KeyError as exc:
            raise KeyError(f"Unknown secret pattern: {pattern_id}") from exc


    def all(self) -> tuple[CompiledSecretPattern, ...]:
        return tuple(self._patterns.values())


    def enabled(self) -> tuple[CompiledSecretPattern, ...]:
        return tuple(
            pattern
            for pattern in self._patterns.values()
            if pattern.definition.enabled
        )


    def by_category(self, category: SecretCategory) -> tuple[CompiledSecretPattern, ...]:
        return tuple(
            pattern
            for pattern in self.enabled()
            if pattern.definition.category == category
        )


    def by_provider(self, provider: str) -> tuple[CompiledSecretPattern, ...]:
        provider_normalized = provider.casefold()

        return tuple(
            pattern
            for pattern in self.enabled()
            if (
                pattern.definition.provider is not None
                and pattern.definition.provider.casefold()
                == provider_normalized
            )
        )


    def __len__(self) -> int:
        return len(self._patterns)


# -- Built-in secret patterns
BUILT_IN_PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern(
        pattern_id="aws_access_key_id",
        name="AWS Access Key ID",
        category=SecretCategory.API_KEY,
        provider="AWS",
        regex=r"\bAKIA[0-9A-Z]{16}\b",
        severity=SecretSeverity.HIGH,
        base_confidence=0.98,
        entropy_required=False,
        context_required=False,
        description=("Detects the standard AWS long-term access key ID format.")
    ),

    SecretPattern(
        pattern_id="github_personal_access_token",
        name="GitHub Personal Access Token",
        category=SecretCategory.ACCESS_TOKEN,
        provider="GitHub",
        regex=r"\bgh[pousr]_[A-Za-z0-9_]{20,255}\b",
        severity=SecretSeverity.HIGH,
        base_confidence=0.98,
        entropy_required=False,
        context_required=False,
        description=("Detects GitHub token formats.")
    ),

    SecretPattern(
        pattern_id="private_key_pem",
        name="Private Key",
        category=SecretCategory.PRIVATE_KEY,
        provider=None,
        regex=(
            r"-----BEGIN "
            r"(?:RSA |EC |OPENSSH |DSA |ED25519 )?"
            r"PRIVATE KEY-----"
        ),
        severity=SecretSeverity.CRITICAL,
        base_confidence=0.99,
        entropy_required=False,
        context_required=False,
        description=("Detects PEM encoded private key headers.")
    ),

    SecretPattern(
        pattern_id="generic_password_assignment",
        name="Generic Password Assignment",
        category=SecretCategory.PASSWORD,
        provider=None,
        regex=(
            r"(?i)\b"
            r"(?:password|passwd|pwd)"
            r"\s*"
            r"[:=]"
            r"\s*"
            r"['\"]?"
            r"[^'\"\s]+"
            r"['\"]?"
        ),
        severity=SecretSeverity.HIGH,
        base_confidence=0.75,
        entropy_required=True,
        context_required=True,
        description=(
            "Detects values assigned to common password keys. "
            "Requires contextual and entropy analysis before "
            "being treated as a confirmed secret."
        )
    ),
)

# Create a registry containing the built-in detection rules.
def create_default_pattern_registry() -> PatternRegistry:
    return PatternRegistry(BUILT_IN_PATTERNS)