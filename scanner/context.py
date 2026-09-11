from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

from scanner.detector import RegexMatch


@dataclass(frozen=True, slots=True)
class ContextResult:
    """
    Represents contextual evidence surrounding a regex match.
    """

    file_path: Path
    pattern_id: str

    key_name: str | None
    candidate_value: str
    contextual_score: float

    is_comment: bool
    is_placeholder: bool

    indicators: tuple[str, ...]
    line_number: int


class ContextDetectionEngine:
    """
    Performs contextual analysis of regex matches.
    """

    _KEY_PATTERN = re.compile(
        r"""
        (?P<key>
            [A-Za-z_][A-Za-z0-9_.-]*
        )
        \s*
        (?P<separator>[:=])
        \s*
        (?P<value>.*?)
        \s*$
        """,
        re.VERBOSE,
    )

    _KEYWORDS = {
        "password",
        "passwd",
        "pwd",
        "secret",
        "api_key",
        "apikey",
        "access_key",
        "access_token",
        "auth_token",
        "authentication_token",
        "private_key",
        "client_secret",
        "database_password",
        "db_password",
        "token",
        "credential",
        "credentials",
        "authorization",
    }

    _PLACEHOLDER_VALUES = {
        "",
        "changeme",
        "change_me",
        "change-this",
        "change-this-password",
        "example",
        "example_password",
        "examplepassword",
        "dummy",
        "dummy_password",
        "password",
        "your_password",
        "your-password",
        "yourpassword",
        "your_api_key",
        "your-api-key",
        "your_token",
        "your-token",
        "placeholder",
        "replace_me",
        "replace-me",
        "replace_this",
        "replace-this",
        "test",
        "test_password",
        "test-password",
        "testing",
        "xxx",
        "xxxxx",
        "xxxxxxxx",
    }

    _PLACEHOLDER_PATTERNS = (
        re.compile(r"\$\{[^}]+\}"),
        re.compile(r"\$\([^)]+\)"),
        re.compile(r"%[^%]+%"),
        re.compile(r"<[^>]+>"),
        re.compile(r"\{\{[^}]+\}\}"),
    )

    # Analyze the context surrounding a regex match.
    def detect(self, content: str, regex_match: RegexMatch) -> ContextResult:
        # Validate input types.
        if not isinstance(content, str):
            raise TypeError("content must be a string.")

        if not isinstance(regex_match, RegexMatch):
            raise TypeError("regex_match must be a RegexMatch.")

        line = self._get_line(content, regex_match.line_number) # Get the matched line.
        is_comment = self._is_comment_line(line)
        key_name, candidate_value = self._extract_assignment(regex_match=regex_match, line=line)

        normalized_value = self._normalize_value(candidate_value) # Normalize the candidate value.
        indicators: list[str] = [] # Collect contextual indicators.

        # Check for a secret-related key.
        if key_name is not None:
            normalized_key = key_name.casefold()
            if self._contains_secret_keyword(normalized_key):
                indicators.append("secret_related_key")

        # Record comment context.
        if is_comment:
            indicators.append("comment_context")

        # Check for a placeholder value and record it
        is_placeholder = self._is_placeholder(normalized_value)
        if is_placeholder:
            indicators.append("placeholder_value")

        # Check for an example value.
        if self._looks_like_example(normalized_value):
            indicators.append("example_or_test_value")

        # Calculate the contextual score.
        contextual_score = self._calculate_contextual_score(
            key_name=key_name,
            is_comment=is_comment,
            is_placeholder=is_placeholder,
            is_example=self._looks_like_example(normalized_value),
        )

        # Build the contextual result.
        return ContextResult(
            file_path=regex_match.file_path,
            pattern_id=regex_match.pattern_id,
            key_name=key_name,
            candidate_value=normalized_value,
            contextual_score=contextual_score,
            is_comment=is_comment,
            is_placeholder=is_placeholder,
            indicators=tuple(indicators),
            line_number=regex_match.line_number,
        )

    # Return a one-based line from the supplied content.
    @staticmethod
    def _get_line(content: str, line_number: int) -> str:
        lines = content.splitlines()
        if line_number < 1 or line_number > len(lines):
            return ""

        return lines[line_number - 1]

    # Detect common full-line comment syntax.
    @staticmethod
    def _is_comment_line(line: str) -> bool:
        stripped = line.lstrip()

        return (
            stripped.startswith("#")
            or stripped.startswith("//")
            or stripped.startswith(";")
        )

    # Extract key/value information from the line.
    def _extract_assignment(self, regex_match: RegexMatch, line: str) -> tuple[str | None, str]:
        match = self._KEY_PATTERN.match(line.strip())

        if match is not None:
            key_name = match.group("key")
            value = match.group("value")

            return key_name, value

        return None, regex_match.matched_text

    # Remove surrounding whitespace and matching quotes.
    @staticmethod
    def _normalize_value(value: str) -> str:
        normalized = value.strip()
        if len(normalized) >= 2:
            if (normalized[0] == normalized[-1] and normalized[0] in {"'", '"'}):
                normalized = normalized[1:-1]

        return normalized.strip()

    # Determine whether a configuration key contains a security-sensitive keyword.
    def _contains_secret_keyword(self, key_name: str) -> bool:
        normalized = key_name.casefold()
        parts = re.split(r"[_\-.]", normalized)

        return any(
            part in self._KEYWORDS
            for part in parts
        ) or normalized in self._KEYWORDS

    # Detect common environment-variable and placeholder syntax.
    def _is_placeholder(self, value: str) -> bool:
        normalized = value.strip().casefold()

        if normalized in self._PLACEHOLDER_VALUES:
            return True

        return any(
            pattern.fullmatch(value.strip())
            for pattern in self._PLACEHOLDER_PATTERNS
        )

    # Detect obvious test/example values.
    @staticmethod
    def _looks_like_example(value: str) -> bool:
        normalized = value.casefold()

        example_terms = (
            "example",
            "dummy",
            "sample",
            "placeholder",
            "test_password",
            "test-token",
            "fake",
        )

        return any(
            term in normalized
            for term in example_terms
        )

    # Calculate contextual evidence on a 0.0–1.0 scale.
    @staticmethod
    def _calculate_contextual_score(key_name: str | None, is_comment: bool, is_placeholder: bool,
                                     is_example: bool) -> float:
        score = 0.0

        # Add evidence for a sensitive key.
        if key_name is not None:
            normalized_key = key_name.casefold()

            if any(
                keyword in normalized_key
                for keyword in (
                    "password",
                    "passwd",
                    "secret",
                    "token",
                    "api_key",
                    "apikey",
                    "credential",
                    "private_key",
                    "access_key",
                )
            ):
                score += 0.50

        # Reduce confidence for comments, placeholders and example values
        if is_comment:
            score -= 0.50

        if is_placeholder:
            score -= 0.40

        if is_example:
            score -= 0.25

        return max(0.0, min(1.0, score)) # score within 0.0–1.0.