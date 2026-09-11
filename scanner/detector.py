from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from scanner.models import SecretCategory, SecretSeverity
from scanner.patterns import CompiledSecretPattern, PatternRegistry


@dataclass(frozen=True, slots=True)
class RegexMatch:
    """
    Represents a raw regex detection.
    """

    pattern_id: str
    pattern_name: str
    category: SecretCategory
    severity: SecretSeverity
    file_path: Path

    start_offset: int
    end_offset: int

    line_number: int
    column_number: int

    matched_text: str

    base_confidence: float
    provider: str | None


class RegexDetectionEngine:
    """
    Performs regex-based secret detection against file contents.
    """

    def __init__(self, pattern_registry: PatternRegistry) -> None:
        self._pattern_registry = pattern_registry

    @property
    def pattern_registry(self) -> PatternRegistry:
        return self._pattern_registry

    # Scan file content using all enabled registered patterns.
    def detect(self, content: str, file_path: Path) -> list[RegexMatch]:
        if not isinstance(content, str):
            raise TypeError("content must be a string.")

        if not isinstance(file_path, Path):
            raise TypeError("file_path must be a pathlib.Path.")

        matches: list[RegexMatch] = [] # Collect all matches.

        # Run each enabled registered pattern against the file content.
        for compiled_pattern in self._pattern_registry.enabled():
            pattern_matches = self._detect_pattern(
                content=content,
                file_path=file_path,
                compiled_pattern=compiled_pattern,
            )
            matches.extend(pattern_matches) # Add pattern matches to results.

        return matches

    # Execute one compiled pattern against the supplied content.
    def _detect_pattern(self, content: str, file_path: Path, compiled_pattern: CompiledSecretPattern) -> list[RegexMatch]:
        pattern = compiled_pattern.definition
        regex = compiled_pattern.compiled_regex

        results: list[RegexMatch] = []

        for match in regex.finditer(content):
            start_offset = match.start()
            end_offset = match.end()
            line_number, column_number = self._get_line_and_column(content, start_offset)

            results.append(
                RegexMatch(
                    pattern_id=pattern.pattern_id,
                    pattern_name=pattern.name,
                    category=pattern.category,
                    severity=pattern.severity,
                    file_path=file_path,
                    start_offset=start_offset,
                    end_offset=end_offset,
                    line_number=line_number,
                    column_number=column_number,
                    matched_text=match.group(0),
                    base_confidence=pattern.base_confidence,
                    provider=pattern.provider,
                )
            )

        return results

    # Convert a zero-based string offset into one-based line and column numbers.
    @staticmethod
    def _get_line_and_column(content: str, offset: int) -> tuple[int, int]:
        line_number = content.count("\n", 0, offset) + 1
        last_newline = content.rfind("\n", 0, offset)

        if last_newline == -1:
            column_number = offset + 1
        else:
            column_number = offset - last_newline

        return line_number, column_number