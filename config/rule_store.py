"""
Rule store used by the Settings GUI.

Reads and edits pattern_rules.yaml / file_rules.yaml without the user having to
touch YAML. Every change is validated with the same code the scanner uses
(RuleLoader / PatternRegistry) *before* it is written, so the GUI can never
leave the application with a configuration file that fails to load.
"""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Any

import yaml

from config.rule_loader import RuleConfigurationError, RuleLoader
from scanner.models import SecretCategory, SecretPattern, SecretSeverity
from scanner.patterns import BUILT_IN_PATTERNS, PatternRegistry
from scanner.scan_config import FileScanConfig

PATTERN_FIELDS = (
    "pattern_id",
    "name",
    "category",
    "provider",
    "regex",
    "severity",
    "base_confidence",
    "entropy_required",
    "context_required",
    "enabled",
    "description",
)

FILE_RULE_KEYS = (
    "included_filenames",
    "included_extensions",
    "included_name_patterns",
    "excluded_directories",
)

CATEGORIES = tuple(category.value for category in SecretCategory)
SEVERITIES = tuple(
    severity.value
    for severity in (
        SecretSeverity.CRITICAL,
        SecretSeverity.HIGH,
        SecretSeverity.MEDIUM,
        SecretSeverity.LOW,
    )
)

_PATTERN_ID_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


class RuleStore:
    """Read/modify/write access to the two YAML rule files."""

    def __init__(self, pattern_rules_path: Path, file_rules_path: Path) -> None:
        self.pattern_rules_path = Path(pattern_rules_path)
        self.file_rules_path = Path(file_rules_path)

    # ------------------------------------------------------------------ #
    # Detection pattern rules
    # ------------------------------------------------------------------ #

    def list_pattern_rules(self) -> list[dict[str, Any]]:
        """
        Return every rule that is currently in effect (built-ins merged with
        the YAML overrides, plus custom rules) as plain dictionaries.

        Each dict carries an extra "source" key: "built-in", "modified"
        (built-in with overrides) or "custom".
        """
        effective = RuleLoader(self.pattern_rules_path).load_patterns(BUILT_IN_PATTERNS)
        built_ins = {p.pattern_id: self._pattern_to_dict(p) for p in BUILT_IN_PATTERNS}

        rules = []
        for pattern in effective:
            rule = self._pattern_to_dict(pattern)
            default = built_ins.get(pattern.pattern_id)
            if default is None:
                rule["source"] = "custom"
            elif rule != default:
                rule["source"] = "modified"
            else:
                rule["source"] = "built-in"
            rules.append(rule)
        return rules

    def save_pattern_rule(self, rule: dict[str, Any], *, original_id: str | None = None) -> None:
        """
        Create a new rule (original_id is None) or update an existing one.

        Built-in rules are stored as a minimal override (only the fields that
        differ from the built-in definition). Custom rules are stored in full.
        """
        rule = self.clean_rule(rule)
        pattern_id = rule["pattern_id"]
        built_ins = {p.pattern_id: p for p in BUILT_IN_PATTERNS}
        entries = self._read_pattern_entries()

        if original_id is None:
            if any(r.get("pattern_id") == pattern_id for r in entries) or pattern_id in built_ins:
                raise RuleConfigurationError(f"A rule with ID '{pattern_id}' already exists.")
        else:
            if pattern_id != original_id:
                raise RuleConfigurationError("The ID of an existing rule cannot be changed.")

        if pattern_id in built_ins:
            built_in = self._pattern_to_dict(built_ins[pattern_id])
            entry: dict[str, Any] = {"pattern_id": pattern_id}
            for field in PATTERN_FIELDS[1:]:
                if rule[field] != built_in[field]:
                    entry[field] = rule[field]
            new_entry = entry if len(entry) > 1 else None
        else:
            new_entry = {field: rule[field] for field in PATTERN_FIELDS}

        self._write_pattern_entries(self._replace_entry(entries, pattern_id, new_entry))

    def set_pattern_enabled(self, pattern_id: str, enabled: bool) -> None:
        current = next(
            (r for r in self.list_pattern_rules() if r["pattern_id"] == pattern_id), None
        )
        if current is None:
            raise RuleConfigurationError(f"Unknown rule '{pattern_id}'.")
        current["enabled"] = bool(enabled)
        self.save_pattern_rule(current, original_id=pattern_id)

    def delete_pattern_rule(self, pattern_id: str) -> None:
        """
        Delete a custom rule, or reset a built-in rule to its default values
        (built-in rules cannot be removed, only disabled).
        """
        entries = self._read_pattern_entries()
        self._write_pattern_entries(self._replace_entry(entries, pattern_id, None))

    # ------------------------------------------------------------------ #
    # File eligibility rules
    # ------------------------------------------------------------------ #

    def read_file_rules(self) -> dict[str, list[str]]:
        data = self._read_yaml(self.file_rules_path)
        section = data.get("file_scanning") or {}
        return {
            key: [str(v) for v in (section.get(key) or []) if isinstance(v, str)]
            for key in FILE_RULE_KEYS
        }

    def save_file_rules(self, rules: dict[str, list[str]]) -> None:
        cleaned: dict[str, list[str]] = {}
        for key in FILE_RULE_KEYS:
            seen: set[str] = set()
            values: list[str] = []
            for value in rules.get(key, []):
                value = str(value).strip()
                if not value:
                    raise RuleConfigurationError(f"'{key}' cannot contain empty values.")
                if value.casefold() in seen:
                    continue
                seen.add(value.casefold())
                values.append(value)
            cleaned[key] = values

        try:
            FileScanConfig.from_mapping(cleaned)
        except ValueError as exc:
            raise RuleConfigurationError(str(exc)) from exc

        data = self._read_yaml(self.file_rules_path)
        data.setdefault("version", 1)
        data["file_scanning"] = cleaned
        self._atomic_write(self.file_rules_path, data, validate=self._validate_file_rules)

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    @staticmethod
    def _pattern_to_dict(pattern: SecretPattern) -> dict[str, Any]:
        return {
            "pattern_id": pattern.pattern_id,
            "name": pattern.name,
            "category": pattern.category.value,
            "provider": pattern.provider or "",
            "regex": pattern.regex,
            "severity": pattern.severity.value,
            "base_confidence": float(pattern.base_confidence),
            "entropy_required": bool(pattern.entropy_required),
            "context_required": bool(pattern.context_required),
            "enabled": bool(pattern.enabled),
            "description": pattern.description or "",
        }

    @staticmethod
    def clean_rule(rule: dict[str, Any]) -> dict[str, Any]:
        """Normalize and validate a rule coming from the GUI."""
        pattern_id = str(rule.get("pattern_id", "")).strip()
        if not pattern_id:
            raise RuleConfigurationError("Pattern ID is required.")
        if not _PATTERN_ID_RE.match(pattern_id):
            raise RuleConfigurationError(
                "Pattern ID may only contain letters, digits, '_', '-' and '.'."
            )

        name = str(rule.get("name", "")).strip()
        if not name:
            raise RuleConfigurationError("Rule name is required.")

        regex = str(rule.get("regex", "")).strip()
        if not regex:
            raise RuleConfigurationError("Regular expression is required.")
        try:
            re.compile(regex, re.IGNORECASE)
        except re.error as exc:
            raise RuleConfigurationError(f"Invalid regular expression: {exc}") from exc

        category = str(rule.get("category", ""))
        if category not in CATEGORIES:
            raise RuleConfigurationError(f"Unknown category: {category!r}.")
        severity = str(rule.get("severity", ""))
        if severity not in SEVERITIES:
            raise RuleConfigurationError(f"Unknown severity: {severity!r}.")

        try:
            confidence = float(rule.get("base_confidence"))
        except (TypeError, ValueError):
            raise RuleConfigurationError("Confidence must be a number between 0 and 1.") from None
        if not 0.0 <= confidence <= 1.0:
            raise RuleConfigurationError("Confidence must be between 0.0 and 1.0.")

        return {
            "pattern_id": pattern_id,
            "name": name,
            "category": category,
            "provider": str(rule.get("provider") or "").strip(),
            "regex": regex,
            "severity": severity,
            "base_confidence": round(confidence, 4),
            "entropy_required": bool(rule.get("entropy_required", False)),
            "context_required": bool(rule.get("context_required", False)),
            "enabled": bool(rule.get("enabled", True)),
            "description": str(rule.get("description") or "").strip(),
        }

    @staticmethod
    def _replace_entry(
        entries: list[dict[str, Any]], pattern_id: str, new_entry: dict[str, Any] | None
    ) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        placed = False
        for entry in entries:
            if entry.get("pattern_id") == pattern_id:
                if new_entry is not None and not placed:
                    result.append(new_entry)
                placed = True
                continue
            result.append(entry)
        if new_entry is not None and not placed:
            result.append(new_entry)
        return result

    def _read_pattern_entries(self) -> list[dict[str, Any]]:
        data = self._read_yaml(self.pattern_rules_path)
        rules = data.get("rules") or []
        if not isinstance(rules, list):
            raise RuleConfigurationError("'rules' must be a list.")
        return [r for r in rules if isinstance(r, dict)]

    def _write_pattern_entries(self, entries: list[dict[str, Any]]) -> None:
        data = self._read_yaml(self.pattern_rules_path)
        data.setdefault("version", 1)
        data["rules"] = entries
        self._atomic_write(self.pattern_rules_path, data, validate=self._validate_pattern_rules)

    @staticmethod
    def _read_yaml(path: Path) -> dict[str, Any]:
        if not path.exists():
            return {}
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise RuleConfigurationError(f"Unable to read {path.name}: {exc}") from exc
        if data is None:
            return {}
        if not isinstance(data, dict):
            raise RuleConfigurationError(f"{path.name}: configuration root must be a mapping.")
        return data

    @staticmethod
    def _validate_pattern_rules(path: Path) -> None:
        patterns = RuleLoader(path).load_patterns(BUILT_IN_PATTERNS)
        PatternRegistry(patterns)  # compiles every regex

    @staticmethod
    def _validate_file_rules(path: Path) -> None:
        RuleLoader(path).load_file_rules()

    @staticmethod
    def _atomic_write(path: Path, data: dict[str, Any], *, validate) -> None:
        """Write to a temp file, validate it with the real loader, then swap it in."""
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=path.stem + ".", suffix=".tmp")
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                yaml.safe_dump(
                    data, handle, sort_keys=False, default_flow_style=False, allow_unicode=True
                )
            try:
                validate(tmp_path)
            except (RuleConfigurationError, ValueError) as exc:
                raise RuleConfigurationError(str(exc)) from exc
            os.replace(tmp_path, path)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()
