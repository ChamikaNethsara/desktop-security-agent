from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any
import yaml

from scanner.models import (SecretCategory, SecretPattern, SecretSeverity)


class RuleConfigurationError(ValueError):
    """
    Raised when the external rule configuration is invalid.
    """


class RuleLoader:
    """
    Loads and validates externally configured detection rules.
    YAML configuration can:
        - enable or disable built-in rules
        - override built-in rule properties
        - define new custom rules
    """

    def __init__(self, configuration_path: Path,) -> None:
        self._configuration_path = (configuration_path.expanduser().resolve())

    # Merge built-in patterns with configured rules
    # Existing pattern IDs override built-ins and new pattern IDs are added as custom rules.
    def load(self, built_in_patterns: tuple[SecretPattern, ...]) -> tuple[SecretPattern, ...]:
        if not self._configuration_path.exists():
            return built_in_patterns

        if not self._configuration_path.is_file():
            raise RuleConfigurationError("Rule configuration path is not a file.")

        try:
            with self._configuration_path.open("r", encoding="utf-8") as file:
                configuration = yaml.safe_load(file)

        except (OSError, yaml.YAMLError) as exc:
            raise RuleConfigurationError(f"Unable to load rule configuration: {exc}") from exc

        if configuration is None:
            return built_in_patterns

        if not isinstance(configuration, dict):
            raise RuleConfigurationError("Rule configuration root must be a mapping.")

        configured_rules = configuration.get("rules", [])

        if not isinstance(configured_rules, list):
            raise RuleConfigurationError("'rules' must be a list.")

        pattern_map = {pattern.pattern_id: pattern for pattern in built_in_patterns}

        for rule in configured_rules:
            if not isinstance(rule, dict):
                raise RuleConfigurationError("Each rule must be a mapping.")

            pattern = self._resolve_rule(rule, pattern_map)
            pattern_map[pattern.pattern_id] = pattern

        return tuple(pattern_map.values())

    # Resolve either a built-in override or a new custom rule.
    def _resolve_rule(self, rule: dict[str, Any], existing_patterns: dict[str, SecretPattern]) -> SecretPattern:
        pattern_id = rule.get("pattern_id")

        if not isinstance(pattern_id, str) or not pattern_id.strip():
            raise RuleConfigurationError("Each rule requires a non-empty pattern_id.")

        existing = existing_patterns.get(pattern_id)
        if existing is not None:
            return self._override_existing(existing, rule)

        return self._create_new_pattern(rule)


    # Override selected properties of an existing pattern.
    def _override_existing(self, existing: SecretPattern, rule: dict[str, Any]) -> SecretPattern:
        allowed_fields = {
            "name",
            "category",
            "regex",
            "severity",
            "base_confidence",
            "provider",
            "entropy_required",
            "context_required",
            "description",
            "enabled",
        }

        unknown_fields = set(rule) - ({"pattern_id"} | allowed_fields)
        if unknown_fields:
            raise RuleConfigurationError("Unknown rule fields: " + ", ".join(sorted(unknown_fields)))

        values: dict[str, Any] = {}

        if "name" in rule:
            values["name"] = self._require_string(rule["name"], "name")

        if "category" in rule:
            values["category"] = self._parse_category(rule["category"])

        if "regex" in rule:
            values["regex"] = self._require_string(rule["regex"], "regex")

        if "severity" in rule:
            values["severity"] = self._parse_severity(rule["severity"])

        if "base_confidence" in rule:
            values["base_confidence"] = self._parse_confidence(rule["base_confidence"])

        if "provider" in rule:
            provider = rule["provider"]

            if provider is not None and not isinstance(provider, str):
                raise RuleConfigurationError("provider must be a string or null.")
            
            values["provider"] = provider

        if "entropy_required" in rule:
            values["entropy_required"] = self._parse_bool(rule["entropy_required"], "entropy_required")

        if "context_required" in rule:
            values["context_required"] = self._parse_bool(rule["context_required"], "context_required")

        if "description" in rule:
            values["description"] = self._require_string(rule["description"], "description")

        if "enabled" in rule:
            values["enabled"] = self._parse_bool(rule["enabled"], "enabled")

        return replace(existing, **values)


    # Create a completely new SecretPattern from YAML.
    def _create_new_pattern(self, rule: dict[str, Any]) -> SecretPattern:
        required_fields = {
            "name",
            "category",
            "regex",
            "severity",
            "base_confidence",
        }

        missing_fields = required_fields - set(rule)
        if missing_fields:
            raise RuleConfigurationError("New rule is missing required fields: " + ", ".join(sorted(missing_fields)))

        allowed_fields = {
            "pattern_id",
            "name",
            "category",
            "regex",
            "severity",
            "base_confidence",
            "provider",
            "entropy_required",
            "context_required",
            "description",
            "enabled",
        }

        unknown_fields = set(rule) - allowed_fields
        if unknown_fields:
            raise RuleConfigurationError("Unknown rule fields: " + ", ".join(sorted(unknown_fields)))

        provider = rule.get("provider")
        if provider is not None and not isinstance(provider, str):
            raise RuleConfigurationError("provider must be a string or null.")

        return SecretPattern(
            pattern_id=rule["pattern_id"],
            name=self._require_string(rule["name"], "name"),
            category=self._parse_category(rule["category"]),
            regex=self._require_string(rule["regex"], "regex"),
            severity=self._parse_severity(rule["severity"]),
            base_confidence=self._parse_confidence(rule["base_confidence"]),
            provider=provider,
            entropy_required=self._parse_bool(rule.get("entropy_required", False), "entropy_required"),
            context_required=self._parse_bool(rule.get("context_required", False), "context_required"),
            description=str(rule.get("description", "")),
            enabled=self._parse_bool(rule.get("enabled", True), "enabled"),
        )


    @staticmethod
    def _require_string(value: Any, field_name: str,) -> str:
        if not isinstance(value, str) or not value.strip():
            raise RuleConfigurationError(f"{field_name} must be a non-empty string.")
        return value


    @staticmethod
    def _parse_bool(value: Any, field_name: str) -> bool:
        if not isinstance(value, bool):
            raise RuleConfigurationError(f"{field_name} must be true or false.")
        return value


    @staticmethod
    def _parse_confidence(value: Any,) -> float:

        if (isinstance(value, bool) or not isinstance(value, (int, float))):
            raise RuleConfigurationError("base_confidence must be a number.")

        confidence = float(value)
        if not 0.0 <= confidence <= 1.0:
            raise RuleConfigurationError("base_confidence must be between 0.0 and 1.0.")
        
        return confidence


    @staticmethod
    def _parse_category(value: Any) -> SecretCategory:
        if not isinstance(value, str):
            raise RuleConfigurationError("category must be a string.")

        try:
            return SecretCategory(value)
        except ValueError as exc:
            raise RuleConfigurationError(f"Unknown secret category: {value}") from exc


    @staticmethod
    def _parse_severity(value: Any) -> SecretSeverity:
        if not isinstance(value, str):
            raise RuleConfigurationError("severity must be a string.")

        try:
            return SecretSeverity(value)
        except ValueError as exc:
            raise RuleConfigurationError(f"Unknown severity: {value}") from exc