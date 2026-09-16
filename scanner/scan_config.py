from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class FileScanConfig:
    """
    Defines the file and directory selection policy used by the file eligibility filter.
    """

    included_filenames: frozenset[str]
    included_extensions: frozenset[str]
    included_name_patterns: frozenset[str]
    excluded_directories: frozenset[str]

    # Create a FileScanConfig from the file_scanning section of the YAML configuration.
    @classmethod
    def from_mapping(cls, data: dict) -> "FileScanConfig":
        if not isinstance(data, dict):
            raise ValueError("'file_scanning' configuration must be a mapping.")

        return cls(
            included_filenames=cls._normalize_values(
                data.get("included_filenames", []), "included_filenames"
            ),
            included_extensions=cls._normalize_values(
                data.get("included_extensions", []), "included_extensions"
            ),
            included_name_patterns=cls._normalize_values(
                data.get("included_name_patterns", []), "included_name_patterns"
            ),
            excluded_directories=cls._normalize_values(
                data.get("excluded_directories", []), "excluded_directories"
            ),
        )

    @staticmethod
    def _normalize_values(values: object, field_name: str) -> frozenset[str]:
        if not isinstance(values, list):
            raise ValueError(f"'{field_name}' must be a list.")

        normalized: set[str] = set()

        for value in values:
            if not isinstance(value, str):
                raise ValueError(f"Every value in '{field_name}' must be a string.")

            value = value.strip()
            if not value:
                raise ValueError(f"'{field_name}' cannot contain empty values.")

            normalized.add(value.casefold())

        return frozenset(normalized)