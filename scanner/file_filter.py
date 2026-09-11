from __future__ import annotations

import fnmatch
from pathlib import Path

from config.default_config import (
    EXCLUDED_DIRECTORIES,
    INCLUDED_EXTENSIONS,
    INCLUDED_FILENAMES,
    INCLUDED_NAME_PATTERNS,
)


class FileEligibilityFilter:
    """
    Determines whether a filesystem path is allowed to enter the scanning pipeline.
    """

    def __init__(
            self,
            monitored_directories: set[Path],
            included_filenames: set[str] | None = None,
            included_extensions: set[str] | None = None,
            included_name_patterns: set[str] | None = None,
            excluded_directories: set[str] | None = None
            ) -> None:

        self._monitored_directories = {
            directory.expanduser().resolve()
            for directory in monitored_directories
        }

        self._included_filenames = (
            included_filenames
            if included_filenames is not None
            else INCLUDED_FILENAMES
        )

        self._included_extensions = (
            included_extensions
            if included_extensions is not None
            else INCLUDED_EXTENSIONS
        )

        self._included_name_patterns = (
            included_name_patterns
            if included_name_patterns is not None
            else INCLUDED_NAME_PATTERNS
        )

        self._excluded_directories = (
            excluded_directories
            if excluded_directories is not None
            else EXCLUDED_DIRECTORIES
        )

        self._normalized_filenames = {
            name.lower()
            for name in self._included_filenames
        }

        self._normalized_extensions = {
            extension.lower()
            for extension in self._included_extensions
        }

        self._normalized_excluded_directories = {
            directory.lower()
            for directory in self._excluded_directories
        }


    # Determine whether a path is allowed into the scanning pipeline.
    def is_eligible(self, path: Path) -> bool:
        path = path.expanduser().resolve()

        if not self._is_within_monitored_scope(path):
            return False

        if not path.exists():
            return False

        if not path.is_file():
            return False

        if self._is_inside_excluded_directory(path):
            return False

        filename = path.name.lower()

        if filename in self._normalized_filenames:
            return True

        if path.suffix.lower() in self._normalized_extensions:
            return True

        if self._matches_name_pattern(filename):
            return True

        return False


    def _is_within_monitored_scope(self, path: Path) -> bool:
        for directory in self._monitored_directories:
            try:
                path.relative_to(directory)
                return True
            except ValueError:
                continue

        return False


    def _is_inside_excluded_directory(self, path: Path) -> bool:
        return any(
            part.lower() in self._normalized_excluded_directories
            for part in path.parts
        )


    def _matches_name_pattern(self, filename: str) -> bool:
        for pattern in self._included_name_patterns:
            pattern = pattern.lower()

            if fnmatch.fnmatch(filename, f"{pattern}.*"):
                return True

            if fnmatch.fnmatch(filename, f"{pattern}-*"):
                return True

            if fnmatch.fnmatch(filename, f"{pattern}_*"):
                return True

        return False