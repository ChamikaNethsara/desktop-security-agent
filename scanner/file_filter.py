from __future__ import annotations

import fnmatch
from pathlib import Path

from scanner.scan_config import FileScanConfig


class FileEligibilityFilter:
    """
    Determines whether a filesystem path is allowed to enter the scanning pipeline.
    """

    def __init__(self, monitored_directories: set[Path], scan_config: FileScanConfig) -> None:
        self._monitored_directories = {
            directory.expanduser().resolve()
            for directory in monitored_directories
        }

        self._scan_config = scan_config

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

        filename = path.name.casefold()

        if filename in self._scan_config.included_filenames:
            return True

        if path.suffix.casefold() in self._scan_config.included_extensions:
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
            part.casefold()
            in self._scan_config.excluded_directories
            for part in path.parts
        )


    def _matches_name_pattern(self, filename: str) -> bool:
        for pattern in self._scan_config.included_name_patterns:
            if fnmatch.fnmatch(filename, f"{pattern}.*"):
                return True

            if fnmatch.fnmatch(filename, f"{pattern}-*"):
                return True

            if fnmatch.fnmatch(filename, f"{pattern}_*"):
                return True

        return False


    @property
    def excluded_directories(self) -> frozenset[str]:
        return self._scan_config.excluded_directories