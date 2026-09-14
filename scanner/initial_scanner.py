from __future__ import annotations

import logging
import os
from pathlib import Path

from scanner.file_filter import FileEligibilityFilter
from scanner.event_queue import ScanEventQueue

logger = logging.getLogger(__name__)


class InitialProjectScanner:
    """
    Discovers eligible files that already exist inside the configured project directories.
    Initial scanning only discovers and queues files.
    """

    def __init__(
            self,
            monitored_directories: set[Path],
            file_filter: FileEligibilityFilter,
            event_queue: ScanEventQueue,
            ) -> None:

        self._monitored_directories = monitored_directories
        self._file_filter = file_filter
        self._event_queue = event_queue


    # Discover existing eligible files and add them to the normal scan queue and return the count
    def scan(self) -> int:
        queued_count = 0

        for directory in self._monitored_directories:
            if not directory.exists():
                logger.warning("Monitored directory does not exist: %s", directory)
                continue

            if not directory.is_dir():
                logger.warning("Monitored path is not a directory: %s", directory)
                continue

            for root, directories, filenames in os.walk(directory, topdown=True, followlinks=False):
                root_path = Path(root)

                # Prevent traversal into known excluded directories.
                directories[:] = [
                    name
                    for name in directories
                    if name not in {
                        ".git",
                        ".svn",
                        ".hg",
                        "node_modules",
                        "venv",
                        ".venv",
                        "__pycache__",
                        "build",
                        "dist",
                        ".idea",
                        ".vscode",
                    }
                ]

                for filename in filenames:
                    path = root_path / filename

                    if not self._file_filter.is_eligible(path):
                        continue

                    if self._event_queue.put(path):
                        queued_count += 1

        logger.info("Initial project scan completed: %d eligible files queued.", queued_count)
        return queued_count