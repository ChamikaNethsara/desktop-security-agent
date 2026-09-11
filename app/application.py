from __future__ import annotations

import logging
from pathlib import Path

from config.default_config import (DEBOUNCE_DELAY_SECONDS)
from scanner.debouncer import EventDebouncer
from scanner.event_queue import ScanEventQueue
from scanner.file_filter import FileEligibilityFilter
from scanner.file_reader import (FileReadStatus, SecureFileReader)
from scanner.watcher import FileWatcher

from scanner.patterns import (PatternRegistry, create_default_pattern_registry)

logger = logging.getLogger(__name__)


class SecurityAgentApplication:
    """
    Coordinates the first six stages of the security agent.
    """

    def __init__(self, monitored_directories: list[Path]) -> None:
        self._monitored_directories = {
            directory.expanduser().resolve()
            for directory in monitored_directories
        }

        if not self._monitored_directories:
            raise ValueError("At least one monitored directory is required.")

        self._event_queue = ScanEventQueue()
        self._file_filter = FileEligibilityFilter(monitored_directories=self._monitored_directories)
        self._file_reader = SecureFileReader()
        self._debouncer = EventDebouncer(callback=self._handle_debounced_event, delay_seconds=DEBOUNCE_DELAY_SECONDS)
        self._watcher = FileWatcher(on_file_event=self._handle_file_event)

        for directory in self._monitored_directories:
            self._watcher.add_directory(directory)

        self._pattern_registry: PatternRegistry = (create_default_pattern_registry())


    # Called by the filesystem watcher and passes the event to the debounce layer.
    def _handle_file_event(self, path: Path) -> None:
        self._debouncer.submit(path)


    # Called after the debounce period and queues the path only if it is eligible for scanning.
    def _handle_debounced_event(self, path: Path) -> None:
        if not self._file_filter.is_eligible(path):
            logger.debug("File is not eligible for scanning: %s", path)
            return
        
        self._event_queue.put(path)


    # Process one file from the queue
    def process_next_file(self) -> None:
        path = self._event_queue.get()

        try:
            result = self._file_reader.read(path)

            if result.status is not FileReadStatus.SUCCESS:
                logger.debug("File could not be processed: %s (%s)", path, result.status.value)
                return

            logger.info(
                "Eligible file read successfully: %s (%d bytes, %s)",
                path,
                result.size_bytes,
                result.encoding
            )

        finally:
            self._event_queue.task_done()


    def start(self) -> None:
        logger.info("Starting Desktop Security Agent...")

        self._watcher.start()

        logger.info("Desktop Security Agent started.")


    def stop(self) -> None:
        logger.info("Stopping Desktop Security Agent...")

        self._debouncer.shutdown()
        self._watcher.stop()

        logger.info("Desktop Security Agent stopped.")


    @property
    def event_queue(self) -> ScanEventQueue:
        return self._event_queue

    @property
    def pattern_registry(self) -> PatternRegistry:
        return self._pattern_registry