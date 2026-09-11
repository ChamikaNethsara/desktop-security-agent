from __future__ import annotations

import logging
from pathlib import Path
from typing import Callable

from watchdog.events import FileSystemEventHandler, FileSystemEvent
from watchdog.observers import Observer

logger = logging.getLogger(__name__)


class ProjectFileEventHandler(FileSystemEventHandler):
    """
    Converts watchdog filesystem events into file-path events.
    """

    def __init__(self, on_file_event: Callable[[Path], None]) -> None:
        super().__init__()
        self._on_file_event = on_file_event

    def on_created(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        self._emit(event.src_path)

    def on_modified(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        self._emit(event.src_path)

    def on_moved(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        self._emit(event.dest_path)

    def _emit(self, path: str) -> None:
        file_path = Path(path)
        logger.debug("Filesystem event received: %s", file_path)
        self._on_file_event(file_path)


class FileWatcher:
    """
    Monitors configured project directories for filesystem changes.
    """

    def __init__(self, on_file_event: Callable[[Path], None]) -> None:
        self._observer = Observer()
        self._event_handler = ProjectFileEventHandler(on_file_event)

        self._watched_directories: set[Path] = set()
        self._started = False


    # Add a directory to the watch list.
    def add_directory(self, directory: Path) -> None:
        directory = directory.expanduser().resolve()

        if not directory.exists():
            raise FileNotFoundError(f"Directory does not exist: {directory}")

        if not directory.is_dir():
            raise NotADirectoryError(f"Path is not a directory: {directory}")

        if directory in self._watched_directories:
            logger.debug("Directory already being monitored: %s", directory)
            return

        self._observer.schedule(self._event_handler, str(directory), recursive=True)
        self._watched_directories.add(directory)

        logger.info("Monitoring project directory: %s", directory)


    # Start the watchdog observer.
    def start(self) -> None:
        if self._started:
            return

        if not self._watched_directories:
            raise RuntimeError("No project directories have been configured.")

        self._observer.start()
        self._started = True

        logger.info("File watcher started.")


    # Stop the watchdog observer safely.
    def stop(self) -> None:
        if not self._started:
            return

        logger.info("Stopping file watcher...")

        self._observer.stop()
        self._observer.join()
        self._started = False

        logger.info("File watcher stopped.")


    # Return currently monitored directories.
    @property
    def watched_directories(self) -> tuple[Path, ...]:
        return tuple(self._watched_directories)