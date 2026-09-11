from __future__ import annotations

import logging
from pathlib import Path
from threading import Lock, Timer
from typing import Callable

logger = logging.getLogger(__name__)


class EventDebouncer:
    """
    Coalesces bursts of filesystem events for the same file.
    """

    def __init__(self, callback: Callable[[Path], None], delay_seconds: float) -> None:
        self._callback = callback
        self._delay_seconds = delay_seconds

        self._timers: dict[Path, Timer] = {}
        self._lock = Lock()


    # Registers an file system event and resets the timer for repeated events.
    def submit(self, path: Path) -> None:
        path = path.resolve()

        with self._lock:
            existing_timer = self._timers.pop(path, None)

            if existing_timer is not None:
                existing_timer.cancel()

            timer = Timer(self._delay_seconds, self._fire, args=(path,))
            timer.daemon = True
            self._timers[path] = timer
            timer.start()

        logger.debug("Filesystem event debounced: %s", path)


    def _fire(self, path: Path) -> None:
        with self._lock:
            self._timers.pop(path, None)

        logger.debug("Debounce period completed: %s", path)
        self._callback(path)


    # Cancel all pending debounce timers.
    def shutdown(self) -> None:
        with self._lock:
            timers = list(self._timers.values())
            self._timers.clear()

        for timer in timers:
            timer.cancel()