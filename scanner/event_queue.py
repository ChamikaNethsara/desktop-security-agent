from __future__ import annotations

import logging
from pathlib import Path
from queue import Empty, Full, Queue
from threading import Lock

from config.default_config import MAX_QUEUE_SIZE

logger = logging.getLogger(__name__)


class ScanEventQueue:
    """
    Thread-safe queue used to transfer filesystem events from the monitoring layer to 
    future scanning workers.
    """

    def __init__(self, max_size: int = MAX_QUEUE_SIZE) -> None:
        self._queue: Queue[Path] = Queue(maxsize=max_size)

        # Prevent the same path from being queued multiple times simultaneously.
        self._pending_paths: set[Path] = set()
        self._lock = Lock()


    # Add a path to the queue and return False if it is already waiting or the queue is full.
    def put(self, path: Path) -> bool:
        path = path.resolve()

        with self._lock:
            if path in self._pending_paths:
                logger.debug("Path already waiting in scan queue: %s", path)
                return False

            try:
                self._queue.put_nowait(path)
            except Full:
                logger.error("Scan queue is full. Event dropped: %s", path)
                return False

            self._pending_paths.add(path)

        logger.debug("Path added to scan queue: %s", path)
        return True


    # Retrieve the next path from the queue and remove it from the pending set.
    def get(self, timeout: float | None = None) -> Path:
        path = self._queue.get(timeout=timeout)
        with self._lock:
            self._pending_paths.discard(path)

        return path


    # Mark the retrieved queue item as processed.
    def task_done(self) -> None:
        self._queue.task_done()

    def empty(self) -> bool:
        return self._queue.empty()

    def qsize(self) -> int:
        return self._queue.qsize()