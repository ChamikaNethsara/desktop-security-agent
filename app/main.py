from __future__ import annotations

import logging
import sys
from pathlib import Path

from scanner.file_reader import FileReadStatus
from app.application import SecurityAgentApplication

def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format=("%(asctime)s | %(levelname)s | %(name)s | %(message)s")
    )


def main() -> int:
    configure_logging()

    if len(sys.argv) < 2:
        print("Usage:\n    python -m app.main <project_directory>")
        return 1

    project_directory = Path(sys.argv[1])

    if not project_directory.exists():
        print(f"Directory does not exist: {project_directory}")
        return 1

    if not project_directory.is_dir():
        print(f"Path is not a directory: {project_directory}")
        return 1

    application = SecurityAgentApplication(monitored_directories=[project_directory])

    try:
        application.start()

        print()
        print("Desktop Security Agent is running.")
        print(f"Monitoring: {project_directory}")
        print()
        print("Press Ctrl+C to stop.")

        while True:
            # Process queued files.
            if not application.event_queue.empty():
                application.process_next_file()

    except KeyboardInterrupt:
        print()
        print("Stopping...")

    finally:
        application.stop()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())