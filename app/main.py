
from __future__ import annotations

import logging
import sys
from pathlib import Path

from app.application import SecurityAgentApplication
from auditor.auditor import ConfigurationAuditor
from auditor.file_discovery import discover_files
from auditor.report import print_audit_report


def configure_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )


def run_audit(project_directory):
    auditor = ConfigurationAuditor()

    files = discover_files(project_directory)
    findings = auditor.audit_project(project_directory)

    print_audit_report(
        project_directory,
        files,
        findings
    )


def run_agent(project_directory):
    configure_logging()

    application = SecurityAgentApplication(
        monitored_directories=[project_directory]
    )

    try:
        application.start()

        print("\nDesktop Security Agent is running.")
        print(f"Monitoring: {project_directory}")
        print("Press Ctrl+C to stop.\n")

        while True:
            if not application.event_queue.empty():
                application.process_next_file()

    except KeyboardInterrupt:
        print("\nStopping agent...")

    finally:
        application.stop()


def main():
    arguments = sys.argv[1:]

    watch_mode = "--watch" in arguments
    arguments = [arg for arg in arguments if arg != "--watch"]

    if len(arguments) != 1:
        print(
            "Usage:\n"
            "  python -m app.main <project_directory>\n"
            "  python -m app.main <project_directory> --watch"
        )
        return 1

    project_directory = Path(arguments[0])

    if not project_directory.is_dir():
        print(f"Invalid project directory: {project_directory}")
        return 1

    if watch_mode:
        run_agent(project_directory)
    else:
        run_audit(project_directory)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())