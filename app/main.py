
from __future__ import annotations

import logging
import sys
import time
from pathlib import Path

from app.application import SecurityAgentApplication
from auditor.auditor import ConfigurationAuditor
from auditor.file_discovery import discover_files
from auditor.report import print_audit_report


# --------------------------------------------------
# Logging Configuration
# --------------------------------------------------

def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


# --------------------------------------------------
# Static Configuration Risk Auditor
# --------------------------------------------------

def run_audit(project_directory: Path) -> None:
    """
    Scan a project directory for insecure configurations.

    Detects configuration risks using CFG-001 to CFG-010,
    calculates the risk score, and prints the audit report.
    """

    print("\nStarting Static Configuration Risk Auditor...\n")

    auditor = ConfigurationAuditor()

    # Discover supported configuration files.
    files = discover_files(project_directory)

    # Run configuration security rules.
    findings = auditor.audit_project(project_directory)

    # Display findings, risk score, and recommendations.
    print_audit_report(
        project_directory,
        files,
        findings,
    )


# --------------------------------------------------
# Real-Time Desktop Security Agent
# --------------------------------------------------

def run_agent(project_directory: Path) -> None:
    """
    Start the real-time security agent.

    Monitor the selected project directory and process
    queued file events until the user stops the agent.
    """

    configure_logging()

    application = SecurityAgentApplication(
        monitored_directories=[project_directory]
    )

    try:
        application.start()

        print("\n==============================================")
        print("DESKTOP SECURITY AGENT")
        print("==============================================")
        print(f"Monitoring: {project_directory}")
        print("Status: Running")
        print("Press Ctrl+C to stop.")
        print("==============================================\n")

        while True:
            if not application.event_queue.empty():
                application.process_next_file()
            else:
                # Avoid consuming excessive CPU while idle.
                time.sleep(0.1)

    except KeyboardInterrupt:
        print("\nStopping Desktop Security Agent...")

    finally:
        application.stop()
        print("Desktop Security Agent stopped.")


# --------------------------------------------------
# Main Entry Point
# --------------------------------------------------

def main() -> int:
    """
    Select the execution mode.

    Default:
        Run the Static Configuration Risk Auditor.

    --watch:
        Run the Real-Time Desktop Security Agent.
    """

    arguments = sys.argv[1:]

    # Determine whether real-time monitoring is requested.
    watch_mode = "--watch" in arguments

    # Remove the optional flag from positional arguments.
    arguments = [
        argument
        for argument in arguments
        if argument != "--watch"
    ]

    # Validate command-line arguments.
    if len(arguments) != 1:
        print(
            "\nUsage:\n"
            "  python -m app.main <project_directory>\n"
            "  python -m app.main <project_directory> --watch\n"
        )
        return 1

    # Resolve the supplied project directory.
    project_directory = Path(arguments[0]).expanduser().resolve()

    if not project_directory.is_dir():
        print(
            f"\nError: Invalid project directory: "
            f"{project_directory}"
        )
        return 1

    try:
        if watch_mode:
            run_agent(project_directory)
        else:
            run_audit(project_directory)

    except Exception:
        logging.exception("Security Agent execution failed")
        return 1

    return 0


# --------------------------------------------------
# Program Execution
# --------------------------------------------------

if __name__ == "__main__":
    raise SystemExit(main())