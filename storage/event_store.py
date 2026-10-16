from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

from scanner.fingerprint import FindingFingerprintGenerator
from scanner.models import SecretFinding


class SQLiteEventStore:
    """
    Persistent local event store for SecretFinding objects (Only finding metadata is stored).
    """

    def __init__(self, database_path: Path) -> None:
        self._database_path = database_path.expanduser().resolve()
        self._database_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._connection = sqlite3.connect(self._database_path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row

        self._configure_database()
        self._create_schema()


    # Apply SQLite configuration suitable for the local desktop security agent.
    def _configure_database(self) -> None:
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._connection.execute("PRAGMA synchronous = NORMAL")
        self._connection.execute("PRAGMA busy_timeout = 5000")

        self._connection.commit()


    # Create the database schema if it does not already exist.
    def _create_schema(self) -> None:
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS secret_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                fingerprint TEXT NOT NULL UNIQUE,

                file_path TEXT NOT NULL,
                line_number INTEGER NOT NULL,

                pattern_id TEXT NOT NULL,
                pattern_name TEXT NOT NULL,

                category TEXT NOT NULL,
                severity TEXT NOT NULL,

                confidence REAL NOT NULL,
                confidence_level TEXT NOT NULL,

                regex_score REAL NOT NULL,
                context_score REAL NOT NULL,
                entropy_score REAL NOT NULL,

                is_placeholder INTEGER NOT NULL,
                is_comment INTEGER NOT NULL,

                description TEXT NOT NULL,

                detected_at TEXT NOT NULL
            )
            """
        )

        self._connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_secret_findings_detected_at
            ON secret_findings(detected_at)
            """
        )

        self._connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_secret_findings_severity
            ON secret_findings(severity)
            """
        )

        self._connection.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_secret_findings_file_path
            ON secret_findings(file_path)
            """
        )

        self._connection.commit()


    # Persist a SecretFinding and return its fingerprint.
    def save(self, finding: SecretFinding) -> str:
        fingerprint = (FindingFingerprintGenerator.generate(finding))

        with self._lock:
            self._connection.execute(
                """
                INSERT OR IGNORE INTO secret_findings (
                    fingerprint,
                    file_path,
                    line_number,
                    pattern_id,
                    pattern_name,
                    category,
                    severity,
                    confidence,
                    confidence_level,
                    regex_score,
                    context_score,
                    entropy_score,
                    is_placeholder,
                    is_comment,
                    description,
                    detected_at
                )
                VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    fingerprint,
                    str(finding.file_path),
                    finding.line_number,
                    finding.pattern_id,
                    finding.pattern_name,
                    finding.category.value,
                    finding.severity.value,
                    finding.confidence,
                    finding.confidence_level.value,
                    finding.regex_score,
                    finding.context_score,
                    finding.entropy_score,
                    int(finding.is_placeholder),
                    int(finding.is_comment),
                    finding.description,
                    finding.detected_at.isoformat(),
                ),
            )

            self._connection.commit()

        return fingerprint


    # Return the total number of persisted findings.
    def count(self) -> int:
        with self._lock:
            cursor = self._connection.execute(
                """
                SELECT COUNT(*)
                FROM secret_findings
                """
            )

            row = cursor.fetchone()

        return int(row[0])


    # Close the SQLite connection.
    def close(self) -> None:
        with self._lock:
            self._connection.close()


    def __enter__(self) -> SQLiteEventStore:
        return self


    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()