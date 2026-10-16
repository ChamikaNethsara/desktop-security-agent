"""
storage/database.py
=====================
Component 2 — Secret Masking and Encrypted Storage Engine
Automated Desktop Security Agent (A.D.S.A.)

Responsibility
--------------
Local SQLite persistence layer for:
    * Finding metadata received from Component 1 (the scanner).
    * Isolated secrets — the AES-256-GCM ciphertext produced by
      storage.encryption once a finding has been masked, plus a link to
      the on-disk masking operation recorded by storage.masker.
    * A remediation event log (detected -> confirmed -> masked ->
      rolled_back -> ...), which Component 4 (dashboard) uses to render
      history/status and feed the security risk-scoring model.

Schema overview
----------------
findings
    One row per candidate secret / configuration finding. Mirrors the
    Component 1 schema field-for-field, plus a `status` lifecycle column
    this module manages.

isolated_secrets
    One row per confirmed secret that has actually been masked. Stores
    ONLY the AES-256-GCM ciphertext (via storage.encryption) — the raw
    secret value is never written to this database.

remediation_events
    Append-only audit trail of status transitions per finding. Contains
    only non-sensitive metadata (event type, timestamp, short note) —
    never a secret value.

Security design notes
----------------------
* `encrypted_value` in `isolated_secrets` is always produced by
  `storage.encryption.encrypt_secret` before it reaches this module's
  SQL layer; this module never writes a raw secret string to any column.
* No log statement, exception message, or returned dict/row in this
  module ever contains a raw secret value.
* Decrypting a stored secret (`get_decrypted_secret`) is provided for
  narrow, authorized internal flows only (e.g. key rotation) and is
  logged at WARNING level (metadata only) every time it's used, so
  access to plaintext is auditable.
* All SQL uses parameterised queries — no string-built SQL — to
  eliminate SQL injection regardless of what a finding's text fields
  contain.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from app.paths import secrets_database_path
from masking.encryption import decrypt_secret, encrypt_secret, DecryptionError, EncryptionError

logger = logging.getLogger("adsa.storage.database")

_DEFAULT_DB_PATH = secrets_database_path()


# --------------------------------------------------------------------------- #
# Exceptions
# --------------------------------------------------------------------------- #

class DatabaseError(Exception):
    """Raised for general database failures. Never contains secret material."""


class FindingNotFoundError(DatabaseError):
    """Raised when a referenced finding_id does not exist."""


class IsolationNotFoundError(DatabaseError):
    """Raised when a referenced isolated_secrets id does not exist."""


class InvalidStatusError(DatabaseError):
    """Raised when a status transition is not one of the recognised values."""


# --------------------------------------------------------------------------- #
# Status vocabularies
# --------------------------------------------------------------------------- #

class FindingStatus:
    """Lifecycle states for a finding. Stored as plain text so the schema
    stays forward-compatible with new states without a migration.
    """
    DETECTED = "detected"
    CONFIRMED = "confirmed"
    MASKED = "masked"
    ROLLED_BACK = "rolled_back"
    IGNORED = "ignored"
    FALSE_POSITIVE = "false_positive"
    VERIFIED = "verified"

    ALL = {DETECTED, CONFIRMED, MASKED, ROLLED_BACK, IGNORED, FALSE_POSITIVE, VERIFIED}
    RESOLVED = {MASKED, VERIFIED, IGNORED, FALSE_POSITIVE}


class IsolationStatus:
    MASKED = "masked"
    ROLLED_BACK = "rolled_back"

    ALL = {MASKED, ROLLED_BACK}


# --------------------------------------------------------------------------- #
# Input schema (matches Component 1 exactly)
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class FindingInput:
    """Candidate finding as received from Component 1 (the scanner)."""
    file_path: str
    line_number: int
    pattern_id: str
    pattern_name: str
    category: str
    severity: str
    confidence: float
    confidence_level: str
    regex_score: float
    context_score: float
    entropy_score: float
    is_placeholder: bool
    is_comment: bool
    detected_at: str  # ISO-8601 string, as produced by the scanner


# --------------------------------------------------------------------------- #
# Schema DDL
# --------------------------------------------------------------------------- #

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS findings (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    file_path           TEXT NOT NULL,
    line_number         INTEGER NOT NULL,
    pattern_id          TEXT,
    pattern_name        TEXT,
    category            TEXT,
    severity            TEXT,
    confidence          REAL,
    confidence_level    TEXT,
    regex_score         REAL,
    context_score       REAL,
    entropy_score       REAL,
    is_placeholder      INTEGER NOT NULL DEFAULT 0,
    is_comment          INTEGER NOT NULL DEFAULT 0,
    detected_at         TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'detected',
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_status    ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_severity  ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_category  ON findings(category);
CREATE INDEX IF NOT EXISTS idx_findings_file_path ON findings(file_path);
CREATE INDEX IF NOT EXISTS idx_findings_location  ON findings(file_path, line_number, pattern_id);

CREATE TABLE IF NOT EXISTS isolated_secrets (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id            INTEGER NOT NULL,
    variable_name         TEXT NOT NULL,
    placeholder           TEXT NOT NULL,
    encrypted_value       TEXT NOT NULL,
    masking_operation_id  TEXT,
    isolation_status      TEXT NOT NULL DEFAULT 'masked',
    isolated_at           TEXT NOT NULL,
    remediated_at         TEXT,
    created_at            TEXT NOT NULL,
    updated_at            TEXT NOT NULL,
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_isolated_finding ON isolated_secrets(finding_id);

CREATE TABLE IF NOT EXISTS remediation_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id   INTEGER NOT NULL,
    event_type   TEXT NOT NULL,
    event_at     TEXT NOT NULL,
    details      TEXT,
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_events_finding ON remediation_events(finding_id);
"""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# Database handler
# --------------------------------------------------------------------------- #

class SecretDatabase:
    """SQLite-backed storage for findings, encrypted secrets, and the
    remediation event history. Safe to share across threads within a
    single process (guarded by an internal lock); use one instance per
    process, not per-request.
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        configured_path = db_path or os.environ.get("ADSA_DB_PATH") or str(_DEFAULT_DB_PATH)
        self.db_path = Path(configured_path).expanduser().resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON;")
        self._conn.execute("PRAGMA journal_mode = WAL;")
        self._init_schema()
        logger.info("Database initialised at %s", self.db_path)

    def _init_schema(self) -> None:
        with self._lock, self._conn:
            self._conn.executescript(_SCHEMA_SQL)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "SecretDatabase":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    @contextmanager
    def _cursor(self) -> Iterator[sqlite3.Cursor]:
        with self._lock, self._conn:
            yield self._conn.cursor()

    # ----------------------------------------------------------------- #
    # Row conversion helpers
    # ----------------------------------------------------------------- #

    @staticmethod
    def _finding_row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        d["is_placeholder"] = bool(d["is_placeholder"])
        d["is_comment"] = bool(d["is_comment"])
        return d

    @staticmethod
    def _isolation_row_to_dict(row: sqlite3.Row, *, include_ciphertext: bool = True) -> Dict[str, Any]:
        d = dict(row)
        if not include_ciphertext:
            d.pop("encrypted_value", None)
        return d

    # ----------------------------------------------------------------- #
    # Findings CRUD
    # ----------------------------------------------------------------- #

    def insert_finding(self, finding: FindingInput) -> int:
        """Insert a new finding row and return its id."""
        now = _now_iso()
        with self._cursor() as cur:
            cur.execute(
                """
                INSERT INTO findings (
                    file_path, line_number, pattern_id, pattern_name, category,
                    severity, confidence, confidence_level, regex_score,
                    context_score, entropy_score, is_placeholder, is_comment,
                    detected_at, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding.file_path, finding.line_number, finding.pattern_id,
                    finding.pattern_name, finding.category, finding.severity,
                    finding.confidence, finding.confidence_level, finding.regex_score,
                    finding.context_score, finding.entropy_score,
                    int(finding.is_placeholder), int(finding.is_comment),
                    finding.detected_at, FindingStatus.DETECTED, now, now,
                ),
            )
            finding_id = cur.lastrowid

        self._log_event(finding_id, FindingStatus.DETECTED, note=f"pattern={finding.pattern_id}")
        logger.info(
            "Inserted finding id=%d file=%s line=%d category=%s severity=%s",
            finding_id, finding.file_path, finding.line_number, finding.category, finding.severity,
        )
        return finding_id

    def find_open_finding(self, file_path: str, line_number: int, pattern_id: str) -> Optional[Dict[str, Any]]:
        """Look up an unresolved finding at the same location/pattern, so
        callers can avoid flooding the table with duplicate rows every
        time an unchanged file is rescanned.
        """
        placeholders = ",".join("?" for _ in FindingStatus.RESOLVED)
        with self._cursor() as cur:
            cur.execute(
                f"""
                SELECT * FROM findings
                WHERE file_path = ? AND line_number = ? AND pattern_id = ?
                  AND status NOT IN ({placeholders})
                ORDER BY id DESC LIMIT 1
                """,
                (file_path, line_number, pattern_id, *FindingStatus.RESOLVED),
            )
            row = cur.fetchone()
        return self._finding_row_to_dict(row) if row else None

    def upsert_finding(self, finding: FindingInput) -> Dict[str, Any]:
        """Insert a finding, or refresh the scores/detected_at of an
        existing unresolved finding at the same (file, line, pattern).
        Returns {"finding_id": int, "created": bool}.
        """
        existing = self.find_open_finding(finding.file_path, finding.line_number, finding.pattern_id)
        if existing is None:
            return {"finding_id": self.insert_finding(finding), "created": True}

        now = _now_iso()
        with self._cursor() as cur:
            cur.execute(
                """
                UPDATE findings SET
                    confidence = ?, confidence_level = ?, regex_score = ?,
                    context_score = ?, entropy_score = ?, is_placeholder = ?,
                    is_comment = ?, detected_at = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    finding.confidence, finding.confidence_level, finding.regex_score,
                    finding.context_score, finding.entropy_score,
                    int(finding.is_placeholder), int(finding.is_comment),
                    finding.detected_at, now, existing["id"],
                ),
            )
        return {"finding_id": existing["id"], "created": False}

    def get_finding(self, finding_id: int) -> Dict[str, Any]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
            row = cur.fetchone()
        if row is None:
            raise FindingNotFoundError(f"No finding with id {finding_id}.")
        return self._finding_row_to_dict(row)

    def list_findings(
        self,
        *,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        file_path: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Query findings with optional filters, most recently detected first."""
        clauses: List[str] = []
        params: List[Any] = []

        if status is not None:
            clauses.append("status = ?")
            params.append(status)
        if severity is not None:
            clauses.append("severity = ?")
            params.append(severity)
        if category is not None:
            clauses.append("category = ?")
            params.append(category)
        if file_path is not None:
            clauses.append("file_path = ?")
            params.append(file_path)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.extend([limit, offset])

        with self._cursor() as cur:
            cur.execute(
                f"SELECT * FROM findings {where} ORDER BY detected_at DESC LIMIT ? OFFSET ?",
                params,
            )
            rows = cur.fetchall()
        return [self._finding_row_to_dict(r) for r in rows]

    def update_finding_status(self, finding_id: int, new_status: str, note: Optional[str] = None) -> None:
        """Transition a finding to a new lifecycle status and record the
        transition in the remediation event log.
        """
        if new_status not in FindingStatus.ALL:
            raise InvalidStatusError(f"'{new_status}' is not a recognised finding status.")

        now = _now_iso()
        with self._cursor() as cur:
            cur.execute("SELECT id FROM findings WHERE id = ?", (finding_id,))
            if cur.fetchone() is None:
                raise FindingNotFoundError(f"No finding with id {finding_id}.")
            cur.execute(
                "UPDATE findings SET status = ?, updated_at = ? WHERE id = ?",
                (new_status, now, finding_id),
            )

        self._log_event(finding_id, new_status, note=note)
        logger.info("Finding id=%d status -> %s", finding_id, new_status)

    def _log_event(self, finding_id: int, event_type: str, note: Optional[str] = None) -> None:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO remediation_events (finding_id, event_type, event_at, details) "
                "VALUES (?, ?, ?, ?)",
                (finding_id, event_type, _now_iso(), note),
            )

    def get_finding_history(self, finding_id: int) -> List[Dict[str, Any]]:
        """Chronological remediation event log for a finding (no secrets)."""
        with self._cursor() as cur:
            cur.execute(
                "SELECT * FROM remediation_events WHERE finding_id = ? ORDER BY event_at ASC",
                (finding_id,),
            )
            rows = cur.fetchall()
        return [dict(r) for r in rows]

    # ----------------------------------------------------------------- #
    # Isolated secrets (encrypted) CRUD
    # ----------------------------------------------------------------- #

    def store_isolated_secret(
        self,
        finding_id: int,
        raw_secret: str,
        variable_name: str,
        placeholder: str,
        masking_operation_id: Optional[str] = None,
    ) -> int:
        """Encrypt `raw_secret` and persist it against `finding_id`, then
        mark the finding as masked. Returns the isolated_secrets row id.

        `raw_secret` is used only in-memory to produce ciphertext via
        storage.encryption.encrypt_secret — it is never written to the
        database, a log line, or an exception message.
        """
        try:
            self.get_finding(finding_id)  # raises FindingNotFoundError if missing
        except FindingNotFoundError:
            raise

        try:
            ciphertext = encrypt_secret(raw_secret)
        except EncryptionError as exc:
            logger.error("Failed to encrypt secret for finding id=%d.", finding_id)
            raise DatabaseError("Unable to encrypt secret for storage.") from exc

        now = _now_iso()
        with self._cursor() as cur:
            cur.execute(
                """
                INSERT INTO isolated_secrets (
                    finding_id, variable_name, placeholder, encrypted_value,
                    masking_operation_id, isolation_status, isolated_at,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding_id, variable_name, placeholder, ciphertext,
                    masking_operation_id, IsolationStatus.MASKED, now, now, now,
                ),
            )
            isolation_id = cur.lastrowid

        self.update_finding_status(
            finding_id, FindingStatus.MASKED,
            note=f"variable={variable_name} operation_id={masking_operation_id}",
        )
        logger.info(
            "Stored isolated secret id=%d for finding id=%d (variable=%s).",
            isolation_id, finding_id, variable_name,
        )
        return isolation_id

    def get_isolated_secret(self, isolation_id: int) -> Dict[str, Any]:
        """Return isolation metadata INCLUDING ciphertext (safe — not
        plaintext). Use get_decrypted_secret() only if plaintext is
        actually required.
        """
        with self._cursor() as cur:
            cur.execute("SELECT * FROM isolated_secrets WHERE id = ?", (isolation_id,))
            row = cur.fetchone()
        if row is None:
            raise IsolationNotFoundError(f"No isolated secret with id {isolation_id}.")
        return self._isolation_row_to_dict(row)

    def list_isolated_secrets_for_finding(self, finding_id: int) -> List[Dict[str, Any]]:
        """Metadata only (ciphertext excluded) — safe for direct dashboard display."""
        with self._cursor() as cur:
            cur.execute(
                "SELECT * FROM isolated_secrets WHERE finding_id = ? ORDER BY isolated_at ASC",
                (finding_id,),
            )
            rows = cur.fetchall()
        return [self._isolation_row_to_dict(r, include_ciphertext=False) for r in rows]

    def get_decrypted_secret(self, isolation_id: int) -> str:
        """Decrypt and return the plaintext of a stored secret.

        Restricted-use accessor: intended only for narrow, authorized
        internal flows (e.g. re-encrypting under a rotated master key).
        Every call is logged at WARNING level (metadata only, never the
        plaintext) so plaintext access is auditable. Callers must not
        log, display, or persist the returned value.
        """
        record = self.get_isolated_secret(isolation_id)
        logger.warning(
            "Plaintext secret decrypted for isolation id=%d (finding id=%d). "
            "Caller is responsible for not persisting or displaying it.",
            isolation_id, record["finding_id"],
        )
        try:
            return decrypt_secret(record["encrypted_value"])
        except DecryptionError as exc:
            raise DatabaseError(f"Unable to decrypt isolated secret id={isolation_id}.") from exc

    def mark_isolation_rolled_back(self, isolation_id: int, revert_finding_to: str = FindingStatus.CONFIRMED) -> None:
        """Mark an isolated secret as rolled back (e.g. after
        storage.masker.rollback() has restored the original file) and
        move its finding back to an unresolved status.
        """
        record = self.get_isolated_secret(isolation_id)
        now = _now_iso()
        with self._cursor() as cur:
            cur.execute(
                "UPDATE isolated_secrets SET isolation_status = ?, remediated_at = ?, updated_at = ? WHERE id = ?",
                (IsolationStatus.ROLLED_BACK, now, now, isolation_id),
            )
        self.update_finding_status(
            record["finding_id"], revert_finding_to,
            note=f"isolation id={isolation_id} rolled back",
        )
        logger.info("Isolated secret id=%d marked rolled_back.", isolation_id)

    # ----------------------------------------------------------------- #
    # Aggregate stats for the dashboard / risk scoring model
    # ----------------------------------------------------------------- #
    def clear_all_findings(self) -> None:
        """Remove all findings, isolations and remediation events (fresh scan)."""
        with self._cursor() as cur:
            cur.execute("DELETE FROM remediation_events")
            cur.execute("DELETE FROM isolated_secrets")
            cur.execute("DELETE FROM findings")

    def get_dashboard_stats(self, recent_limit: int = 10) -> Dict[str, Any]:
        """Aggregate counts consumed by Component 4 (dashboard) and the
        security risk-scoring model (Component 3/coordinator).
        """
        with self._cursor() as cur:
            total = cur.execute("SELECT COUNT(*) AS c FROM findings").fetchone()["c"]

            by_status = {
                r["status"]: r["c"]
                for r in cur.execute("SELECT status, COUNT(*) AS c FROM findings GROUP BY status")
            }

            unresolved_placeholders = ",".join("?" for _ in FindingStatus.RESOLVED)
            unresolved_by_severity = {
                r["severity"]: r["c"]
                for r in cur.execute(
                    f"""
                    SELECT severity, COUNT(*) AS c FROM findings
                    WHERE status NOT IN ({unresolved_placeholders})
                    GROUP BY severity
                    """,
                    tuple(FindingStatus.RESOLVED),
                )
            }

            by_category = {
                r["category"]: r["c"]
                for r in cur.execute("SELECT category, COUNT(*) AS c FROM findings GROUP BY category")
            }

            recent_rows = cur.execute(
                "SELECT * FROM findings ORDER BY detected_at DESC LIMIT ?",
                (recent_limit,),
            ).fetchall()

        masked_count = by_status.get(FindingStatus.MASKED, 0)
        false_positive_count = by_status.get(FindingStatus.FALSE_POSITIVE, 0)
        ignored_count = by_status.get(FindingStatus.IGNORED, 0)
        remediation_rate = (masked_count / total) if total else 0.0

        return {
            "total_findings": total,
            "by_status": by_status,
            "unresolved_by_severity": unresolved_by_severity,
            "by_category": by_category,
            "masked_count": masked_count,
            "false_positive_count": false_positive_count,
            "ignored_count": ignored_count,
            "remediation_rate": remediation_rate,
            "recent_findings": [self._finding_row_to_dict(r) for r in recent_rows],
        }
