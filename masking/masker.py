"""
storage/masker.py
===================
Component 2 — Secret Masking and Encrypted Storage Engine
Automated Desktop Security Agent (A.D.S.A.)

Responsibility
--------------
Given a confirmed finding's location (file_path, line_number), its raw
secret value and a chosen variable name, safely replace the raw secret in
the configuration file with an environment-variable placeholder such as
``${DB_PASSWORD}``, without corrupting the surrounding file syntax
(.env, Dockerfile, JSON, YAML).

Provides:
    * preview_mask(...)  -> dry-run, returns a REDACTED before/after view
                             with no raw secret in the returned object.
    * apply_mask(...)    -> performs the edit, taking an encrypted backup
                             first so the change is reversible.
    * rollback(...)      -> restores the file from its encrypted backup.

Security design notes
----------------------
* The on-disk edit is a targeted, exact substring replacement of the raw
  secret within its specific line — everything else on the line (quotes,
  indentation, punctuation) is left untouched, which is what keeps the
  surrounding JSON/YAML/.env/Dockerfile syntax valid without needing a
  full re-serialisation (and the formatting churn that comes with it).
* After writing, the file is re-validated against its format's grammar
  where one exists (JSON must still parse; YAML must still parse). If
  validation fails, the write is reverted automatically before any
  exception is raised.
* Reversibility is implemented by taking a full, AES-256-GCM encrypted
  backup of the original file (via storage.encryption) *before* editing.
  Nothing about the secret is ever written to disk in plaintext by this
  module — the only plaintext copy of the secret that can exist is the
  live config file the developer already owns.
* No log statement, exception message, dataclass returned to a caller,
  or manifest entry in this module ever contains the raw secret value.
  Preview objects show a REDACTED stand-in for the original value.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Final, List, Optional

import yaml

from masking.encryption import decrypt_secret, encrypt_secret, DecryptionError, EncryptionError

logger = logging.getLogger("adsa.storage.masker")

_REDACTED: Final[str] = "[REDACTED]"

_BACKUP_DIR: Final[Path] = Path(
    os.environ.get("ADSA_BACKUP_DIR", str(Path.home() / ".adsa" / "backups"))
)
_MANIFEST_PATH: Final[Path] = _BACKUP_DIR / "manifest.json"


# --------------------------------------------------------------------------- #
# Exceptions
# --------------------------------------------------------------------------- #

class MaskingError(Exception):
    """Raised when a secret cannot be safely masked. Never contains the
    raw secret value."""


class RollbackError(Exception):
    """Raised when a masking operation cannot be rolled back."""


# --------------------------------------------------------------------------- #
# File format detection
# --------------------------------------------------------------------------- #

class FileFormat(str, Enum):
    ENV = "env"
    DOCKERFILE = "dockerfile"
    JSON = "json"
    YAML = "yaml"
    UNKNOWN = "unknown"


def detect_format(file_path: Path) -> FileFormat:
    """Best-effort detection of config file type from its name/extension."""
    name = file_path.name
    suffix = file_path.suffix.lower()

    if name == "Dockerfile" or name.startswith("Dockerfile.") or suffix == ".dockerfile":
        return FileFormat.DOCKERFILE
    if suffix == ".env" or name == ".env" or name.startswith(".env."):
        return FileFormat.ENV
    if suffix == ".json":
        return FileFormat.JSON
    if suffix in (".yaml", ".yml"):
        return FileFormat.YAML
    return FileFormat.UNKNOWN


# --------------------------------------------------------------------------- #
# Variable name sanitisation
# --------------------------------------------------------------------------- #

_INVALID_VAR_CHARS = re.compile(r"[^A-Za-z0-9_]")


def sanitize_variable_name(variable_name: str) -> str:
    """Normalise a proposed placeholder name into a safe shell/env-style
    identifier: UPPER_SNAKE_CASE, starts with a letter or underscore.
    """
    if not variable_name or not variable_name.strip():
        raise MaskingError("A variable name is required to build a placeholder.")

    cleaned = _INVALID_VAR_CHARS.sub("_", variable_name.strip()).upper()
    if cleaned and cleaned[0].isdigit():
        cleaned = f"_{cleaned}"
    cleaned = re.sub(r"_+", "_", cleaned).strip("_")

    if not cleaned:
        raise MaskingError("Variable name did not contain any valid characters.")
    return cleaned


def build_placeholder(variable_name: str) -> str:
    return "${%s}" % sanitize_variable_name(variable_name)


# --------------------------------------------------------------------------- #
# Preview (dry-run) result
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class MaskPreview:
    """Result of a dry-run. Contains no raw secret material — the
    original line is shown with the secret redacted, safe to log,
    display in the dashboard, or embed in a PDF report.
    """
    file_path: str
    line_number: int
    file_format: FileFormat
    placeholder: str
    before_redacted: str   # original line, secret replaced with [REDACTED]
    after: str              # line as it will look post-mask (safe to show in full)
    occurrences_found: int
    safe_to_apply: bool
    warnings: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class MaskOperation:
    """Record of an applied mask, sufficient to audit or roll back the
    change. Contains no raw secret material.
    """
    operation_id: str
    file_path: str
    line_number: int
    variable_name: str
    placeholder: str
    file_format: FileFormat
    applied_at: float
    status: str  # "applied" | "rolled_back"


# --------------------------------------------------------------------------- #
# Internal helpers
# --------------------------------------------------------------------------- #

def _read_file_text(file_path: Path) -> str:
    try:
        return file_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise MaskingError(f"File not found: {file_path}") from None
    except UnicodeDecodeError:
        raise MaskingError(
            f"File is not valid UTF-8 text and cannot be safely masked: {file_path}"
        ) from None
    except OSError as exc:
        raise MaskingError(f"Unable to read file ({type(exc).__name__}): {file_path}") from None


def _atomic_write(file_path: Path, content: str) -> None:
    """Write content to file_path atomically (write to a temp file in the
    same directory, then os.replace) so a crash mid-write can never leave
    a half-written config file on disk.
    """
    directory = file_path.parent
    fd, tmp_path = tempfile.mkstemp(dir=str(directory), prefix=f".{file_path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as tmp_file:
            tmp_file.write(content)
        os.replace(tmp_path, file_path)
    except OSError as exc:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise MaskingError(f"Unable to write file ({type(exc).__name__}): {file_path}") from None


def _redact_line(line: str, raw_secret: str) -> str:
    """Return `line` with every exact occurrence of raw_secret replaced by
    a generic redaction marker (never used for the actual on-disk edit,
    only for safe display/logging).
    """
    return line.replace(raw_secret, _REDACTED)


def _locate_and_replace(line: str, raw_secret: str, placeholder: str) -> tuple[str, int]:
    """Replace exact occurrences of raw_secret in `line` with `placeholder`.
    Returns (new_line, occurrence_count). Does not mutate anything on disk.
    """
    occurrences = line.count(raw_secret)
    new_line = line.replace(raw_secret, placeholder)
    return new_line, occurrences


def _validate_rewritten_file(content: str, file_format: FileFormat) -> Optional[str]:
    """Return an error message if the rewritten file content is no longer
    structurally valid for its format, else None.
    """
    if file_format == FileFormat.JSON:
        try:
            json.loads(content)
        except json.JSONDecodeError as exc:
            return f"Resulting file is not valid JSON ({exc.msg} at line {exc.lineno})."
    elif file_format == FileFormat.YAML:
        try:
            yaml.safe_load(content)
        except yaml.YAMLError:
            return "Resulting file is not valid YAML."
    # .env / Dockerfile / unknown: no strict grammar to re-parse against;
    # line-count preservation (checked by the caller) is the safety net.
    return None


def _line_count(content: str) -> int:
    return len(content.splitlines())


# --------------------------------------------------------------------------- #
# Backup manifest (metadata only — never stores raw secrets)
# --------------------------------------------------------------------------- #

class _BackupManifest:
    """Tracks masking operations and where their encrypted backups live.

    The manifest file itself is plain JSON but contains only non-sensitive
    metadata (paths, ids, timestamps, variable names, status). The actual
    original file content is stored separately, AES-256-GCM encrypted,
    under `_BACKUP_DIR/<operation_id>.bak.enc`.
    """

    def __init__(self, manifest_path: Path = _MANIFEST_PATH) -> None:
        self._path = manifest_path

    def _load(self) -> dict:
        if not self._path.exists():
            return {"operations": {}}
        try:
            return json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.warning("Backup manifest was unreadable; starting a fresh manifest.")
            return {"operations": {}}

    def _save(self, data: dict) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(self._path, json.dumps(data, indent=2))

    def record_backup(self, operation: MaskOperation, backup_file: Path) -> None:
        data = self._load()
        data["operations"][operation.operation_id] = {
            "file_path": operation.file_path,
            "line_number": operation.line_number,
            "variable_name": operation.variable_name,
            "placeholder": operation.placeholder,
            "file_format": operation.file_format.value,
            "applied_at": operation.applied_at,
            "status": operation.status,
            "backup_file": str(backup_file),
        }
        self._save(data)

    def mark_rolled_back(self, operation_id: str) -> None:
        data = self._load()
        if operation_id in data["operations"]:
            data["operations"][operation_id]["status"] = "rolled_back"
            self._save(data)

    def get(self, operation_id: str) -> Optional[dict]:
        data = self._load()
        return data["operations"].get(operation_id)

    def list_for_file(self, file_path: str) -> List[dict]:
        data = self._load()
        return [
            {**record, "operation_id": op_id}
            for op_id, record in data["operations"].items()
            if record["file_path"] == file_path
        ]


_manifest = _BackupManifest()


def _write_encrypted_backup(operation_id: str, original_content: str) -> Path:
    _BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    backup_path = _BACKUP_DIR / f"{operation_id}.bak.enc"
    try:
        token = encrypt_secret(original_content)
    except EncryptionError as exc:
        raise MaskingError("Unable to create an encrypted backup before masking.") from exc
    backup_path.write_text(token, encoding="ascii")
    try:
        os.chmod(backup_path, 0o600)
    except OSError:
        pass
    return backup_path


def _read_encrypted_backup(backup_path: Path) -> str:
    if not backup_path.exists():
        raise RollbackError("Backup file for this operation no longer exists.")
    token = backup_path.read_text(encoding="ascii")
    try:
        return decrypt_secret(token)
    except DecryptionError as exc:
        raise RollbackError("Unable to decrypt the backup for this operation.") from exc


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def preview_mask(file_path: str, line_number: int, raw_secret: str, variable_name: str) -> MaskPreview:
    """Dry-run: compute what masking would do, without touching the file.

    The returned MaskPreview is safe to log, display, or serialise — it
    never contains the raw secret value.
    """
    path = Path(file_path)
    file_format = detect_format(path)
    placeholder = build_placeholder(variable_name)
    warnings: List[str] = []

    content = _read_file_text(path)
    lines = content.splitlines(keepends=True)

    if line_number < 1 or line_number > len(lines):
        raise MaskingError(f"Line {line_number} is out of range for {file_path}.")

    original_line = lines[line_number - 1]
    new_line, occurrences = _locate_and_replace(original_line, raw_secret, placeholder)

    safe_to_apply = True
    if occurrences == 0:
        safe_to_apply = False
        warnings.append(
            "The expected secret value was not found on this line. The file may "
            "have changed since it was scanned; re-scan before masking."
        )
    elif occurrences > 1:
        safe_to_apply = False
        warnings.append(
            f"The secret value appears {occurrences} times on this line; masking "
            "is blocked to avoid an ambiguous edit."
        )

    if file_format == FileFormat.UNKNOWN:
        warnings.append(
            "Unrecognised file format; only a plain text substitution and a "
            "line-count check will be used to validate the edit."
        )

    return MaskPreview(
        file_path=str(path),
        line_number=line_number,
        file_format=file_format,
        placeholder=placeholder,
        before_redacted=_redact_line(original_line, raw_secret).rstrip("\n"),
        after=new_line.rstrip("\n") if occurrences == 1 else _redact_line(original_line, raw_secret).rstrip("\n"),
        occurrences_found=occurrences,
        safe_to_apply=safe_to_apply,
        warnings=warnings,
    )


def apply_mask(file_path: str, line_number: int, raw_secret: str, variable_name: str) -> MaskOperation:
    """Replace the raw secret at (file_path, line_number) with an
    environment-variable placeholder, after taking an encrypted backup of
    the whole file so the change can be rolled back.

    Raises MaskingError without ever including the raw secret value.
    """
    path = Path(file_path)
    file_format = detect_format(path)
    placeholder = build_placeholder(variable_name)

    original_content = _read_file_text(path)
    lines = original_content.splitlines(keepends=True)

    if line_number < 1 or line_number > len(lines):
        raise MaskingError(f"Line {line_number} is out of range for {file_path}.")

    target_line = lines[line_number - 1]
    new_line, occurrences = _locate_and_replace(target_line, raw_secret, placeholder)

    if occurrences == 0:
        raise MaskingError(
            f"Expected secret not found at {file_path}:{line_number}. "
            "Re-scan the file before attempting to mask it."
        )
    if occurrences > 1:
        raise MaskingError(
            f"Secret value appears {occurrences} times at {file_path}:{line_number}; "
            "refusing an ambiguous edit."
        )

    original_line_count = _line_count(original_content)

    new_lines = list(lines)
    new_lines[line_number - 1] = new_line
    new_content = "".join(new_lines)

    format_error = _validate_rewritten_file(new_content, file_format)
    if format_error is None and _line_count(new_content) != original_line_count:
        format_error = "Masking would change the file's line count, which is not expected for a single-value edit."

    if format_error:
        logger.error("Masking aborted for %s:%d — %s", file_path, line_number, format_error)
        raise MaskingError(f"Refusing to apply mask: {format_error}")

    operation_id = str(uuid.uuid4())

    # Backup BEFORE writing, so a crash between backup and write can never
    # leave us without a way to recover the original file.
    backup_path = _write_encrypted_backup(operation_id, original_content)

    try:
        _atomic_write(path, new_content)
    except MaskingError:
        # Roll forward failed; the backup is harmless to leave in place,
        # but there is nothing to roll back since the file was never changed.
        raise

    operation = MaskOperation(
        operation_id=operation_id,
        file_path=str(path),
        line_number=line_number,
        variable_name=sanitize_variable_name(variable_name),
        placeholder=placeholder,
        file_format=file_format,
        applied_at=time.time(),
        status="applied",
    )
    _manifest.record_backup(operation, backup_path)

    logger.info(
        "Masked secret at %s:%d as %s (operation_id=%s).",
        file_path, line_number, placeholder, operation_id,
    )
    return operation


def rollback(operation_id: str) -> None:
    """Restore a file to its pre-mask state using the encrypted backup
    recorded for `operation_id`.
    """
    record = _manifest.get(operation_id)
    if record is None:
        raise RollbackError(f"No masking operation found with id {operation_id}.")
    if record["status"] == "rolled_back":
        raise RollbackError(f"Operation {operation_id} has already been rolled back.")

    backup_path = Path(record["backup_file"])
    original_content = _read_encrypted_backup(backup_path)

    target_path = Path(record["file_path"])
    _atomic_write(target_path, original_content)

    _manifest.mark_rolled_back(operation_id)
    logger.info("Rolled back masking operation %s for %s.", operation_id, record["file_path"])


def list_operations_for_file(file_path: str) -> List[dict]:
    """Return manifest metadata (no secrets) for all masking operations
    recorded against a given file, most recent last.
    """
    return sorted(_manifest.list_for_file(file_path), key=lambda r: r["applied_at"])
