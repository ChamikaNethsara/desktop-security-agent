from __future__ import annotations

import hashlib
import re
from pathlib import Path

from scanner.models import SecretFinding


class FindingFingerprintGenerator:
    """
    Generates deterministic fingerprints for SecretFinding objects.
    The fingerprint includes:
        - Normalized file path
        - Pattern ID
        - Line number
        - SHA-256 hash of the candidate secret
    """

    HASH_ALGORITHM = "sha256"
    SHA256_HEX_LENGTH = 64

    # Generate a SHA-256 hash for a candidate secret.
    @classmethod
    def hash_secret(cls, candidate_value: str) -> str:
        if not isinstance(candidate_value, str):
            raise TypeError("candidate_value must be a string.")

        return hashlib.sha256(candidate_value.encode("utf-8")).hexdigest()

    # Generate a deterministic fingerprint for a finding.
    @classmethod
    def generate(cls, finding: SecretFinding) -> str:
        if not finding.secret_hash:
            raise ValueError("secret_hash is required to generate a value-aware fingerprint.")

        if not cls._is_valid_sha256_hash(finding.secret_hash):
            raise ValueError("secret_hash must be a valid SHA-256 hexadecimal digest.")
        
        normalized_path = (
            finding.file_path
            .expanduser()
            .resolve()
            .as_posix()
            .casefold()
        )

        # Build fingerprint input without the secret value.
        fingerprint_input = (
            f"path={normalized_path}\n"
            f"pattern={finding.pattern_id}\n"
            f"line={finding.line_number}"
            f"secret_hash={finding.secret_hash}"
        )

        # Generate the SHA-256 fingerprint.
        digest = hashlib.sha256(fingerprint_input.encode("utf-8")).hexdigest()

        return digest

    # Validate that a value is a 64-character SHA-256 hex digest.
    @classmethod
    def _is_valid_sha256_hash(cls, value: str) -> bool:
        if len(value) != cls.SHA256_HEX_LENGTH:
            return False

        return re.fullmatch(r"[0-9a-f]{64}", value) is not None