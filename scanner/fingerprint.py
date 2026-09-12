from __future__ import annotations

import hashlib
from pathlib import Path
from scanner.models import SecretFinding


class FindingFingerprintGenerator:
    """
    Generates deterministic fingerprints for SecretFinding objects.
    """

    HASH_ALGORITHM = "sha256"

    # Generate a deterministic fingerprint for a finding.
    @classmethod
    def generate(cls, finding: SecretFinding,) -> str:
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
        )

        # Generate the SHA-256 fingerprint.
        digest = hashlib.sha256(fingerprint_input.encode("utf-8")).hexdigest()

        return digest