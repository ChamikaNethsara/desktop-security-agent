from __future__ import annotations

import threading
from scanner.fingerprint import FindingFingerprintGenerator
from scanner.models import SecretFinding


class FindingDeduplicator:
    """
    Suppresses duplicate SecretFinding objects.
    """

    def __init__(self, fingerprint_generator: type[FindingFingerprintGenerator] = FindingFingerprintGenerator) -> None:
        self._fingerprint_generator = fingerprint_generator
        self._seen_fingerprints: set[str] = set()
        self._lock = threading.Lock() # Protect the fingerprint set from concurrent access.


    # Return True if seen; otherwise register and return False.
    def is_duplicate(self, finding: SecretFinding) -> bool:
        fingerprint = self._fingerprint_generator.generate(finding)

        # Check and register the fingerprint atomically.
        with self._lock:
            if fingerprint in self._seen_fingerprints:
                return True

            self._seen_fingerprints.add(fingerprint)
            return False


    # Register a finding and return its fingerprint.
    def add(self, finding: SecretFinding) -> str:
        fingerprint = self._fingerprint_generator.generate(finding)

        with self._lock:
            self._seen_fingerprints.add(fingerprint)

        return fingerprint


    # Check whether a finding fingerprint is already known.
    def contains(self, finding: SecretFinding) -> bool:
        fingerprint = self._fingerprint_generator.generate(finding)

        with self._lock:
            return fingerprint in self._seen_fingerprints


    # Clear all in-memory fingerprints.
    def clear(self) -> None:
        with self._lock:
            self._seen_fingerprints.clear()


    # Return the number of stored fingerprints.
    def __len__(self) -> int:
        with self._lock:
            return len(self._seen_fingerprints)