from pathlib import Path

from scanner.fingerprint import FindingFingerprintGenerator
from scanner.models import (ConfidenceLevel, SecretCategory, SecretFinding, SecretSeverity)


def create_finding(
        *,
        path: str = "project/.env",
        line_number: int = 1,
        pattern_id: str = "generic_password_assignment",
        confidence: float = 0.80
        ) -> SecretFinding:

    return SecretFinding(
        file_path=Path(path),
        line_number=line_number,
        pattern_id=pattern_id,
        pattern_name="Generic Password Assignment",
        category=SecretCategory.PASSWORD,
        severity=SecretSeverity.HIGH,
        confidence=confidence,
        confidence_level=ConfidenceLevel.CRITICAL,
        regex_score=0.75,
        context_score=0.50,
        entropy_score=1.00,
        is_placeholder=False,
        is_comment=False,
    )


def test_same_finding_produces_same_fingerprint() -> None:
    finding = create_finding()
    fingerprint_a = FindingFingerprintGenerator.generate(finding)
    fingerprint_b = FindingFingerprintGenerator.generate(finding)

    assert fingerprint_a == fingerprint_b


def test_fingerprint_is_sha256_hex() -> None:
    finding = create_finding()
    fingerprint = FindingFingerprintGenerator.generate(finding)

    assert len(fingerprint) == 64
    assert all(
        character in "0123456789abcdef"
        for character in fingerprint
    )


def test_different_line_produces_different_fingerprint() -> None:
    finding_a = create_finding(line_number=1)
    finding_b = create_finding(line_number=2)

    fingerprint_a = FindingFingerprintGenerator.generate(finding_a)
    fingerprint_b = FindingFingerprintGenerator.generate(finding_b)

    assert fingerprint_a != fingerprint_b


def test_different_pattern_produces_different_fingerprint() -> None:
    finding_a = create_finding(pattern_id="generic_password_assignment")
    finding_b = create_finding(pattern_id="another_pattern")

    fingerprint_a = FindingFingerprintGenerator.generate(finding_a)
    fingerprint_b = FindingFingerprintGenerator.generate(finding_b)

    assert fingerprint_a != fingerprint_b


def test_different_file_produces_different_fingerprint() -> None:
    finding_a = create_finding(path="project_a/.env")
    finding_b = create_finding(path="project_b/.env")

    fingerprint_a = FindingFingerprintGenerator.generate(finding_a)
    fingerprint_b = FindingFingerprintGenerator.generate(finding_b)

    assert fingerprint_a != fingerprint_b


def test_confidence_does_not_change_fingerprint() -> None:
    finding_a = create_finding(confidence=0.70)
    finding_b = create_finding(confidence=0.90)

    fingerprint_a = FindingFingerprintGenerator.generate(finding_a)
    fingerprint_b = FindingFingerprintGenerator.generate(finding_b)

    assert fingerprint_a == fingerprint_b


def test_fingerprint_does_not_depend_on_plaintext_secret() -> None:
    finding_a = create_finding(confidence=0.70)
    finding_b = create_finding(confidence=0.90)

    fingerprint_a = FindingFingerprintGenerator.generate(finding_a)
    fingerprint_b = FindingFingerprintGenerator.generate(finding_b)

    assert fingerprint_a == fingerprint_b