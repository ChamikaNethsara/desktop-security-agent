from pathlib import Path
from scanner.models import (ConfidenceLevel, SecretCategory, SecretFinding, SecretSeverity)
from storage.event_store import SQLiteEventStore


def create_finding(
        *,
        path: str = "project/.env",
        line_number: int = 1,
        pattern_id: str = "generic_password_assignment"
        ) -> SecretFinding:

    return SecretFinding(
        file_path=Path(path),
        line_number=line_number,
        pattern_id=pattern_id,
        pattern_name="Generic Password Assignment",
        category=SecretCategory.PASSWORD,
        severity=SecretSeverity.HIGH,
        confidence=0.80,
        confidence_level=ConfidenceLevel.MEDIUM,
        regex_score=0.75,
        context_score=0.50,
        entropy_score=1.00,
        is_placeholder=False,
        is_comment=False,
        description="Test finding",
    )


def test_database_is_created(tmp_path: Path) -> None:
    database_path = tmp_path / "security_agent.db"
    store = SQLiteEventStore(database_path)

    assert database_path.exists()
    assert store.count() == 0

    store.close()


def test_finding_is_persisted(tmp_path: Path) -> None:
    database_path = tmp_path / "security_agent.db"
    store = SQLiteEventStore(database_path)

    finding = create_finding()
    fingerprint = store.save(finding)

    assert len(fingerprint) == 64
    assert store.count() == 1

    store.close()


def test_duplicate_finding_is_not_inserted(tmp_path: Path) -> None:
    database_path = tmp_path / "security_agent.db"
    store = SQLiteEventStore(database_path)

    finding = create_finding()

    store.save(finding)
    store.save(finding)

    assert store.count() == 1

    store.close()


def test_different_findings_are_persisted(tmp_path: Path) -> None:
    database_path = tmp_path / "security_agent.db"
    store = SQLiteEventStore(database_path)

    finding_a = create_finding(line_number=1)
    finding_b = create_finding(line_number=2)

    store.save(finding_a)
    store.save(finding_b)

    assert store.count() == 2

    store.close()


def test_store_can_be_reopened(tmp_path: Path) -> None:
    database_path = tmp_path / "security_agent.db"

    finding = create_finding()
    store = SQLiteEventStore(database_path)

    store.save(finding)
    store.close()

    reopened_store = SQLiteEventStore(database_path)
    
    assert reopened_store.count() == 1
    reopened_store.close()


def test_plaintext_secret_is_not_stored(tmp_path: Path) -> None:
    database_path = tmp_path / "security_agent.db"
    store = SQLiteEventStore(database_path)

    finding = create_finding()
    store.save(finding)

    store.close()
    database_bytes = database_path.read_bytes()

    assert b"x9F!kP72@Qz#Lm91" not in database_bytes