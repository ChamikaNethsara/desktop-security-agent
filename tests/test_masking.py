"""
tests/test_storage.py
=======================
Pytest suite for Component 2 (Secret Masking and Encrypted Storage Engine):

    * masking.encryption — AES-256-GCM encrypt/decrypt round trip
    * masking.masker     — dry-run preview, apply, and rollback on a
                            temporary .env file (plus JSON syntax safety)
    * masking.database   — schema creation, finding CRUD, isolated
                            (encrypted) secret storage, and dashboard stats

Isolation & cleanup
--------------------
Every test runs against throwaway files created under pytest's built-in
`tmp_path` fixture, and any module-level state that would otherwise point
at a developer's real home directory (the encryption key file, the
masker's backup directory/manifest) is redirected into `tmp_path` via
`monkeypatch`. Both fixtures are provided by pytest itself and clean up
automatically after each test — no manual `os.remove`/`shutil.rmtree`
calls or hand-rolled temp directories appear anywhere in this file.
"""

from __future__ import annotations

import json
import os

import pytest

import masking.encryption as encryption_module
import masking.masker as masker_module

from masking.encryption import decrypt_secret, encrypt_secret, DecryptionError
from masking.masker import MaskingError, apply_mask, preview_mask, rollback
from masking.database import (
    FindingInput,
    FindingNotFoundError,
    FindingStatus,
    SecretDatabase,
)


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

@pytest.fixture(autouse=True)
def isolated_encryption(tmp_path, monkeypatch):
    """Force the file-based key backend, point it at a per-test tmp path,
    and give every test a *fresh* in-memory key cache. Without the fresh
    cache, the module-level singleton in storage.encryption would keep
    reusing whichever key was generated first in the pytest process,
    which would break the permissions/creation assertions below and
    leak key state between tests.
    """
    key_path = tmp_path / "keys" / "master.key"
    monkeypatch.setenv("ADSA_KEY_BACKEND", "file")
    monkeypatch.setenv("ADSA_KEY_FILE_PATH", str(key_path))

    fresh_key_store = encryption_module._KeyStore()
    monkeypatch.setattr(encryption_module, "_key_store", fresh_key_store)
    monkeypatch.setattr(
        encryption_module, "_default_encryptor", encryption_module.SecretEncryptor(fresh_key_store)
    )
    return key_path


@pytest.fixture(autouse=True)
def isolated_masker_backups(tmp_path, monkeypatch):
    """Redirect masking.masker's encrypted backup directory and manifest
    file into the per-test tmp path so masking operations in one test
    can never see or restore another test's backups.
    """
    backup_dir = tmp_path / "backups"
    manifest_path = backup_dir / "manifest.json"

    monkeypatch.setattr(masker_module, "_BACKUP_DIR", backup_dir)
    monkeypatch.setattr(masker_module, "_MANIFEST_PATH", manifest_path)
    monkeypatch.setattr(masker_module, "_manifest", masker_module._BackupManifest(manifest_path))
    return backup_dir


@pytest.fixture
def env_file(tmp_path):
    """A small temporary .env file containing one secret to mask."""
    path = tmp_path / ".env"
    path.write_text(
        "APP_NAME=adsa\n"
        "DB_PASSWORD=Sup3rSecretPass!\n"
        "DEBUG=false\n"
    )
    return path


@pytest.fixture
def db(tmp_path):
    """A SecretDatabase backed by a throwaway SQLite file under tmp_path."""
    database = SecretDatabase(db_path=str(tmp_path / "adsa_test.db"))
    yield database
    database.close()


@pytest.fixture
def sample_finding():
    return FindingInput(
        file_path="/repo/.env",
        line_number=2,
        pattern_id="PWD-001",
        pattern_name="Password assignment",
        category="Passwords",
        severity="High",
        confidence=0.92,
        confidence_level="high",
        regex_score=0.9,
        context_score=0.95,
        entropy_score=0.6,
        is_placeholder=False,
        is_comment=False,
        detected_at="2026-09-08T10:00:00+00:00",
    )


# --------------------------------------------------------------------------- #
# 1. storage.encryption — AES-256-GCM round trip
# --------------------------------------------------------------------------- #

class TestEncryption:

    def test_encrypt_decrypt_round_trip(self):
        plaintext = "Sup3rSecretPass!"
        ciphertext = encrypt_secret(plaintext)

        assert isinstance(ciphertext, str)
        assert ciphertext != plaintext
        assert plaintext not in ciphertext  # no plaintext leaking into the stored token

        assert decrypt_secret(ciphertext) == plaintext

    def test_ciphertext_is_not_deterministic(self):
        """A fresh random nonce per call means encrypting the same value
        twice must not produce the same ciphertext, but both tokens must
        still decrypt back to the original value.
        """
        plaintext = "identical-secret-value"
        token_a = encrypt_secret(plaintext)
        token_b = encrypt_secret(plaintext)

        assert token_a != token_b
        assert decrypt_secret(token_a) == plaintext
        assert decrypt_secret(token_b) == plaintext

    def test_tampered_ciphertext_is_rejected(self):
        token = encrypt_secret("another-secret-value")
        flipped_char = "A" if token[-4] != "A" else "B"
        tampered = token[:-4] + flipped_char + token[-3:]

        with pytest.raises(DecryptionError):
            decrypt_secret(tampered)

    def test_malformed_token_is_rejected(self):
        with pytest.raises(DecryptionError):
            decrypt_secret("not-a-valid-ciphertext-token")

    def test_empty_plaintext_is_rejected(self):
        with pytest.raises(Exception):
            encrypt_secret("")

    def test_key_file_created_with_owner_only_permissions(self, isolated_encryption):
        key_path = isolated_encryption
        assert not key_path.exists()

        encrypt_secret("trigger-key-generation")

        assert key_path.exists()
        if os.name == "nt":
            assert (key_path.stat().st_mode & 0o600) == 0o600
        else:
            assert (key_path.stat().st_mode & 0o777) == 0o600


# --------------------------------------------------------------------------- #
# 2. masking.masker — preview / apply / rollback
# --------------------------------------------------------------------------- #

class TestMasker:

    def test_preview_does_not_modify_the_file(self, env_file):
        original_content = env_file.read_text()

        preview = preview_mask(str(env_file), 2, "Sup3rSecretPass!", "db password")

        assert env_file.read_text() == original_content
        assert preview.safe_to_apply is True
        assert preview.occurrences_found == 1
        assert preview.placeholder == "${DB_PASSWORD}"
        assert "Sup3rSecretPass!" not in preview.before_redacted
        assert "[REDACTED]" in preview.before_redacted
        assert "${DB_PASSWORD}" in preview.after

    def test_apply_mask_replaces_secret_and_preserves_other_lines(self, env_file):
        operation = apply_mask(str(env_file), 2, "Sup3rSecretPass!", "db password")

        new_content = env_file.read_text()
        assert "Sup3rSecretPass!" not in new_content
        assert "DB_PASSWORD=${DB_PASSWORD}" in new_content
        assert "APP_NAME=adsa" in new_content
        assert "DEBUG=false" in new_content
        assert operation.status == "applied"
        assert operation.placeholder == "${DB_PASSWORD}"

    def test_rollback_restores_the_original_file_exactly(self, env_file):
        original_content = env_file.read_text()

        operation = apply_mask(str(env_file), 2, "Sup3rSecretPass!", "db password")
        assert env_file.read_text() != original_content

        rollback(operation.operation_id)
        assert env_file.read_text() == original_content

    def test_apply_mask_rejects_a_secret_that_is_no_longer_there(self, env_file):
        with pytest.raises(MaskingError):
            apply_mask(str(env_file), 2, "this-value-does-not-exist", "db_password")

    def test_apply_mask_rejects_an_ambiguous_line(self, tmp_path):
        dup_file = tmp_path / "dup.env"
        dup_file.write_text("TOKEN=abcabc\n")

        with pytest.raises(MaskingError):
            apply_mask(str(dup_file), 1, "abc", "token")

    def test_apply_mask_on_json_keeps_the_file_valid_json(self, tmp_path):
        json_file = tmp_path / "config.json"
        json_file.write_text(json.dumps({"database": {"password": "j8Kx92mQpz11ZLq"}}, indent=2) + "\n")

        secret_line = next(
            i for i, line in enumerate(json_file.read_text().splitlines(), start=1)
            if "j8Kx92mQpz11ZLq" in line
        )
        apply_mask(str(json_file), secret_line, "j8Kx92mQpz11ZLq", "db_password")

        rewritten = json_file.read_text()
        assert "j8Kx92mQpz11ZLq" not in rewritten

        parsed = json.loads(rewritten)  # must still parse as valid JSON
        assert parsed["database"]["password"] == "${DB_PASSWORD}"


# --------------------------------------------------------------------------- #
# 3. masking.database — schema, findings, isolated secrets, dashboard stats
# --------------------------------------------------------------------------- #

class TestDatabase:

    def test_database_file_and_schema_are_created_on_init(self, tmp_path):
        db_path = tmp_path / "fresh.db"
        assert not db_path.exists()

        database = SecretDatabase(db_path=str(db_path))
        try:
            assert db_path.exists()
            assert database.get_dashboard_stats()["total_findings"] == 0
        finally:
            database.close()

    def test_insert_and_get_finding_round_trip(self, db, sample_finding):
        finding_id = db.insert_finding(sample_finding)

        record = db.get_finding(finding_id)
        assert record["file_path"] == sample_finding.file_path
        assert record["line_number"] == sample_finding.line_number
        assert record["category"] == sample_finding.category
        assert record["severity"] == sample_finding.severity
        assert record["status"] == FindingStatus.DETECTED
        assert record["is_placeholder"] is False
        assert record["is_comment"] is False

    def test_get_missing_finding_raises(self, db):
        with pytest.raises(FindingNotFoundError):
            db.get_finding(9999)

    def test_upsert_avoids_duplicate_rows_for_the_same_location(self, db, sample_finding):
        first = db.upsert_finding(sample_finding)
        second = db.upsert_finding(sample_finding)

        assert first["created"] is True
        assert second["created"] is False
        assert first["finding_id"] == second["finding_id"]
        assert len(db.list_findings()) == 1

    def test_store_isolated_secret_persists_ciphertext_only(self, db, sample_finding):
        finding_id = db.insert_finding(sample_finding)
        raw_secret = "Sup3rSecretPass!"

        isolation_id = db.store_isolated_secret(
            finding_id,
            raw_secret,
            variable_name="DB_PASSWORD",
            placeholder="${DB_PASSWORD}",
            masking_operation_id="op-abc-123",
        )

        stored = db.get_isolated_secret(isolation_id)
        assert stored["encrypted_value"] != raw_secret
        assert raw_secret not in stored["encrypted_value"]

        # The dashboard-facing listing must never expose ciphertext.
        metadata_only = db.list_isolated_secrets_for_finding(finding_id)
        assert len(metadata_only) == 1
        assert "encrypted_value" not in metadata_only[0]

        # The finding should have advanced to 'masked'.
        assert db.get_finding(finding_id)["status"] == FindingStatus.MASKED

        # Only the restricted accessor can recover plaintext.
        assert db.get_decrypted_secret(isolation_id) == raw_secret

    def test_rollback_isolation_reverts_finding_status(self, db, sample_finding):
        finding_id = db.insert_finding(sample_finding)
        isolation_id = db.store_isolated_secret(
            finding_id, "Sup3rSecretPass!", "DB_PASSWORD", "${DB_PASSWORD}"
        )

        db.mark_isolation_rolled_back(isolation_id)

        assert db.get_finding(finding_id)["status"] == FindingStatus.CONFIRMED

        event_types = [event["event_type"] for event in db.get_finding_history(finding_id)]
        assert event_types == ["detected", "masked", "confirmed"]

    def test_dashboard_stats_aggregate_correctly(self, db, sample_finding):
        db.insert_finding(sample_finding)  # High severity, Passwords, stays 'detected'

        critical_finding = FindingInput(
            file_path="/repo/Dockerfile",
            line_number=5,
            pattern_id="API-001",
            pattern_name="API key",
            category="API keys",
            severity="Critical",
            confidence=0.98,
            confidence_level="high",
            regex_score=0.95,
            context_score=0.9,
            entropy_score=0.99,
            is_placeholder=False,
            is_comment=False,
            detected_at="2026-09-08T10:05:00+00:00",
        )
        critical_id = db.insert_finding(critical_finding)
        db.update_finding_status(critical_id, FindingStatus.FALSE_POSITIVE)

        stats = db.get_dashboard_stats()

        assert stats["total_findings"] == 2
        assert stats["by_status"][FindingStatus.DETECTED] == 1
        assert stats["by_status"][FindingStatus.FALSE_POSITIVE] == 1
        assert stats["false_positive_count"] == 1
        # The false-positive finding is resolved, so it's excluded from
        # the "unresolved by severity" breakdown used by the risk score.
        assert stats["unresolved_by_severity"] == {"High": 1}
        assert stats["by_category"] == {"Passwords": 1, "API keys": 1}
        assert len(stats["recent_findings"]) == 2


# --------------------------------------------------------------------------- #
# 4. Bonus: masker + database composed end-to-end (as a coordinator would)
# --------------------------------------------------------------------------- #

class TestMaskerDatabaseIntegration:

    def test_mask_then_persist_then_rollback_round_trip(self, db, env_file, sample_finding):
        finding_id = db.insert_finding(sample_finding)
        raw_secret = "Sup3rSecretPass!"

        operation = apply_mask(str(env_file), 2, raw_secret, "db_password")
        isolation_id = db.store_isolated_secret(
            finding_id, raw_secret, "DB_PASSWORD", operation.placeholder,
            masking_operation_id=operation.operation_id,
        )

        assert "Sup3rSecretPass!" not in env_file.read_text()
        assert db.get_finding(finding_id)["status"] == FindingStatus.MASKED

        rollback(operation.operation_id)
        db.mark_isolation_rolled_back(isolation_id)

        assert "Sup3rSecretPass!" in env_file.read_text()
        assert db.get_finding(finding_id)["status"] == FindingStatus.CONFIRMED
