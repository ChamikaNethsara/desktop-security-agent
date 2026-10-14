"""
demo_component2.py
====================
Standalone demo of Component 2 — Secret Masking and Encrypted Storage Engine.
Run this from the project root (the folder containing storage/, tests/, conftest.py)
to see encryption, masking, and database storage working end-to-end.

Usage:
    python demo_component2.py
"""

import os
import tempfile

# Use a throwaway temp directory for the key/backup/db files so this demo
# never touches your real ~/.adsa folder.
DEMO_DIR = tempfile.mkdtemp(prefix="adsa_demo_")
os.environ["ADSA_KEY_BACKEND"] = "file"
os.environ["ADSA_KEY_FILE_PATH"] = os.path.join(DEMO_DIR, "master.key")
os.environ["ADSA_BACKUP_DIR"] = os.path.join(DEMO_DIR, "backups")
os.environ["ADSA_DB_PATH"] = os.path.join(DEMO_DIR, "adsa.db")

from masking.encryption import encrypt_secret, decrypt_secret
from masking.masker import preview_mask, apply_mask, rollback
from masking.database import SecretDatabase, FindingInput, FindingStatus

SEPARATOR = "=" * 60


def section(title):
    print(f"\n{SEPARATOR}\n {title}\n{SEPARATOR}")


# --------------------------------------------------------------------- #
# 1. Encryption
# --------------------------------------------------------------------- #
section("1. AES-256-GCM Encryption")

raw_secret = "Sup3rSecretPass!"
ciphertext = encrypt_secret(raw_secret)
print(f"Original secret : {raw_secret}")
print(f"Encrypted token : {ciphertext[:50]}...")

decrypted = decrypt_secret(ciphertext)
print(f"Decrypted back  : {decrypted}")
assert decrypted == raw_secret
print("Result: Encryption round-trip successful.")

# --------------------------------------------------------------------- #
# 2. Masking
# --------------------------------------------------------------------- #
section("2. Secret Masking (.env file)")

env_path = os.path.join(DEMO_DIR, ".env")
with open(env_path, "w") as f:
    f.write("APP_NAME=adsa\nDB_PASSWORD=Sup3rSecretPass!\nDEBUG=false\n")

print("Before masking:")
print(open(env_path).read())

preview = preview_mask(env_path, 2, "Sup3rSecretPass!", "db_password")
print(f"Preview (redacted) : {preview.before_redacted}")
print(f"Preview (after)    : {preview.after}")

operation = apply_mask(env_path, 2, "Sup3rSecretPass!", "db_password")
print(f"\nMasking applied. Operation ID: {operation.operation_id}")
print("After masking:")
print(open(env_path).read())

# --------------------------------------------------------------------- #
# 3. Database
# --------------------------------------------------------------------- #
section("3. SQLite Database + Encrypted Storage")

db = SecretDatabase()

finding = FindingInput(
    file_path=env_path, line_number=2, pattern_id="PWD-001",
    pattern_name="Password assignment", category="Passwords", severity="High",
    confidence=0.92, confidence_level="high", regex_score=0.9,
    context_score=0.95, entropy_score=0.6, is_placeholder=False,
    is_comment=False, detected_at="2026-09-08T10:00:00+00:00",
)
finding_id = db.insert_finding(finding)
print(f"Finding inserted with id: {finding_id}, status: {db.get_finding(finding_id)['status']}")

isolation_id = db.store_isolated_secret(
    finding_id, "Sup3rSecretPass!", "DB_PASSWORD", operation.placeholder,
    masking_operation_id=operation.operation_id,
)
print(f"Secret isolated with id: {isolation_id}")
print(f"Finding status now: {db.get_finding(finding_id)['status']}")

stored = db.get_isolated_secret(isolation_id)
print(f"Ciphertext stored in DB (never plaintext): {stored['encrypted_value'][:50]}...")

stats = db.get_dashboard_stats()
print(f"\nDashboard stats: {stats['total_findings']} finding(s), "
      f"{stats['masked_count']} masked, by category: {stats['by_category']}")

db.close()

# --------------------------------------------------------------------- #
# 4. Rollback
# --------------------------------------------------------------------- #
section("4. Rollback")

rollback(operation.operation_id)
print("After rollback, .env file restored:")
print(open(env_path).read())

section("Component 2 demo complete — all steps passed.")
