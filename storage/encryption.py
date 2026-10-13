"""
storage/encryption.py
======================
Component 2 — Secret Masking and Encrypted Storage Engine
Automated Desktop Security Agent (A.D.S.A.)

Responsibility
--------------
Provides AES-256-GCM authenticated encryption for confirmed secret values
before they are persisted by storage/database.py, plus secure generation,
storage and loading of the local master key.

Security design notes
----------------------
* Cipher: AES-256-GCM (AEAD) via `cryptography.hazmat.primitives.ciphers.aead.AESGCM`.
  GCM gives us confidentiality + integrity (tamper detection) in one step,
  which is why we don't need a separate HMAC layer like Fernet uses.
* Key: a random 32-byte (256-bit) key, generated once per installation.
* Key storage preference order:
    1. OS credential store via the `keyring` package (Windows Credential
       Manager / macOS Keychain / Linux Secret Service) — the key material
       never touches an unencrypted file on disk.
    2. Local key file fallback (used automatically if no OS keyring backend
       is available, e.g. headless Linux CI). The file is written with
       owner-only permissions (0600) and its directory is created 0700.
* Nonces: a fresh random 96-bit (12-byte) nonce is generated per encryption
  call (never reused with the same key), and stored alongside the
  ciphertext so decryption can reconstruct it. Reuse of a nonce with GCM
  breaks confidentiality, so we never let the caller supply one.
* Zero plaintext leakage:
    - No log statement in this module ever includes plaintext secrets,
      derived keys, or raw key bytes.
    - Exceptions raised here never embed the plaintext or key in their
      message — only non-sensitive metadata (e.g. ciphertext length).
    - `repr()`/`str()` of the encryptor object never dumps key material.
"""

from __future__ import annotations

import base64
import logging
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

logger = logging.getLogger("adsa.storage.encryption")

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

_KEY_SIZE_BYTES: Final[int] = 32          # 256-bit key for AES-256
_NONCE_SIZE_BYTES: Final[int] = 12        # 96-bit nonce, standard for GCM
_FORMAT_VERSION: Final[bytes] = b"\x01"   # 1-byte version tag prefixed to every token

_KEYRING_SERVICE_NAME: Final[str] = "ADSA-SecretVault"
_KEYRING_USERNAME: Final[str] = "adsa-master-key"

# Fallback on-disk location if no OS keyring backend is usable.
_DEFAULT_KEY_DIR: Final[Path] = Path.home() / ".adsa" / "keys"
_DEFAULT_KEY_FILE: Final[Path] = _DEFAULT_KEY_DIR / "master.key"


# --------------------------------------------------------------------------- #
# Exceptions
# --------------------------------------------------------------------------- #

class EncryptionError(Exception):
    """Raised when a secret cannot be encrypted. Never contains plaintext."""


class DecryptionError(Exception):
    """Raised when a ciphertext cannot be decrypted or verified.

    Deliberately generic — never distinguishes "wrong key" vs "corrupted
    data" vs "tampered data" in the message, to avoid giving an attacker
    an oracle, and never includes any secret material.
    """


class KeyManagementError(Exception):
    """Raised when the master key cannot be generated, stored, or loaded."""


# --------------------------------------------------------------------------- #
# Key management
# --------------------------------------------------------------------------- #

class _KeyStore:
    """Handles secure generation, persistence and retrieval of the AES-256
    master key used to encrypt/decrypt secret values.

    Tries the OS keyring first; falls back to a permission-locked local
    file if no keyring backend is available. The fallback path and
    keyring service name can be overridden via environment variables so
    deployments can point at a shared/managed location if needed:

        ADSA_KEY_BACKEND   = "keyring" | "file"   (force a backend)
        ADSA_KEY_FILE_PATH = custom path for the file backend
    """

    def __init__(self) -> None:
        self._cached_key: Optional[bytes] = None
        self._backend: Optional[str] = None  # "keyring" or "file", set on first use

    # -- public -------------------------------------------------------- #

    def get_key(self) -> bytes:
        """Return the 32-byte master key, generating and persisting a new
        one on first run. Result is cached in memory for the process
        lifetime (never written back out anywhere else).
        """
        if self._cached_key is not None:
            return self._cached_key

        forced_backend = os.environ.get("ADSA_KEY_BACKEND")

        key: Optional[bytes] = None
        if forced_backend != "file":
            key = self._try_load_from_keyring()
            if key is not None:
                self._backend = "keyring"

        if key is None and forced_backend != "keyring":
            key = self._load_or_create_file_key()
            self._backend = "file"

        if key is None:
            # forced_backend == "keyring" but keyring truly unavailable.
            raise KeyManagementError(
                "Master key backend 'keyring' was requested but no usable "
                "OS keyring backend is available on this system."
            )

        if len(key) != _KEY_SIZE_BYTES:
            raise KeyManagementError(
                "Stored master key has an unexpected length; refusing to "
                "use it. Delete the stored key to regenerate, only if you "
                "have no encrypted secrets that depend on it."
            )

        self._cached_key = key
        logger.info("Master key loaded (backend=%s).", self._backend)
        return key

    # -- keyring backend ------------------------------------------------ #

    def _try_load_from_keyring(self) -> Optional[bytes]:
        try:
            import keyring
            from keyring.errors import NoKeyringError, PasswordSetError
        except ImportError:
            logger.debug("keyring package not installed; using file backend.")
            return None

        try:
            existing = keyring.get_password(_KEYRING_SERVICE_NAME, _KEYRING_USERNAME)
            if existing:
                return base64.b64decode(existing.encode("ascii"))

            new_key = AESGCM.generate_key(bit_length=256)
            keyring.set_password(
                _KEYRING_SERVICE_NAME,
                _KEYRING_USERNAME,
                base64.b64encode(new_key).decode("ascii"),
            )
            logger.info("Generated new master key and stored it in the OS keyring.")
            return new_key
        except (NoKeyringError, PasswordSetError, RuntimeError) as exc:
            logger.debug("OS keyring unavailable (%s); falling back to file backend.",
                         type(exc).__name__)
            return None

    # -- file backend ----------------------------------------------------#

    def _load_or_create_file_key(self) -> bytes:
        key_path = Path(os.environ.get("ADSA_KEY_FILE_PATH", str(_DEFAULT_KEY_FILE)))

        try:
            if key_path.exists():
                raw = key_path.read_bytes()
                return base64.b64decode(raw)

            key_path.parent.mkdir(parents=True, exist_ok=True)
            os.chmod(key_path.parent, stat.S_IRWXU)  # 0700: owner rwx only

            new_key = AESGCM.generate_key(bit_length=256)
            key_path.write_bytes(base64.b64encode(new_key))
            os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600: owner rw only

            logger.warning(
                "OS keyring not available. Master key stored in local file "
                "at a permission-locked path. For stronger protection, "
                "install/enable an OS keyring backend."
            )
            return new_key
        except OSError as exc:
            raise KeyManagementError(
                "Unable to read or create the local master key file "
                f"(backend error: {type(exc).__name__})."
            ) from None


# Module-level singleton so all callers share one cached key/backend choice.
_key_store = _KeyStore()


# --------------------------------------------------------------------------- #
# Encryption / decryption
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class _Token:
    """Internal representation of an encrypted payload prior to encoding."""
    version: bytes
    nonce: bytes
    ciphertext: bytes  # includes the GCM authentication tag


class SecretEncryptor:
    """AES-256-GCM encryptor/decryptor for individual secret values.

    Each call to `encrypt` uses a fresh random nonce. The returned string
    is a self-contained, base64-encoded token of the form:

        base64( version_byte || nonce(12 bytes) || ciphertext_with_tag )

    so `database.py` can store it as a single opaque TEXT column and hand
    it back unchanged for decryption later.
    """

    def __init__(self, key_store: _KeyStore = _key_store) -> None:
        self._key_store = key_store

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a secret value. Returns a base64 ciphertext token.

        Raises EncryptionError on failure. Never includes `plaintext` in
        any exception message or log line.
        """
        if not isinstance(plaintext, str):
            raise EncryptionError("Secret value to encrypt must be a string.")
        if plaintext == "":
            raise EncryptionError("Refusing to encrypt an empty secret value.")

        try:
            key = self._key_store.get_key()
            nonce = os.urandom(_NONCE_SIZE_BYTES)
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), associated_data=None)

            token = _Token(version=_FORMAT_VERSION, nonce=nonce, ciphertext=ciphertext)
            encoded = base64.b64encode(token.version + token.nonce + token.ciphertext).decode("ascii")

            logger.debug("Encrypted a secret value (ciphertext_len=%d).", len(encoded))
            return encoded
        except KeyManagementError:
            raise
        except Exception as exc:
            # Deliberately generic: never surface plaintext or key bytes.
            logger.error("Encryption failed (%s).", type(exc).__name__)
            raise EncryptionError("Failed to encrypt secret value.") from None

    def decrypt(self, token_str: str) -> str:
        """Decrypt a token produced by `encrypt`. Returns the plaintext.

        Raises DecryptionError on any failure (wrong key, corrupted data,
        tampering, or bad format). The error message is intentionally
        generic and never contains plaintext, key material, or the raw
        token contents.
        """
        if not isinstance(token_str, str) or not token_str:
            raise DecryptionError("Invalid ciphertext token.")

        try:
            raw = base64.b64decode(token_str.encode("ascii"), validate=True)
        except Exception:
            raise DecryptionError("Invalid ciphertext token.") from None

        min_len = len(_FORMAT_VERSION) + _NONCE_SIZE_BYTES
        if len(raw) <= min_len:
            raise DecryptionError("Invalid ciphertext token.")

        version = raw[:1]
        if version != _FORMAT_VERSION:
            raise DecryptionError("Unsupported ciphertext format version.")

        nonce = raw[1:1 + _NONCE_SIZE_BYTES]
        ciphertext = raw[1 + _NONCE_SIZE_BYTES:]

        try:
            key = self._key_store.get_key()
            aesgcm = AESGCM(key)
            plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
            return plaintext_bytes.decode("utf-8")
        except InvalidTag:
            logger.warning("Decryption failed integrity check (possible tampering or wrong key).")
            raise DecryptionError("Failed to decrypt ciphertext token.") from None
        except KeyManagementError:
            raise
        except Exception as exc:
            logger.error("Decryption failed (%s).", type(exc).__name__)
            raise DecryptionError("Failed to decrypt ciphertext token.") from None


# --------------------------------------------------------------------------- #
# Module-level convenience API (required interface)
# --------------------------------------------------------------------------- #

_default_encryptor = SecretEncryptor()


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a confirmed secret value for storage. See SecretEncryptor.encrypt."""
    return _default_encryptor.encrypt(plaintext)


def decrypt_secret(ciphertext: str) -> str:
    """Decrypt a stored secret value. See SecretEncryptor.decrypt."""
    return _default_encryptor.decrypt(ciphertext)
