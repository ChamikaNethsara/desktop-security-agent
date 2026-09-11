from __future__ import annotations

import codecs
import logging
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from config.default_config import MAX_FILE_SIZE_BYTES

logger = logging.getLogger(__name__)


class FileReadStatus(Enum):
    SUCCESS = "success"
    NOT_FOUND = "not_found"
    NOT_A_FILE = "not_a_file"
    TOO_LARGE = "too_large"
    BINARY = "binary"
    PERMISSION_DENIED = "permission_denied"
    DECODE_ERROR = "decode_error"
    IO_ERROR = "io_error"


@dataclass(frozen=True)
class FileReadResult:
    """
    Result of a safe file read and content is populated only when status == SUCCESS.
    """

    path: Path
    status: FileReadStatus

    content: str | None = None
    encoding: str | None = None
    size_bytes: int = 0

    error_message: str | None = None


class SecureFileReader:
    """
    Safely reads text configuration files.
    """

    def __init__(self, max_file_size_bytes: int = MAX_FILE_SIZE_BYTES,) -> None:
        if max_file_size_bytes <= 0:
            raise ValueError("max_file_size_bytes must be greater than zero.")

        self._max_file_size_bytes = max_file_size_bytes

    # Safely read a file as text.
    def read(self, path: Path) -> FileReadResult:
        path = path.expanduser().resolve()

        # -- Existence
        if not path.exists():
            return FileReadResult(
                path=path,
                status=FileReadStatus.NOT_FOUND,
            )

        # -- Regular file check
        if not path.is_file():
            return FileReadResult(
                path=path,
                status=FileReadStatus.NOT_A_FILE,
            )

        # -- File size
        try:
            size_bytes = path.stat().st_size
        except OSError as exc:
            logger.warning("Unable to stat file: %s (%s)", path, exc)

            return FileReadResult(
                path=path,
                status=FileReadStatus.IO_ERROR,
                error_message=str(exc),
            )

        if size_bytes > self._max_file_size_bytes:
            logger.info("Skipping oversized file: %s (%d bytes)", path, size_bytes)

            return FileReadResult(
                path=path,
                status=FileReadStatus.TOO_LARGE,
                size_bytes=size_bytes,
            )

        # -- Read raw bytes
        try:
            raw_data = path.read_bytes()
        except PermissionError as exc:
            logger.warning("Permission denied while reading file: %s", path)

            return FileReadResult(
                path=path,
                status=FileReadStatus.PERMISSION_DENIED,
                size_bytes=size_bytes,
                error_message=str(exc),
            )

        except OSError as exc:
            logger.warning("I/O error while reading file: %s (%s)", path, exc)

            return FileReadResult(
                path=path,
                status=FileReadStatus.IO_ERROR,
                size_bytes=size_bytes,
                error_message=str(exc),
            )

        # -- Binary detection
        if self._looks_binary(raw_data):
            return FileReadResult(
                path=path,
                status=FileReadStatus.BINARY,
                size_bytes=size_bytes,
            )

        # -- Decode
        content, encoding = self._decode(raw_data)

        if content is None:
            return FileReadResult(
                path=path,
                status=FileReadStatus.DECODE_ERROR,
                size_bytes=size_bytes,
            )

        return FileReadResult(
            path=path,
            status=FileReadStatus.SUCCESS,
            content=content,
            encoding=encoding,
            size_bytes=size_bytes,
        )

    # Detect whether the supplied data appears to be binary content.
    @staticmethod
    def _looks_binary(data: bytes) -> bool:
        if b"\x00" in data:
            return True

        if not data:
            return False

        # Count control characters other than common text whitespace.
        control_count = 0

        for byte in data:
            if byte < 32 and byte not in {
                9,   # tab
                10,  # LF
                13,  # CR
            }:
                control_count += 1

        control_ratio = control_count / len(data)
        return control_ratio > 0.05

    @staticmethod
    def _decode(data: bytes) -> tuple[str | None, str | None]:
        # -- BOM-aware decoding
        if data.startswith(codecs.BOM_UTF8):
            try:
                return data.decode("utf-8-sig"), "utf-8-sig"
            except UnicodeDecodeError:
                return None, None

        if data.startswith(codecs.BOM_UTF16_LE):
            try:
                return data.decode("utf-16-le"), "utf-16-le"
            except UnicodeDecodeError:
                return None, None

        if data.startswith(codecs.BOM_UTF16_BE):
            try:
                return data.decode("utf-16-be"), "utf-16-be"
            except UnicodeDecodeError:
                return None, None


        # -- Standard UTF-8
        try:
            return data.decode("utf-8"), "utf-8"
        except UnicodeDecodeError:
            pass

        # -- UTF-16 fallback
        try:
            return data.decode("utf-16"), "utf-16"
        except UnicodeDecodeError:
            pass

        # -- Could not decode safely
        return None, None