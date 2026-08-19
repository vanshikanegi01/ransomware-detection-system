"""Cryptographic integrity verification utilities using SHA-256.

Member 3: Recovery Engineer
TRINETRA: Bharat's Next-Generation Cyber Resilience Platform
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Union

CHUNK_SIZE = 64 * 1024  # 64 KB streaming buffer


def calculate_sha256(file_path: Union[str, Path], chunk_size: int = CHUNK_SIZE) -> str:
    """Calculate the SHA-256 hexadecimal hash of a file using streaming chunks.

    Args:
        file_path: Path to the target file.
        chunk_size: Read buffer size in bytes (default 64KB).

    Returns:
        64-character lowercase hexadecimal SHA-256 digest.

    Raises:
        FileNotFoundError: If the target file does not exist.
        IsADirectoryError: If the path is a directory.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found for SHA-256 calculation: {path}")

    hasher = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest().lower()


def calculate_bytes_sha256(data: bytes) -> str:
    """Calculate the SHA-256 hexadecimal hash of raw byte data.

    Args:
        data: Raw bytes to hash.

    Returns:
        64-character lowercase hexadecimal SHA-256 digest.
    """
    return hashlib.sha256(data).hexdigest().lower()


def verify_file_integrity(file_path: Union[str, Path], expected_hash: str) -> bool:
    """Verify that a file's SHA-256 hash matches the expected hash.

    Args:
        file_path: Path to the file to verify.
        expected_hash: The known clean/stored SHA-256 digest.

    Returns:
        True if hashes match exactly, False otherwise (including on missing file).
    """
    try:
        actual_hash = calculate_sha256(file_path)
        return actual_hash == expected_hash.strip().lower()
    except (FileNotFoundError, PermissionError, IsADirectoryError):
        return False


def verify_bytes_integrity(data: bytes, expected_hash: str) -> bool:
    """Verify that raw bytes' SHA-256 hash matches the expected hash.

    Args:
        data: Byte buffer to verify.
        expected_hash: The known clean/stored SHA-256 digest.

    Returns:
        True if hashes match exactly, False otherwise.
    """
    actual_hash = calculate_bytes_sha256(data)
    return actual_hash == expected_hash.strip().lower()
