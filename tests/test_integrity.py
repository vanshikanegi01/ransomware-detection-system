"""Unit tests for SHA-256 integrity hashing and verification.

Member 3: Recovery Engineer
TRINETRA: Bharat's Next-Generation Cyber Resilience Platform
"""

import hashlib
import tempfile
from pathlib import Path

import pytest

from vaultkeeper.integrity import (
    calculate_bytes_sha256,
    calculate_sha256,
    verify_bytes_integrity,
    verify_file_integrity,
)


def test_sha256_stability(tmp_path: Path):
    """Test that calculating SHA-256 repeatedly for the same file produces identical output."""
    test_file = tmp_path / "sample.txt"
    test_file.write_text("Hello, TRINETRA Cyber Resilience Platform!", encoding="utf-8")

    hash1 = calculate_sha256(test_file)
    hash2 = calculate_sha256(test_file)

    assert len(hash1) == 64
    assert hash1 == hash2
    # Check against known hashlib digest
    expected = hashlib.sha256(b"Hello, TRINETRA Cyber Resilience Platform!").hexdigest()
    assert hash1 == expected


def test_sha256_changes_on_modification(tmp_path: Path):
    """Test that changing even a single byte changes the calculated hash."""
    test_file = tmp_path / "mutation.txt"
    test_file.write_bytes(b"Clean baseline data 12345")
    initial_hash = calculate_sha256(test_file)

    # Mutate 1 character
    test_file.write_bytes(b"Clean baseline data 12346")
    modified_hash = calculate_sha256(test_file)

    assert initial_hash != modified_hash


def test_sha256_chunked_streaming(tmp_path: Path):
    """Test chunked streaming on multi-megabyte payloads."""
    large_file = tmp_path / "large_payload.bin"
    chunk = b"A" * (64 * 1024)  # 64 KB
    total_chunks = 16  # 1 MB total

    with open(large_file, "wb") as f:
        for _ in range(total_chunks):
            f.write(chunk)

    expected_hash = hashlib.sha256(chunk * total_chunks).hexdigest()
    calculated_hash = calculate_sha256(large_file, chunk_size=32 * 1024)

    assert calculated_hash == expected_hash


def test_verify_file_integrity(tmp_path: Path):
    """Test verify_file_integrity logic on match, mismatch, and nonexistent files."""
    test_file = tmp_path / "verify.txt"
    test_file.write_text("Integrity Check Data", encoding="utf-8")
    actual_hash = calculate_sha256(test_file)

    # Valid match
    assert verify_file_integrity(test_file, actual_hash) is True
    # Case insensitivity & whitespace tolerance
    assert verify_file_integrity(test_file, f"  {actual_hash.upper()}  ") is True
    # Mismatched hash
    assert verify_file_integrity(test_file, "0" * 64) is False
    # Nonexistent file
    assert verify_file_integrity(tmp_path / "nonexistent.txt", actual_hash) is False


def test_bytes_integrity_helpers():
    """Test raw bytes calculation and verification."""
    data = b"In-memory stream test"
    digest = calculate_bytes_sha256(data)

    assert len(digest) == 64
    assert verify_bytes_integrity(data, digest) is True
    assert verify_bytes_integrity(data, "a" * 64) is False
