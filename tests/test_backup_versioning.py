"""Unit tests for backup creation, AES-256 vault protection, and versioning engines.

Member 3: Recovery Engineer
TRINETRA: Bharat's Next-Generation Cyber Resilience Platform
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from vaultkeeper.encryption import generate_aes_key
from vaultkeeper.integrity import calculate_sha256
from vaultkeeper.manager import VaultkeeperManager
from vaultkeeper.metadata import SQLiteMetadataStore
from vaultkeeper.models import BackupStatus


def test_backup_creation_and_metadata(tmp_path: Path):
    """Test that creating a backup generates metadata and preserves the original file."""
    work_dir = tmp_path / "work"
    vault_dir = tmp_path / "vault"
    work_dir.mkdir()
    vault_dir.mkdir()

    source_file = work_dir / "invoice.docx"
    source_content = "Invoice #1001: Amount $500.00"
    source_file.write_text(source_content, encoding="utf-8")
    original_sha = calculate_sha256(source_file)

    key = generate_aes_key()
    manager = VaultkeeperManager(vault_dir=vault_dir, encryption_key=key)

    meta = manager.backup_file(source_file, custom_timestamp="2026-08-19T10:00:00")

    # Verify metadata fields
    assert meta.version_number == 1
    assert meta.file_size == len(source_content.encode("utf-8"))
    assert meta.sha256_hash == original_sha
    assert meta.status == BackupStatus.VERIFIED_CLEAN.value
    assert meta.is_encrypted is True
    assert meta.encryption_algorithm == "AES-256-GCM"

    # Verify original file untouched
    assert source_file.read_text(encoding="utf-8") == source_content

    # Verify vault file exists on disk and is encrypted (not plain text)
    vault_path = Path(meta.vault_path)
    assert vault_path.is_file()
    assert vault_path.read_bytes() != source_content.encode("utf-8")


def test_multiple_versions_preserved(tmp_path: Path):
    """Test creating multiple sequential versions (v1, v2, v3) without overwriting."""
    work_dir = tmp_path / "work"
    vault_dir = tmp_path / "vault"
    work_dir.mkdir()
    vault_dir.mkdir()

    doc = work_dir / "report.docx"
    key = generate_aes_key()
    manager = VaultkeeperManager(vault_dir=vault_dir, encryption_key=key)

    # Version 1
    doc.write_text("Report Draft V1", encoding="utf-8")
    m1 = manager.backup_file(doc, custom_timestamp="2026-08-19T09:00:00")

    # Version 2
    doc.write_text("Report Draft V2 - Edits", encoding="utf-8")
    m2 = manager.backup_file(doc, custom_timestamp="2026-08-19T10:00:00")

    # Version 3
    doc.write_text("Report Final V3 - Signed", encoding="utf-8")
    m3 = manager.backup_file(doc, custom_timestamp="2026-08-19T11:00:00")

    assert m1.version_number == 1
    assert m2.version_number == 2
    assert m3.version_number == 3

    # Ensure all 3 physical vault files exist separately
    assert Path(m1.vault_path).exists()
    assert Path(m2.vault_path).exists()
    assert Path(m3.vault_path).exists()
    assert m1.vault_path != m2.vault_path != m3.vault_path

    # Check version listing
    versions = manager.list_file_versions(doc)
    assert len(versions) == 3
    assert [v.version_number for v in versions] == [1, 2, 3]


def test_attack_timestamp_filtering_and_sorting(tmp_path: Path):
    """Test filtering candidate backups against the attack boundary timestamp."""
    work_dir = tmp_path / "work"
    vault_dir = tmp_path / "vault"
    work_dir.mkdir()
    vault_dir.mkdir()

    doc = work_dir / "database.sqlite"
    key = generate_aes_key()
    manager = VaultkeeperManager(vault_dir=vault_dir, encryption_key=key)

    # v1 at 10:00
    doc.write_text("DB State 1", encoding="utf-8")
    manager.backup_file(doc, custom_timestamp="2026-08-19T10:00:00")

    # v2 at 11:00
    doc.write_text("DB State 2", encoding="utf-8")
    manager.backup_file(doc, custom_timestamp="2026-08-19T11:00:00")

    # v3 at 12:00
    doc.write_text("DB State 3", encoding="utf-8")
    manager.backup_file(doc, custom_timestamp="2026-08-19T12:00:00")

    # v4 at 12:06 (post-attack)
    doc.write_text("DB State 4 [Encrypted Ransomware Garbage]", encoding="utf-8")
    manager.backup_file(doc, custom_timestamp="2026-08-19T12:06:00")

    # Attack occurred at 12:05:00
    attack_time = "2026-08-19T12:05:00"

    candidates = manager.versioning_engine.get_candidate_versions_before_boundary(
        source_path=doc, attack_timestamp=attack_time
    )

    # Must contain v1, v2, v3, but EXCLUDE v4 (12:06 >= 12:05)
    assert len(candidates) == 3
    # Must be sorted newest to oldest: [v3, v2, v1]
    assert candidates[0].version_number == 3
    assert candidates[1].version_number == 2
    assert candidates[2].version_number == 1


def test_backup_directory_batch(tmp_path: Path):
    """Test backing up an entire directory of files."""
    work_dir = tmp_path / "folder"
    vault_dir = tmp_path / "vault"
    work_dir.mkdir()
    vault_dir.mkdir()

    (work_dir / "f1.txt").write_text("File 1", encoding="utf-8")
    (work_dir / "f2.txt").write_text("File 2", encoding="utf-8")
    sub = work_dir / "subdir"
    sub.mkdir()
    (sub / "f3.txt").write_text("File 3", encoding="utf-8")

    manager = VaultkeeperManager(vault_dir=vault_dir, encryption_key=generate_aes_key())
    backed_up = manager.backup_directory(work_dir, recursive=True)

    assert len(backed_up) == 3
    all_stored = manager.get_all_backups()
    assert len(all_stored) == 3
