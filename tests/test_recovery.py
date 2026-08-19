"""Unit tests for the Vaultkeeper recovery engine, rollback algorithm, and state machine.

Member 3: Recovery Engineer
TRINETRA: Bharat's Next-Generation Cyber Resilience Platform
"""

import json
from pathlib import Path

import pytest

from vaultkeeper.encryption import generate_aes_key
from vaultkeeper.integrity import calculate_sha256
from vaultkeeper.manager import VaultkeeperManager
from vaultkeeper.models import (
    FileRecoveryStatus,
    IncidentEvent,
    RecoveryProgressEvent,
    RecoveryState,
)


def test_single_file_recovery_and_post_verification(tmp_path: Path):
    """Test full recovery cycle of a single file corrupted by simulated ransomware."""
    work_dir = tmp_path / "work"
    vault_dir = tmp_path / "vault"
    work_dir.mkdir()
    vault_dir.mkdir()

    doc = work_dir / "financials.xlsx"
    original_content = "Q3 Revenue: $1,200,000 | Net Profit: $350,000"
    doc.write_text(original_content, encoding="utf-8")
    expected_hash = calculate_sha256(doc)

    manager = VaultkeeperManager(vault_dir=vault_dir, encryption_key=generate_aes_key())

    # 1. Take clean backup at 10:00
    meta = manager.backup_file(doc, custom_timestamp="2026-08-19T10:00:00")

    # 2. Simulate ransomware damage on original file at 12:00
    doc.write_text("ENCRYPTED_RANSOMWARE_GARBAGE_PAYLOAD", encoding="utf-8")
    assert calculate_sha256(doc) != expected_hash

    # 3. Trigger recovery with attack timestamp 12:00
    incident = {
        "event": "RANSOMWARE_CONFIRMED",
        "incident_id": "INC-001",
        "timestamp": "2026-08-19T12:00:00",
        "risk_score": 90.0,
        "affected_files": [str(doc)],
    }

    report = manager.handle_incident(incident)

    # 4. Verify report metrics
    assert report.recovery_status == RecoveryState.COMPLETE.value
    assert report.files_at_risk == 1
    assert report.files_recovered == 1
    assert report.files_lost == 0
    assert report.files[0].status == FileRecoveryStatus.RECOVERED.value
    assert report.files[0].version_used == meta.version_id

    # 5. Verify restored file on disk
    assert doc.read_text(encoding="utf-8") == original_content
    assert calculate_sha256(doc) == expected_hash


def test_fallback_to_older_candidate_on_integrity_failure(tmp_path: Path):
    """Test that if the newest candidate fails integrity check, Vaultkeeper falls back to an older candidate."""
    work_dir = tmp_path / "work"
    vault_dir = tmp_path / "vault"
    work_dir.mkdir()
    vault_dir.mkdir()

    doc = work_dir / "critical_data.csv"
    key = generate_aes_key()
    manager = VaultkeeperManager(vault_dir=vault_dir, encryption_key=key)

    # v1 at 09:00 (Clean)
    v1_content = "ID,Name,Role\n1,Alice,Admin"
    doc.write_text(v1_content, encoding="utf-8")
    m1 = manager.backup_file(doc, custom_timestamp="2026-08-19T09:00:00")
    v1_expected_hash = calculate_sha256(doc)

    # v2 at 10:00 (Clean when created)
    v2_content = "ID,Name,Role\n1,Alice,Admin\n2,Bob,Engineer"
    doc.write_text(v2_content, encoding="utf-8")
    m2 = manager.backup_file(doc, custom_timestamp="2026-08-19T10:00:00")

    # Manually tamper with the v2 physical vault file (simulate vault storage corruption)
    v2_vault_file = Path(m2.vault_path)
    corrupted_bytes = bytearray(v2_vault_file.read_bytes())
    corrupted_bytes[15] ^= 0xFF  # Flip bits in ciphertext
    v2_vault_file.write_bytes(bytes(corrupted_bytes))

    # Attack occurs at 12:00
    # Overwrite source file with dummy malware data
    doc.write_text("MALWARE_OVERWRITE", encoding="utf-8")

    incident = {
        "event": "RANSOMWARE_CONFIRMED",
        "incident_id": "INC-TAMPER-002",
        "timestamp": "2026-08-19T12:00:00",
        "affected_files": [str(doc)],
    }

    report = manager.handle_incident(incident)

    # Must fall back to v1 and succeed!
    assert report.recovery_status == RecoveryState.COMPLETE.value
    assert report.files_recovered == 1
    assert report.integrity_failures >= 1
    assert report.files[0].version_used == m1.version_id
    assert doc.read_text(encoding="utf-8") == v1_content
    assert calculate_sha256(doc) == v1_expected_hash


def test_selective_multi_file_restoration(tmp_path: Path):
    """Test that only affected files are restored, leaving unaffected files completely untouched."""
    work_dir = tmp_path / "work"
    vault_dir = tmp_path / "vault"
    work_dir.mkdir()
    vault_dir.mkdir()

    f1 = work_dir / "file1.txt"
    f2 = work_dir / "file2.txt"
    f3 = work_dir / "file3.txt"

    f1.write_text("Clean File 1", encoding="utf-8")
    f2.write_text("Clean File 2", encoding="utf-8")
    f3.write_text("Clean File 3", encoding="utf-8")

    manager = VaultkeeperManager(vault_dir=vault_dir, encryption_key=generate_aes_key())
    manager.backup_files([f1, f2, f3], custom_timestamp="2026-08-19T10:00:00")

    # Mutate file1 and file2 (affected by attack), but file3 is untouched
    f1.write_text("RANSOM_ENCRYPTED_1", encoding="utf-8")
    f2.write_text("RANSOM_ENCRYPTED_2", encoding="utf-8")

    incident = {
        "event": "RANSOMWARE_CONFIRMED",
        "incident_id": "INC-SELECTIVE-003",
        "timestamp": "2026-08-19T12:00:00",
        "affected_files": [str(f1), str(f2)],  # f3 is not in list
    }

    report = manager.handle_incident(incident)

    assert report.recovery_status == RecoveryState.COMPLETE.value
    assert report.files_at_risk == 2
    assert report.files_recovered == 2

    # f1 and f2 restored
    assert f1.read_text(encoding="utf-8") == "Clean File 1"
    assert f2.read_text(encoding="utf-8") == "Clean File 2"
    # f3 remains intact
    assert f3.read_text(encoding="utf-8") == "Clean File 3"


def test_partial_and_failed_recovery_reporting(tmp_path: Path):
    """Test partial recovery when one file has a valid backup and another has no backup."""
    work_dir = tmp_path / "work"
    vault_dir = tmp_path / "vault"
    work_dir.mkdir()
    vault_dir.mkdir()

    f_backed_up = work_dir / "saved.txt"
    f_unbacked = work_dir / "never_backed_up.txt"

    f_backed_up.write_text("Known Good State", encoding="utf-8")
    f_unbacked.write_text("Unbacked State", encoding="utf-8")

    manager = VaultkeeperManager(vault_dir=vault_dir, encryption_key=generate_aes_key())
    manager.backup_file(f_backed_up, custom_timestamp="2026-08-19T10:00:00")

    # Corrupt both
    f_backed_up.write_text("CORRUPTED", encoding="utf-8")
    f_unbacked.write_text("CORRUPTED", encoding="utf-8")

    incident = {
        "event": "RANSOMWARE_CONFIRMED",
        "incident_id": "INC-PARTIAL-004",
        "timestamp": "2026-08-19T12:00:00",
        "affected_files": [str(f_backed_up), str(f_unbacked)],
    }

    report = manager.handle_incident(incident)

    assert report.recovery_status == RecoveryState.PARTIAL.value
    assert report.files_at_risk == 2
    assert report.files_recovered == 1
    assert report.files_lost == 1

    # Verify per-file status
    results_by_path = {Path(r.path).name: r for r in report.files}
    assert results_by_path["saved.txt"].status == FileRecoveryStatus.RECOVERED.value
    assert results_by_path["never_backed_up.txt"].status == FileRecoveryStatus.FAILED.value


def test_progress_callbacks_and_reporting_persistence(tmp_path: Path):
    """Test that progress events are emitted and reports can be retrieved from metadata DB."""
    work_dir = tmp_path / "work"
    vault_dir = tmp_path / "vault"
    work_dir.mkdir()
    vault_dir.mkdir()

    f1 = work_dir / "audit.txt"
    f1.write_text("Audit Log Clean", encoding="utf-8")

    manager = VaultkeeperManager(vault_dir=vault_dir, encryption_key=generate_aes_key())
    manager.backup_file(f1, custom_timestamp="2026-08-19T09:00:00")

    f1.write_text("LOCKED", encoding="utf-8")

    events_received: list[RecoveryProgressEvent] = []

    def on_progress(ev: RecoveryProgressEvent):
        events_received.append(ev)

    incident = {
        "event": "RANSOMWARE_CONFIRMED",
        "incident_id": "INC-AUDIT-005",
        "timestamp": "2026-08-19T12:00:00",
        "affected_files": [str(f1)],
    }

    report = manager.handle_incident(incident, progress_callback=on_progress)

    # Check progress events emitted
    event_names = [e.event for e in events_received]
    assert "recovery_started" in event_names
    assert "file_recovered" in event_names
    assert "recovery_complete" in event_names

    # Check persistence retrieval
    stored_report = manager.get_incident_report("INC-AUDIT-005")
    assert stored_report is not None
    assert stored_report.incident_id == "INC-AUDIT-005"
    assert stored_report.files_recovered == 1
    assert stored_report.recovery_status == RecoveryState.COMPLETE.value
