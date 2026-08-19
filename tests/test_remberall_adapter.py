"""Unit tests for the Remberall adapter abstraction and mock implementation.

Member 3: Recovery Engineer
TRINETRA: Bharat's Next-Generation Cyber Resilience Platform
"""

from pathlib import Path

import pytest

from vaultkeeper.remberall_adapter import MockRemberallAdapter, RemberallAdapter


def test_remberall_adapter_abstract_enforcement():
    """Verify that RemberallAdapter cannot be instantiated directly without implementing methods."""
    with pytest.raises(TypeError):
        RemberallAdapter()  # type: ignore[abstract]


def test_mock_remberall_adapter_snapshot_and_listing(tmp_path: Path):
    """Test snapshot creation, cataloging, and deduplication calculation in MockRemberallAdapter."""
    adapter = MockRemberallAdapter()

    src1 = tmp_path / "doc1.txt"
    src2 = tmp_path / "doc2.txt"
    vault1 = tmp_path / "v1.vault"
    vault2 = tmp_path / "v2.vault"

    src1.write_text("Hello World", encoding="utf-8")
    src2.write_text("Hello World", encoding="utf-8")  # Same content -> duplicate hash
    vault1.write_bytes(b"enc1")
    vault2.write_bytes(b"enc2")

    hash_val = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

    # 1. Create first snapshot
    snap1 = adapter.create_snapshot(
        source_path=src1,
        vault_path=vault1,
        sha256_hash=hash_val,
        file_size=11,
    )
    assert snap1["snapshot_id"] == "remberall_snap_000001"
    assert snap1["is_deduplicated"] is False

    # 2. Create second snapshot with duplicate content
    snap2 = adapter.create_snapshot(
        source_path=src2,
        vault_path=vault2,
        sha256_hash=hash_val,
        file_size=11,
    )
    assert snap2["snapshot_id"] == "remberall_snap_000002"
    assert snap2["is_deduplicated"] is True

    # 3. List snapshots per file
    snaps_doc1 = adapter.list_snapshots(src1)
    assert len(snaps_doc1) == 1
    assert snaps_doc1[0]["snapshot_id"] == "remberall_snap_000001"

    # 4. Verify integrity check
    assert adapter.verify_snapshot("remberall_snap_000001", hash_val) is True
    assert adapter.verify_snapshot("remberall_snap_000001", "wrong_hash") is False
    assert adapter.verify_snapshot("nonexistent_id", hash_val) is False

    # 5. Check deduplication metrics
    metrics = adapter.get_deduplication_metrics()
    assert metrics["total_snapshots"] == 2
    assert metrics["unique_content_hashes"] == 1
    assert metrics["simulated_bytes_saved"] == 11
    assert metrics["total_ingested_bytes"] == 22
    assert metrics["deduplication_ratio"] == 2.0
