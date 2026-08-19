"""Adapter interface and mock implementation for the Remberall recovery/versioning layer.

=============================================================================
ARCHITECTURAL NOTE ON REMBERALL INTEGRATION:
The TRINETRA project specification defines Remberall as an open-source
recovery and versioning layer providing snapshotting, deduplication,
integrity verification, and fast recovery.

Because the specific third-party Python SDK / method signatures for Remberall
are not specified in the project documentation, Vaultkeeper strictly isolates
all Remberall interactions behind this Adapter Pattern (`RemberallAdapter`).

Do NOT call hypothetical external Remberall functions directly in core logic.
When the concrete Remberall SDK is integrated, implement a production adapter
implementing `RemberallAdapter`.
=============================================================================

Member 3: Recovery Engineer
TRINETRA: Bharat's Next-Generation Cyber Resilience Platform
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from vaultkeeper.integrity import calculate_sha256


class RemberallAdapter(ABC):
    """Abstract interface defining required capabilities for Remberall integration."""

    @abstractmethod
    def create_snapshot(
        self, source_path: Path, vault_path: Path, sha256_hash: str, **kwargs: Any
    ) -> Dict[str, Any]:
        """Record and manage a point-in-time file snapshot.

        Args:
            source_path: Path to the original file.
            vault_path: Path where the protected snapshot copy is stored.
            sha256_hash: Pre-calculated SHA-256 fingerprint.

        Returns:
            Dictionary containing snapshot reference information.
        """

    @abstractmethod
    def list_snapshots(self, source_path: Path) -> List[Dict[str, Any]]:
        """List historical snapshots for a given source path.

        Args:
            source_path: Path to the original file.

        Returns:
            List of snapshot descriptor dictionaries.
        """

    @abstractmethod
    def verify_snapshot(self, snapshot_id: str, expected_hash: str) -> bool:
        """Verify the cryptographic integrity of a snapshot.

        Args:
            snapshot_id: Unique snapshot identifier.
            expected_hash: Known expected SHA-256 digest.

        Returns:
            True if integrity is verified, False otherwise.
        """

    @abstractmethod
    def restore_snapshot(self, snapshot_id: str, target_path: Path) -> bool:
        """Restore a snapshot to the designated target path.

        Args:
            snapshot_id: Unique snapshot identifier.
            target_path: Destination path on disk.

        Returns:
            True if restored successfully, False otherwise.
        """

    @abstractmethod
    def get_deduplication_metrics(self) -> Dict[str, Any]:
        """Return storage deduplication statistics.

        Returns:
            Dictionary with deduplication metrics (e.g., total snapshots, unique hashes, bytes saved).
        """


class MockRemberallAdapter(RemberallAdapter):
    """Local, decoupled reference implementation of the Remberall adapter.

    Used for testing, local offline execution, and prototype demonstrations
    without requiring an external undocumented daemon or C-extension.
    """

    def __init__(self) -> None:
        # In-memory catalog: snapshot_id -> snapshot_info
        self._snapshots: Dict[str, Dict[str, Any]] = {}
        # In-memory index: source_path -> list of snapshot_ids
        self._file_index: Dict[str, List[str]] = {}
        # Deduplication tracking: hash -> storage_path
        self._hash_store: Dict[str, str] = {}
        self._bytes_saved: int = 0
        self._total_ingested_bytes: int = 0

    def create_snapshot(
        self, source_path: Path, vault_path: Path, sha256_hash: str, **kwargs: Any
    ) -> Dict[str, Any]:
        """Record a snapshot and track simulated deduplication."""
        src_str = str(source_path.resolve().as_posix())
        vault_str = str(vault_path.resolve().as_posix())
        snapshot_id = f"remberall_snap_{len(self._snapshots) + 1:06d}"
        file_size = kwargs.get("file_size", 0)

        self._total_ingested_bytes += file_size
        is_duplicate = sha256_hash in self._hash_store
        if is_duplicate:
            self._bytes_saved += file_size
        else:
            self._hash_store[sha256_hash] = vault_str

        record = {
            "snapshot_id": snapshot_id,
            "source_path": src_str,
            "vault_path": vault_str,
            "sha256": sha256_hash.lower(),
            "timestamp": kwargs.get(
                "timestamp", datetime.now(timezone.utc).isoformat()
            ),
            "file_size": file_size,
            "is_deduplicated": is_duplicate,
            "metadata": kwargs,
        }

        self._snapshots[snapshot_id] = record
        if src_str not in self._file_index:
            self._file_index[src_str] = []
        self._file_index[src_str].append(snapshot_id)

        return record

    def list_snapshots(self, source_path: Path) -> List[Dict[str, Any]]:
        """List all snapshots registered for the given source path."""
        src_str = str(source_path.resolve().as_posix())
        snap_ids = self._file_index.get(src_str, [])
        return [self._snapshots[sid] for sid in snap_ids if sid in self._snapshots]

    def verify_snapshot(self, snapshot_id: str, expected_hash: str) -> bool:
        """Check stored hash against expected hash."""
        snap = self._snapshots.get(snapshot_id)
        if not snap:
            return False
        return snap["sha256"] == expected_hash.strip().lower()

    def restore_snapshot(self, snapshot_id: str, target_path: Path) -> bool:
        """Simulate adapter-level restore validation."""
        snap = self._snapshots.get(snapshot_id)
        if not snap:
            return False
        vault_path = Path(snap["vault_path"])
        return vault_path.exists()

    def get_deduplication_metrics(self) -> Dict[str, Any]:
        """Return simulated deduplication stats."""
        return {
            "adapter_type": "MockRemberallAdapter",
            "total_snapshots": len(self._snapshots),
            "unique_content_hashes": len(self._hash_store),
            "total_ingested_bytes": self._total_ingested_bytes,
            "simulated_bytes_saved": self._bytes_saved,
            "deduplication_ratio": (
                round(self._total_ingested_bytes / max(1, (self._total_ingested_bytes - self._bytes_saved)), 2)
                if (self._total_ingested_bytes - self._bytes_saved) > 0
                else 1.0
            ),
        }
