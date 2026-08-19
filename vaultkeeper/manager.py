"""High-level facade and orchestrator for the TRINETRA Vaultkeeper module.

Member 3: Recovery Engineer
TRINETRA: Bharat's Next-Generation Cyber Resilience Platform
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

from vaultkeeper.backup import BackupEngine
from vaultkeeper.encryption import generate_aes_key
from vaultkeeper.metadata import MetadataStore, SQLiteMetadataStore, normalize_path
from vaultkeeper.models import (
    BackupMetadata,
    IncidentEvent,
    RecoveryProgressEvent,
    RecoveryReport,
    RecoveryState,
)
from vaultkeeper.recovery import RecoveryEngine
from vaultkeeper.remberall_adapter import MockRemberallAdapter, RemberallAdapter
from vaultkeeper.restore import RestoreEngine
from vaultkeeper.versioning import VersioningEngine

logger = logging.getLogger(__name__)


class VaultkeeperManager:
    """Unified entry point providing backup, versioning, AES-256 protection, and auto-recovery."""

    def __init__(
        self,
        vault_dir: Union[str, Path],
        db_path: Optional[Union[str, Path]] = None,
        encryption_key: Optional[bytes] = None,
        remberall_adapter: Optional[RemberallAdapter] = None,
    ) -> None:
        """Initialize VaultkeeperManager.

        Args:
            vault_dir: Directory where protected, encrypted backup snapshots will reside.
            db_path: Optional path for SQLite metadata catalog (defaults to vault_dir/metadata.db).
            encryption_key: 32-byte AES-256 key. If None, auto-generates or uses unencrypted fallback based on config.
            remberall_adapter: Optional custom Remberall adapter (defaults to MockRemberallAdapter).
        """
        self.vault_dir = Path(vault_dir).resolve()
        self.vault_dir.mkdir(parents=True, exist_ok=True)

        if db_path is None:
            metadata_file = self.vault_dir / "vault_metadata.db"
            self.metadata_store: MetadataStore = SQLiteMetadataStore(metadata_file)
        elif isinstance(db_path, str) and db_path == ":memory:":
            self.metadata_store = SQLiteMetadataStore(":memory:")
        else:
            self.metadata_store = SQLiteMetadataStore(db_path)

        self.encryption_key = encryption_key
        self.remberall_adapter = remberall_adapter or MockRemberallAdapter()

        # Instantiate sub-engines
        self.backup_engine = BackupEngine(
            vault_dir=self.vault_dir,
            metadata_store=self.metadata_store,
            encryption_key=self.encryption_key,
            remberall_adapter=self.remberall_adapter,
        )

        self.versioning_engine = VersioningEngine(
            metadata_store=self.metadata_store
        )

        self.restore_engine = RestoreEngine(
            encryption_key=self.encryption_key,
            metadata_store=self.metadata_store,
        )

        self.recovery_engine = RecoveryEngine(
            versioning_engine=self.versioning_engine,
            restore_engine=self.restore_engine,
            metadata_store=self.metadata_store,
        )

    # -------------------------------------------------------------------------
    # Backup & Snapshot Operations
    # -------------------------------------------------------------------------

    def backup_file(
        self,
        source_path: Union[str, Path],
        custom_timestamp: Optional[Union[str, datetime]] = None,
    ) -> BackupMetadata:
        """Create a protected, versioned backup copy of an individual file.

        Args:
            source_path: Path to the target file.
            custom_timestamp: Optional point-in-time timestamp.

        Returns:
            BackupMetadata describing the new version.
        """
        return self.backup_engine.create_backup(
            source_path=source_path, custom_timestamp=custom_timestamp
        )

    def backup_files(
        self,
        file_paths: List[Union[str, Path]],
        custom_timestamp: Optional[Union[str, datetime]] = None,
    ) -> List[BackupMetadata]:
        """Back up a collection of individual file paths.

        Args:
            file_paths: List of file paths to preserve.
            custom_timestamp: Optional batch timestamp.

        Returns:
            List of created BackupMetadata records.
        """
        return self.backup_engine.backup_files(
            file_paths=file_paths, custom_timestamp=custom_timestamp
        )

    def backup_directory(
        self,
        directory_path: Union[str, Path],
        recursive: bool = True,
        custom_timestamp: Optional[Union[str, datetime]] = None,
    ) -> List[BackupMetadata]:
        """Back up all files in a directory.

        Args:
            directory_path: Directory path to scan and back up.
            recursive: Whether to recursively scan subdirectories.
            custom_timestamp: Optional batch timestamp.

        Returns:
            List of created BackupMetadata records.
        """
        return self.backup_engine.backup_directory(
            directory_path=directory_path,
            recursive=recursive,
            custom_timestamp=custom_timestamp,
        )

    # -------------------------------------------------------------------------
    # Versioning & Queries
    # -------------------------------------------------------------------------

    def list_file_versions(self, source_path: Union[str, Path]) -> List[BackupMetadata]:
        """Retrieve all recorded historical versions for a file.

        Args:
            source_path: Path to target file.

        Returns:
            List of BackupMetadata records ordered chronologically.
        """
        return self.versioning_engine.list_versions(source_path)

    def get_backup(self, version_id: str) -> Optional[BackupMetadata]:
        """Retrieve metadata for a specific version ID."""
        return self.metadata_store.get_backup(version_id)

    def get_all_backups(self) -> List[BackupMetadata]:
        """Retrieve all backup records across the entire vault catalog."""
        return self.metadata_store.get_all_backups()

    # -------------------------------------------------------------------------
    # Incident Handling & Recovery
    # -------------------------------------------------------------------------

    def handle_incident(
        self,
        incident: Union[Dict[str, Any], IncidentEvent],
        progress_callback: Optional[Callable[[RecoveryProgressEvent], None]] = None,
        destination_override: Optional[Union[str, Path]] = None,
    ) -> RecoveryReport:
        """Handle a confirmed ransomware incident and execute automated recovery.

        Args:
            incident: Structured incident dict or IncidentEvent model from Policy Engine.
            progress_callback: Optional progress listener for FastAPI WebSocket/UI feeds.
            destination_override: Optional target directory for safe restore testing.

        Returns:
            RecoveryReport containing complete recovery results and per-file audit trail.
        """
        if isinstance(incident, dict):
            incident_obj = IncidentEvent.from_dict(incident)
        else:
            incident_obj = incident

        return self.recovery_engine.execute_recovery(
            incident=incident_obj,
            progress_callback=progress_callback,
            destination_override=destination_override,
        )

    def get_incident_report(self, incident_id: str) -> Optional[RecoveryReport]:
        """Retrieve a stored recovery report by incident ID."""
        return self.metadata_store.get_incident_report(incident_id)

    @property
    def current_recovery_state(self) -> RecoveryState:
        """Get the current state of the recovery state machine."""
        return self.recovery_engine.current_state

    # -------------------------------------------------------------------------
    # Diagnostics & Adapter Metrics
    # -------------------------------------------------------------------------

    def get_adapter_metrics(self) -> Dict[str, Any]:
        """Return metrics from the Remberall adapter layer."""
        return self.remberall_adapter.get_deduplication_metrics()

    def audit_vault_integrity(self) -> Dict[str, Any]:
        """Audit the cryptographic integrity of all stored backups in the vault.

        Returns:
            Dictionary with counts of clean vs corrupted backups found.
        """
        all_backups = self.get_all_backups()
        total = len(all_backups)
        valid_count = 0
        corrupted_count = 0

        for b in all_backups:
            is_valid, _, _ = self.restore_engine.verify_candidate_integrity(b)
            if is_valid:
                valid_count += 1
            else:
                corrupted_count += 1

        return {
            "total_backups_audited": total,
            "valid_backups": valid_count,
            "corrupted_backups": corrupted_count,
            "vault_integrity_healthy": corrupted_count == 0,
        }
