"""Protected backup creation and version vaulting engine.

Member 3: Recovery Engineer
TRINETRA: Bharat's Next-Generation Cyber Resilience Platform
"""

from __future__ import annotations

import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Union

from vaultkeeper.encryption import encrypt_file
from vaultkeeper.integrity import calculate_sha256
from vaultkeeper.metadata import MetadataStore, normalize_path
from vaultkeeper.models import BackupMetadata, BackupStatus
from vaultkeeper.remberall_adapter import RemberallAdapter


class BackupEngine:
    """Handles snapshotting, cryptographic hashing, AES-256 encryption, and cataloging."""

    def __init__(
        self,
        vault_dir: Union[str, Path],
        metadata_store: MetadataStore,
        encryption_key: Optional[bytes] = None,
        remberall_adapter: Optional[RemberallAdapter] = None,
    ) -> None:
        """Initialize BackupEngine.

        Args:
            vault_dir: Directory where protected vault copies are stored.
            metadata_store: Persistence store for backup metadata.
            encryption_key: 32-byte AES-256 key (if None, backups are stored unencrypted).
            remberall_adapter: Optional Remberall integration adapter.
        """
        self.vault_dir = Path(vault_dir).resolve()
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_store = metadata_store
        self.encryption_key = encryption_key
        self.remberall_adapter = remberall_adapter

    def create_backup(
        self,
        source_path: Union[str, Path],
        custom_timestamp: Optional[Union[str, datetime]] = None,
    ) -> BackupMetadata:
        """Create a protected, versioned backup copy of a source file.

        The original file is untouched and preserved.

        Args:
            source_path: Path to the clean file to back up.
            custom_timestamp: Optional explicit ISO timestamp or datetime object.

        Returns:
            BackupMetadata record of the saved version.

        Raises:
            FileNotFoundError: If the source file does not exist.
        """
        src = Path(source_path).resolve()
        if not src.is_file():
            raise FileNotFoundError(f"Source file not found for backup: {src}")

        # 1. Calculate SHA-256 of the uncompromised source file
        sha256_hash = calculate_sha256(src)
        file_size = src.stat().st_size

        # 2. Determine sequential version number
        version_num = self.metadata_store.get_next_version_number(src)

        # 3. Format timestamp
        if custom_timestamp is None:
            ts_str = datetime.now(timezone.utc).isoformat()
        elif isinstance(custom_timestamp, datetime):
            ts_str = custom_timestamp.isoformat()
        else:
            ts_str = str(custom_timestamp)

        # 4. Generate unique version ID and target vault path
        short_uuid = uuid.uuid4().hex[:8]
        version_id = f"v_{version_num:04d}_{short_uuid}"
        vault_filename = f"{src.stem}_v{version_num}_{version_id}.vault"
        vault_path = self.vault_dir / vault_filename

        # 5. Store file in vault (with AES-256-GCM encryption if key provided)
        is_encrypted = self.encryption_key is not None
        enc_algo = "AES-256-GCM" if is_encrypted else "NONE"

        if is_encrypted and self.encryption_key:
            encrypt_file(src, vault_path, self.encryption_key)
        else:
            shutil.copy2(src, vault_path)

        # 6. Construct metadata
        metadata = BackupMetadata(
            version_id=version_id,
            source_path=normalize_path(src),
            vault_path=normalize_path(vault_path),
            timestamp=ts_str,
            file_size=file_size,
            sha256_hash=sha256_hash,
            version_number=version_num,
            status=BackupStatus.VERIFIED_CLEAN.value,
            is_encrypted=is_encrypted,
            encryption_algorithm=enc_algo,
        )

        # 7. Record metadata in SQLite catalog
        self.metadata_store.add_backup(metadata)

        # 8. Notify Remberall adapter if configured
        if self.remberall_adapter:
            self.remberall_adapter.create_snapshot(
                source_path=src,
                vault_path=vault_path,
                sha256_hash=sha256_hash,
                version_id=version_id,
                version_number=version_num,
                timestamp=ts_str,
                file_size=file_size,
            )

        return metadata

    def backup_files(
        self,
        file_paths: List[Union[str, Path]],
        custom_timestamp: Optional[Union[str, datetime]] = None,
    ) -> List[BackupMetadata]:
        """Back up a list of individual files.

        Args:
            file_paths: List of file paths to back up.
            custom_timestamp: Optional timestamp to associate with all backups in this batch.

        Returns:
            List of created BackupMetadata records.
        """
        results: List[BackupMetadata] = []
        for path in file_paths:
            p = Path(path)
            if p.is_file():
                meta = self.create_backup(p, custom_timestamp=custom_timestamp)
                results.append(meta)
        return results

    def backup_directory(
        self,
        directory_path: Union[str, Path],
        recursive: bool = True,
        custom_timestamp: Optional[Union[str, datetime]] = None,
    ) -> List[BackupMetadata]:
        """Back up all files in a configured critical directory.

        Args:
            directory_path: Directory path to scan and back up.
            recursive: Whether to scan subdirectories.
            custom_timestamp: Optional batch timestamp.

        Returns:
            List of created BackupMetadata records.
        """
        dir_path = Path(directory_path).resolve()
        if not dir_path.is_dir():
            raise NotADirectoryError(f"Directory not found: {dir_path}")

        files_to_backup: List[Path] = []
        pattern = "**/*" if recursive else "*"
        for item in dir_path.glob(pattern):
            if item.is_file():
                files_to_backup.append(item)

        return self.backup_files(files_to_backup, custom_timestamp=custom_timestamp)
