"""File restoration engine with pre-restore and post-restore cryptographic verification.

Member 3: Recovery Engineer
TRINETRA: Bharat's Next-Generation Cyber Resilience Platform
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Tuple, Union

from vaultkeeper.encryption import DecryptionIntegrityError, decrypt_bytes
from vaultkeeper.integrity import calculate_bytes_sha256, calculate_sha256
from vaultkeeper.metadata import MetadataStore
from vaultkeeper.models import BackupMetadata, BackupStatus


class RestoreEngine:
    """Restores files with dual-stage SHA-256 and AES-256-GCM integrity validation."""

    def __init__(
        self,
        encryption_key: Optional[bytes] = None,
        metadata_store: Optional[MetadataStore] = None,
    ) -> None:
        """Initialize RestoreEngine.

        Args:
            encryption_key: 32-byte AES-256 key for decrypting vault files.
            metadata_store: Optional metadata store to update status on corrupted candidates.
        """
        self.encryption_key = encryption_key
        self.metadata_store = metadata_store

    def verify_candidate_integrity(
        self, candidate: BackupMetadata
    ) -> Tuple[bool, Optional[bytes], Optional[str]]:
        """Verify the integrity of a backup candidate BEFORE attempting restoration.

        Step 1: Check vault file existence.
        Step 2: Authenticate & decrypt AES-256-GCM ciphertext payload (if encrypted).
        Step 3: Calculate SHA-256 of extracted plaintext.
        Step 4: Verify plaintext hash matches the recorded candidate.sha256_hash.

        Args:
            candidate: BackupMetadata record of the snapshot candidate.

        Returns:
            Tuple of (is_valid, plaintext_bytes, error_message).
        """
        vault_path = Path(candidate.vault_path)
        if not vault_path.is_file():
            return False, None, f"Vault storage file not found at: {vault_path}"

        try:
            raw_vault_data = vault_path.read_bytes()
            if candidate.is_encrypted:
                if not self.encryption_key:
                    return (
                        False,
                        None,
                        "Candidate backup is AES-256 encrypted, but no decryption key was supplied.",
                    )
                plaintext = decrypt_bytes(raw_vault_data, self.encryption_key)
            else:
                plaintext = raw_vault_data

            # Calculate SHA-256 of decrypted candidate content
            candidate_hash = calculate_bytes_sha256(plaintext)
            expected_hash = candidate.sha256_hash.strip().lower()

            if candidate_hash != expected_hash:
                return (
                    False,
                    None,
                    f"Candidate SHA-256 mismatch (Expected: {expected_hash}, Actual: {candidate_hash})",
                )

            return True, plaintext, None

        except DecryptionIntegrityError as e:
            return (
                False,
                None,
                f"Candidate decryption failed (tampered ciphertext or invalid key): {e}",
            )
        except Exception as e:
            return False, None, f"Candidate verification error: {str(e)}"

    def restore_candidate(
        self,
        candidate: BackupMetadata,
        destination_path: Optional[Union[str, Path]] = None,
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """Safely restore a candidate version to disk with dual-stage verification.

        Rule: "Never claim success without post-restore integrity verification."

        Args:
            candidate: BackupMetadata record to restore.
            destination_path: Path where file should be restored (defaults to candidate.source_path).

        Returns:
            Tuple of (success_bool, restored_sha256, error_message).
        """
        target_path = Path(destination_path if destination_path else candidate.source_path).resolve()

        # Step 1: Pre-restore candidate verification
        is_valid, plaintext, err = self.verify_candidate_integrity(candidate)
        if not is_valid or plaintext is None:
            if self.metadata_store:
                self.metadata_store.update_backup_status(
                    candidate.version_id, BackupStatus.CORRUPTED
                )
            return False, None, f"Pre-restore candidate verification failed: {err}"

        # Step 2: Write plaintext to target destination
        try:
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.write_bytes(plaintext)
        except Exception as e:
            return False, None, f"Failed writing restored file to {target_path}: {str(e)}"

        # Step 3: Post-restore verification on disk
        try:
            restored_hash = calculate_sha256(target_path)
            expected_hash = candidate.sha256_hash.strip().lower()

            if restored_hash != expected_hash:
                # Post-restore integrity failed! Remove corrupted file from disk
                try:
                    if target_path.exists():
                        target_path.unlink()
                except Exception:
                    pass
                return (
                    False,
                    restored_hash,
                    f"Post-restore hash verification failed (Expected {expected_hash}, got {restored_hash}).",
                )

            return True, restored_hash, None

        except Exception as e:
            return False, None, f"Post-restore verification error: {str(e)}"
