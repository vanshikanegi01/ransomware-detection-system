"""Version management, snapshot querying, and attack-boundary filtering engine.

Member 3: Recovery Engineer
TRINETRA: Bharat's Next-Generation Cyber Resilience Platform
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Union

from vaultkeeper.metadata import MetadataStore, normalize_path
from vaultkeeper.models import BackupMetadata, BackupStatus


def parse_iso_timestamp(ts_str: str) -> datetime:
    """Safely parse an ISO-8601 timestamp into a timezone-aware datetime object."""
    # Normalize common variations
    clean_str = ts_str.strip()
    try:
        dt = datetime.fromisoformat(clean_str)
    except ValueError:
        # Fallback format handling (e.g. YYYY-MM-DD HH:MM:SS)
        clean_str_iso = clean_str.replace(" ", "T")
        dt = datetime.fromisoformat(clean_str_iso)

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class VersioningEngine:
    """Manages historical file versions and applies the attack time boundary."""

    def __init__(self, metadata_store: MetadataStore) -> None:
        """Initialize VersioningEngine with a metadata persistence store.

        Args:
            metadata_store: MetadataStore implementation instance.
        """
        self.metadata_store = metadata_store

    def list_versions(self, source_path: Union[str, Path]) -> List[BackupMetadata]:
        """List all available backup versions for a given source path.

        Args:
            source_path: Path to the target file.

        Returns:
            List of BackupMetadata records ordered from oldest (v1) to newest (vN).
        """
        return self.metadata_store.get_versions_for_file(source_path)

    def get_candidate_versions_before_boundary(
        self,
        source_path: Union[str, Path],
        attack_timestamp: Union[str, datetime],
    ) -> List[BackupMetadata]:
        """Retrieve backup candidates created strictly BEFORE the attack timestamp.

        The attack timestamp represents the trusted onset boundary of the ransomware.
        Any snapshot taken at or after this boundary is considered potentially compromised
        and is excluded.

        Candidates are returned sorted from NEWEST to OLDEST (most recent safe point first).

        Args:
            source_path: Path of the affected file.
            attack_timestamp: ISO-8601 string or datetime representing attack boundary.

        Returns:
            List of candidate BackupMetadata records sorted newest -> oldest.
        """
        if isinstance(attack_timestamp, datetime):
            boundary_dt = (
                attack_timestamp
                if attack_timestamp.tzinfo is not None
                else attack_timestamp.replace(tzinfo=timezone.utc)
            )
        else:
            boundary_dt = parse_iso_timestamp(attack_timestamp)

        all_versions = self.list_versions(source_path)
        valid_candidates: List[BackupMetadata] = []

        for ver in all_versions:
            # Check status is not permanently marked corrupted
            if ver.status == BackupStatus.CORRUPTED.value:
                continue

            ver_dt = parse_iso_timestamp(ver.timestamp)

            # Strict rule: backup_timestamp < attack_timestamp
            if ver_dt < boundary_dt:
                valid_candidates.append(ver)

        # Sort candidate versions from newest to oldest
        valid_candidates.sort(
            key=lambda x: (parse_iso_timestamp(x.timestamp), x.version_number),
            reverse=True,
        )

        return valid_candidates
