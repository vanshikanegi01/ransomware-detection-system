"""Metadata catalog and persistence layer for Vaultkeeper using SQLite.

Member 3: Recovery Engineer
TRINETRA: Bharat's Next-Generation Cyber Resilience Platform
"""

from __future__ import annotations

import json
import sqlite3
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Callable, List, Optional, TypeVar, Union

from vaultkeeper.models import BackupMetadata, BackupStatus, RecoveryReport

T = TypeVar("T")


def normalize_path(path: Union[str, Path]) -> str:
    """Normalize file paths to absolute POSIX-style string representation."""
    return str(Path(path).resolve().as_posix())


class MetadataStore(ABC):
    """Abstract interface for Vaultkeeper metadata persistence."""

    @abstractmethod
    def add_backup(self, metadata: BackupMetadata) -> None:
        """Insert or update a backup version record."""

    @abstractmethod
    def get_backup(self, version_id: str) -> Optional[BackupMetadata]:
        """Fetch a specific backup record by version ID."""

    @abstractmethod
    def get_versions_for_file(self, source_path: Union[str, Path]) -> List[BackupMetadata]:
        """Fetch all backup versions for a specific source path ordered by version number."""

    @abstractmethod
    def get_all_backups(self) -> List[BackupMetadata]:
        """Fetch all backup records across all files."""

    @abstractmethod
    def update_backup_status(self, version_id: str, status: Union[str, BackupStatus]) -> None:
        """Update the integrity/cleanliness status of a backup."""

    @abstractmethod
    def get_next_version_number(self, source_path: Union[str, Path]) -> int:
        """Calculate the next sequential version number for a file."""

    @abstractmethod
    def save_incident_report(self, report: RecoveryReport) -> None:
        """Persist a post-incident recovery report."""

    @abstractmethod
    def get_incident_report(self, incident_id: str) -> Optional[RecoveryReport]:
        """Retrieve a stored recovery report by incident ID."""

    def close(self) -> None:
        """Close any open database handles."""


class SQLiteMetadataStore(MetadataStore):
    """SQLite implementation of the metadata store with explicit connection lifecycle."""

    def __init__(self, db_path: Union[str, Path] = ":memory:"):
        """Initialize SQLite metadata store.

        Args:
            db_path: Path to SQLite database file, or ':memory:' for in-memory DB.
        """
        self.db_path = str(db_path)
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _with_connection(self, query_fn: Callable[[sqlite3.Connection], T]) -> T:
        """Execute a callable with an auto-closed SQLite connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                return query_fn(conn)
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Create necessary database tables and indexes if they do not exist."""
        def _exec(conn: sqlite3.Connection) -> None:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS backups (
                    version_id TEXT PRIMARY KEY,
                    source_path TEXT NOT NULL,
                    vault_path TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    sha256_hash TEXT NOT NULL,
                    version_number INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    is_encrypted INTEGER NOT NULL,
                    encryption_algorithm TEXT NOT NULL
                )
                """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_backups_source_path 
                ON backups (source_path, version_number)
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS incident_reports (
                    incident_id TEXT PRIMARY KEY,
                    recovery_started TEXT NOT NULL,
                    recovery_completed TEXT NOT NULL,
                    files_at_risk INTEGER NOT NULL,
                    files_encrypted INTEGER NOT NULL,
                    files_recovered INTEGER NOT NULL,
                    files_lost INTEGER NOT NULL,
                    integrity_failures INTEGER NOT NULL,
                    recovery_status TEXT NOT NULL,
                    report_json TEXT NOT NULL
                )
                """
            )

        self._with_connection(_exec)

    def add_backup(self, metadata: BackupMetadata) -> None:
        """Insert or replace a backup metadata record."""
        norm_source = normalize_path(metadata.source_path)
        norm_vault = normalize_path(metadata.vault_path)
        status_val = (
            metadata.status.value
            if isinstance(metadata.status, BackupStatus)
            else str(metadata.status)
        )

        def _exec(conn: sqlite3.Connection) -> None:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO backups (
                    version_id, source_path, vault_path, timestamp,
                    file_size, sha256_hash, version_number, status,
                    is_encrypted, encryption_algorithm
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    metadata.version_id,
                    norm_source,
                    norm_vault,
                    metadata.timestamp,
                    metadata.file_size,
                    metadata.sha256_hash.lower(),
                    metadata.version_number,
                    status_val,
                    1 if metadata.is_encrypted else 0,
                    metadata.encryption_algorithm,
                ),
            )

        self._with_connection(_exec)

    def get_backup(self, version_id: str) -> Optional[BackupMetadata]:
        """Fetch a single backup record by version ID."""
        def _exec(conn: sqlite3.Connection) -> Optional[BackupMetadata]:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM backups WHERE version_id = ?", (version_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_metadata(row)

        return self._with_connection(_exec)

    def get_versions_for_file(self, source_path: Union[str, Path]) -> List[BackupMetadata]:
        """Fetch all backup versions for a source file ordered by version number ascending."""
        norm_source = normalize_path(source_path)

        def _exec(conn: sqlite3.Connection) -> List[BackupMetadata]:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM backups 
                WHERE source_path = ? 
                ORDER BY version_number ASC, timestamp ASC
                """,
                (norm_source,),
            )
            rows = cursor.fetchall()
            return [self._row_to_metadata(r) for r in rows]

        return self._with_connection(_exec)

    def get_all_backups(self) -> List[BackupMetadata]:
        """Fetch all backup records across all files."""
        def _exec(conn: sqlite3.Connection) -> List[BackupMetadata]:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM backups ORDER BY timestamp ASC")
            rows = cursor.fetchall()
            return [self._row_to_metadata(r) for r in rows]

        return self._with_connection(_exec)

    def update_backup_status(self, version_id: str, status: Union[str, BackupStatus]) -> None:
        """Update the status field of a backup."""
        status_val = status.value if isinstance(status, BackupStatus) else str(status)

        def _exec(conn: sqlite3.Connection) -> None:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE backups SET status = ? WHERE version_id = ?",
                (status_val, version_id),
            )

        self._with_connection(_exec)

    def get_next_version_number(self, source_path: Union[str, Path]) -> int:
        """Get the next integer version number for a file (1-indexed)."""
        norm_source = normalize_path(source_path)

        def _exec(conn: sqlite3.Connection) -> int:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT MAX(version_number) FROM backups WHERE source_path = ?",
                (norm_source,),
            )
            res = cursor.fetchone()
            max_num = res[0] if res and res[0] is not None else 0
            return max_num + 1

        return self._with_connection(_exec)

    def save_incident_report(self, report: RecoveryReport) -> None:
        """Store an incident report JSON and indexed columns."""
        def _exec(conn: sqlite3.Connection) -> None:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO incident_reports (
                    incident_id, recovery_started, recovery_completed,
                    files_at_risk, files_encrypted, files_recovered,
                    files_lost, integrity_failures, recovery_status, report_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report.incident_id,
                    report.recovery_started,
                    report.recovery_completed,
                    report.files_at_risk,
                    report.files_encrypted,
                    report.files_recovered,
                    report.files_lost,
                    report.integrity_failures,
                    report.recovery_status,
                    report.to_json(),
                ),
            )

        self._with_connection(_exec)

    def get_incident_report(self, incident_id: str) -> Optional[RecoveryReport]:
        """Fetch stored incident recovery report by incident ID."""
        def _exec(conn: sqlite3.Connection) -> Optional[RecoveryReport]:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT report_json FROM incident_reports WHERE incident_id = ?",
                (incident_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            data = json.loads(row["report_json"])
            return RecoveryReport.from_dict(data)

        return self._with_connection(_exec)

    def close(self) -> None:
        """No persistent connection kept; all connections close per operation."""
        pass

    @staticmethod
    def _row_to_metadata(row: sqlite3.Row) -> BackupMetadata:
        return BackupMetadata(
            version_id=row["version_id"],
            source_path=row["source_path"],
            vault_path=row["vault_path"],
            timestamp=row["timestamp"],
            file_size=row["file_size"],
            sha256_hash=row["sha256_hash"],
            version_number=row["version_number"],
            status=row["status"],
            is_encrypted=bool(row["is_encrypted"]),
            encryption_algorithm=row["encryption_algorithm"],
        )
