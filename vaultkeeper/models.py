"""Data models and schemas for the Vaultkeeper module.

Member 3: Recovery Engineer
TRINETRA: Bharat's Next-Generation Cyber Resilience Platform
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class RecoveryState(str, Enum):
    """Lifecycle states of the recovery state machine."""

    IDLE = "IDLE"
    RECEIVED = "RECEIVED"
    ANALYZING = "ANALYZING"
    VERIFYING = "VERIFYING"
    RESTORING = "RESTORING"
    POST_VERIFY = "POST_VERIFY"
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class FileRecoveryStatus(str, Enum):
    """Recovery status of an individual file."""

    RECOVERED = "RECOVERED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class BackupStatus(str, Enum):
    """Integrity and validity status of a stored backup version."""

    VERIFIED_CLEAN = "VERIFIED_CLEAN"
    CORRUPTED = "CORRUPTED"
    UNVERIFIED = "UNVERIFIED"


@dataclass
class BackupMetadata:
    """Metadata describing a single protected recovery copy / version."""

    version_id: str
    source_path: str
    vault_path: str
    timestamp: str  # ISO-8601 formatted timestamp, e.g. "2026-08-18T17:30:00"
    file_size: int
    sha256_hash: str
    version_number: int
    status: str = BackupStatus.VERIFIED_CLEAN.value
    is_encrypted: bool = True
    encryption_algorithm: str = "AES-256-GCM"

    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary representation."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> BackupMetadata:
        """Create BackupMetadata instance from dictionary."""
        return cls(
            version_id=str(data["version_id"]),
            source_path=str(data["source_path"]),
            vault_path=str(data["vault_path"]),
            timestamp=str(data["timestamp"]),
            file_size=int(data["file_size"]),
            sha256_hash=str(data["sha256_hash"]),
            version_number=int(data["version_number"]),
            status=str(data.get("status", BackupStatus.VERIFIED_CLEAN.value)),
            is_encrypted=bool(data.get("is_encrypted", True)),
            encryption_algorithm=str(data.get("encryption_algorithm", "AES-256-GCM")),
        )


@dataclass
class IncidentEvent:
    """Trigger event received from the Policy Engine (Member 4) upon attack confirmation."""

    incident_id: str
    timestamp: str  # Attack onset boundary timestamp (ISO-8601)
    event: str = "RANSOMWARE_CONFIRMED"
    risk_score: float = 0.0
    affected_files: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary representation."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> IncidentEvent:
        """Create IncidentEvent instance from dictionary."""
        return cls(
            incident_id=str(data.get("incident_id", "UNKNOWN_INCIDENT")),
            timestamp=str(data["timestamp"]),
            event=str(data.get("event", "RANSOMWARE_CONFIRMED")),
            risk_score=float(data.get("risk_score", 0.0)),
            affected_files=[str(p) for p in data.get("affected_files", [])],
        )


@dataclass
class FileRecoveryResult:
    """Per-file recovery outcome tracking."""

    path: str
    status: str  # "RECOVERED" or "FAILED"
    version_used: Optional[str] = None
    error_message: Optional[str] = None
    original_sha256: Optional[str] = None
    restored_sha256: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary representation."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> FileRecoveryResult:
        """Create FileRecoveryResult instance from dictionary."""
        return cls(
            path=str(data["path"]),
            status=str(data["status"]),
            version_used=data.get("version_used"),
            error_message=data.get("error_message"),
            original_sha256=data.get("original_sha256"),
            restored_sha256=data.get("restored_sha256"),
        )


@dataclass
class RecoveryProgressEvent:
    """Progress event emitted during recovery for UI/Backend updates."""

    incident_id: str
    event: str  # e.g., "recovery_started", "candidate_found", "file_recovered", etc.
    path: Optional[str] = None
    completed: int = 0
    total: int = 0
    message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary representation."""
        return asdict(self)


@dataclass
class RecoveryReport:
    """Comprehensive post-incident recovery summary for Business Recovery Report."""

    incident_id: str
    recovery_started: str
    recovery_completed: str
    files_at_risk: int
    files_encrypted: int
    files_recovered: int
    files_lost: int
    integrity_failures: int
    recovery_status: str  # "COMPLETE", "PARTIAL", "FAILED"
    files: List[FileRecoveryResult] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary representation."""
        res = asdict(self)
        res["files"] = [f.to_dict() if isinstance(f, FileRecoveryResult) else f for f in self.files]
        return res

    def to_json(self, indent: int = 2) -> str:
        """Serialize report to formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RecoveryReport:
        """Create RecoveryReport from dictionary."""
        files = [
            FileRecoveryResult.from_dict(f) if isinstance(f, dict) else f
            for f in data.get("files", [])
        ]
        return cls(
            incident_id=str(data["incident_id"]),
            recovery_started=str(data["recovery_started"]),
            recovery_completed=str(data["recovery_completed"]),
            files_at_risk=int(data["files_at_risk"]),
            files_encrypted=int(data["files_encrypted"]),
            files_recovered=int(data["files_recovered"]),
            files_lost=int(data["files_lost"]),
            integrity_failures=int(data["integrity_failures"]),
            recovery_status=str(data["recovery_status"]),
            files=files,
        )
