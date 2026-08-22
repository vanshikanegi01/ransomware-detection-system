"""
Defensive Telemetry Data Models for Windows Watchdog Agent (Member 1).

Defines structured dataclasses for file system and process telemetry events,
enabling consistent, serialization-ready data models for downstream analysis
(e.g., RiskAnalyser and Policy Engine).
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional


class EventType(str, Enum):
    """Enumeration of supported file system event types."""
    CREATED = "created"
    MODIFIED = "modified"
    DELETED = "deleted"
    MOVED = "moved"
    RENAMED = "renamed"
    HEARTBEAT = "heartbeat"
    UNKNOWN = "unknown"

    @classmethod
    def from_str(cls, value: str) -> EventType:
        """Safely parse string into EventType enum."""
        if not value:
            return cls.UNKNOWN
        val = value.strip().lower()
        for item in cls:
            if item.value == val:
                return item
        return cls.UNKNOWN


@dataclass
class ProcessTelemetry:
    """
    Defensive telemetry snapshot for a local process.
    
    Attributes:
        pid: Process Identifier.
        name: Name of the process executable (e.g., 'notepad.exe').
        exe_path: Full path to the executable file, if accessible.
        cpu_percent: CPU usage percentage snapshot.
        memory_percent: Memory usage percentage snapshot.
        memory_rss_bytes: Resident Set Size memory in bytes (if available).
        status: Current process status (e.g. 'running', 'sleeping').
        timestamp: ISO-8601 UTC timestamp of the measurement.
    """
    pid: int
    name: str = "unknown"
    exe_path: Optional[str] = None
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    memory_rss_bytes: Optional[int] = None
    status: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert ProcessTelemetry dataclass to a plain dictionary."""
        return asdict(self)

    def to_json(self, indent: Optional[int] = None) -> str:
        """Serialize ProcessTelemetry to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ProcessTelemetry:
        """Reconstruct ProcessTelemetry instance from dictionary."""
        return cls(
            pid=int(data.get("pid", 0)),
            name=str(data.get("name", "unknown")),
            exe_path=data.get("exe_path"),
            cpu_percent=float(data.get("cpu_percent", 0.0)),
            memory_percent=float(data.get("memory_percent", 0.0)),
            memory_rss_bytes=data.get("memory_rss_bytes"),
            status=data.get("status"),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
        )


@dataclass
class EventData:
    """
    Unified telemetry schema for file system events.
    
    Attributes:
        event_id: Unique UUID string for event tracking.
        timestamp: ISO-8601 UTC timestamp of event detection.
        event_type: Type of event (created, modified, deleted, moved/renamed).
        file_path: Absolute or canonical path of target file/directory.
        dest_path: Destination path for rename or move operations.
        file_extension: Normalized file extension (e.g., '.docx', '.exe').
        file_size_bytes: File size in bytes (None if deleted or inaccessible).
        is_directory: True if target is a directory, False for files.
        is_canary: True if event involves a monitored canary/honeypot decoy file.
        severity: Event severity level ('normal', 'high', 'critical').
        process_telemetry: Optional snapshot of active/associated process.
        metadata: Extensible key-value store for additional defensive context.
    """
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_type: str = EventType.UNKNOWN.value
    file_path: str = ""
    dest_path: Optional[str] = None
    file_extension: str = ""
    file_size_bytes: Optional[int] = None
    is_directory: bool = False
    is_canary: bool = False
    severity: str = "normal"
    process_telemetry: Optional[ProcessTelemetry] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert EventData to a dictionary with serializable values."""
        res = asdict(self)
        if self.process_telemetry is not None:
            res["process_telemetry"] = self.process_telemetry.to_dict()
        return res

    def to_json(self, indent: Optional[int] = None) -> str:
        """Serialize EventData to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EventData:
        """Reconstruct EventData instance from dictionary."""
        proc_data = data.get("process_telemetry")
        proc_obj = ProcessTelemetry.from_dict(proc_data) if proc_data else None

        return cls(
            event_id=data.get("event_id", str(uuid.uuid4())),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            event_type=data.get("event_type", EventType.UNKNOWN.value),
            file_path=data.get("file_path", ""),
            dest_path=data.get("dest_path"),
            file_extension=data.get("file_extension", ""),
            file_size_bytes=data.get("file_size_bytes"),
            is_directory=bool(data.get("is_directory", False)),
            is_canary=bool(data.get("is_canary", False)),
            severity=str(data.get("severity", "normal")),
            process_telemetry=proc_obj,
            metadata=data.get("metadata", {}),
        )


@dataclass
class HeartbeatData:
    """
    Defensive telemetry heartbeat indicating active operational status of the Watchdog Agent.
    
    Attributes:
        heartbeat_id: Unique UUID string for heartbeat tracking.
        timestamp: ISO-8601 UTC timestamp of heartbeat emission.
        event_type: Identifier for event ("heartbeat").
        status: Current operational status of the agent (e.g., 'active', 'healthy', 'degraded').
        pid: Process Identifier of the running agent.
        uptime_seconds: Total elapsed running time in seconds.
        events_processed: Total number of file telemetry events captured since start.
        watch_dir: Canonical path string of the monitored target directory.
        process_telemetry: Optional local process telemetry (CPU %, RAM %).
        metadata: Extensible key-value store for additional system health context.
    """
    heartbeat_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_type: str = EventType.HEARTBEAT.value
    status: str = "active"
    pid: int = field(default_factory=os.getpid)
    uptime_seconds: float = 0.0
    events_processed: int = 0
    watch_dir: str = ""
    process_telemetry: Optional[ProcessTelemetry] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert HeartbeatData to a dictionary with serializable values."""
        res = asdict(self)
        if self.process_telemetry is not None:
            res["process_telemetry"] = self.process_telemetry.to_dict()
        return res

    def to_json(self, indent: Optional[int] = None) -> str:
        """Serialize HeartbeatData to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> HeartbeatData:
        """Reconstruct HeartbeatData instance from dictionary."""
        proc_data = data.get("process_telemetry")
        proc_obj = ProcessTelemetry.from_dict(proc_data) if proc_data else None

        return cls(
            heartbeat_id=data.get("heartbeat_id", str(uuid.uuid4())),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            event_type=data.get("event_type", EventType.HEARTBEAT.value),
            status=str(data.get("status", "active")),
            pid=int(data.get("pid", os.getpid())),
            uptime_seconds=float(data.get("uptime_seconds", 0.0)),
            events_processed=int(data.get("events_processed", 0)),
            watch_dir=str(data.get("watch_dir", "")),
            process_telemetry=proc_obj,
            metadata=data.get("metadata", {}),
        )


