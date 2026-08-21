"""
TRINETRA - Member 1: Windows Watchdog Agent Package.

Provides real-time defensive file system event monitoring and safe local
process telemetry collection for ransomware and anomaly detection pipelines.
"""

from watcher.file_monitor import FileMonitor
from watcher.models import EventData, EventType, ProcessTelemetry
from watcher.process_monitor import ProcessMonitor
from watcher.watcher import WatchdogAgent

__version__ = "1.0.0"

__all__ = [
    "WatchdogAgent",
    "FileMonitor",
    "ProcessMonitor",
    "EventData",
    "ProcessTelemetry",
    "EventType",
]
