"""
TRINETRA - Member 1: Windows Watchdog Agent Package.

Provides real-time defensive file system event monitoring and safe local
process telemetry collection for ransomware and anomaly detection pipelines.
"""

from watcher.canary_monitor import CanaryMonitor
from watcher.file_monitor import FileMonitor
from watcher.heartbeat import HeartbeatMonitor
from watcher.models import EventData, EventType, HeartbeatData, ProcessTelemetry
from watcher.process_monitor import ProcessMonitor
from watcher.service import ServiceConfig, ServiceState, WatchdogService
from watcher.watcher import WatchdogAgent

__version__ = "1.0.0"

__all__ = [
    "WatchdogAgent",
    "WatchdogService",
    "ServiceState",
    "ServiceConfig",
    "FileMonitor",
    "ProcessMonitor",
    "CanaryMonitor",
    "HeartbeatMonitor",
    "EventData",
    "HeartbeatData",
    "ProcessTelemetry",
    "EventType",
]



