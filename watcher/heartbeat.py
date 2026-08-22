"""
Heartbeat Telemetry Monitor for Windows Watchdog Agent (Member 1).

Periodically emits structured defensive health and liveness telemetry (HeartbeatData)
on a dedicated non-blocking daemon thread. Provides health status, uptime tracking,
event throughput metrics, and local resource metrics to downstream receivers.
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

# Ensure project root is in sys.path when executed directly or imported in isolation
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from watcher.models import HeartbeatData, ProcessTelemetry
from watcher.process_monitor import ProcessMonitor

logger = logging.getLogger("watcher.heartbeat")


class HeartbeatMonitor:
    """
    Periodic Heartbeat Telemetry Monitor.
    
    Runs a non-blocking background loop emitting `HeartbeatData` at a configurable
    interval. Gracefully starts and stops with the Watchdog Agent.
    """

    def __init__(
        self,
        interval: float = 30.0,
        callback: Optional[Callable[[HeartbeatData], None]] = None,
        get_status_fn: Optional[Callable[[], Dict[str, Any]]] = None,
        process_monitor: Optional[ProcessMonitor] = None,
        watch_dir: Optional[str | Path] = None,
    ) -> None:
        """
        Initialize the HeartbeatMonitor.

        Args:
            interval: Periodic emission interval in seconds (default: 30.0s).
            callback: Function invoked whenever a HeartbeatData event is generated.
            get_status_fn: Optional callable returning a dictionary with dynamic agent metrics:
                           (e.g., {'uptime_seconds': ..., 'events_processed': ..., 'status': ...}).
            process_monitor: ProcessMonitor instance for gathering host resource metrics.
            watch_dir: Monitored target directory path string.
        """
        if interval <= 0:
            raise ValueError(f"Heartbeat interval must be greater than 0, got {interval}")

        self.interval = float(interval)
        self.callback = callback or (lambda hb: None)
        self.get_status_fn = get_status_fn
        self.process_monitor = process_monitor or ProcessMonitor()
        self.watch_dir = str(Path(watch_dir).resolve()) if watch_dir else ""

        self._start_time: Optional[float] = None
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._is_running = False

    def set_callback(self, callback: Callable[[HeartbeatData], None]) -> None:
        """Update or register the heartbeat callback."""
        self.callback = callback

    def _collect_current_heartbeat(self) -> HeartbeatData:
        """
        Gather current agent metrics and generate a HeartbeatData snapshot.
        """
        uptime = (time.time() - self._start_time) if self._start_time else 0.0
        events_count = 0
        agent_status = "active"
        extra_meta: Dict[str, Any] = {}

        if self.get_status_fn:
            try:
                dyn = self.get_status_fn()
                if isinstance(dyn, dict):
                    uptime = float(dyn.get("uptime_seconds", uptime))
                    events_count = int(dyn.get("events_processed", 0))
                    agent_status = str(dyn.get("status", agent_status))
                    extra_meta = dyn.get("metadata", {})
            except Exception as e:
                logger.debug("Non-fatal error querying get_status_fn: %s", e)

        # Get passive process telemetry for the current agent process
        proc_telemetry: Optional[ProcessTelemetry] = None
        try:
            if self.process_monitor.is_psutil_available:
                proc_telemetry = self.process_monitor.get_current_process_telemetry()
        except Exception as e:
            logger.debug("Non-fatal error reading process telemetry for heartbeat: %s", e)

        return HeartbeatData(
            status=agent_status,
            pid=os.getpid(),
            uptime_seconds=round(uptime, 2),
            events_processed=events_count,
            watch_dir=self.watch_dir,
            process_telemetry=proc_telemetry,
            metadata=extra_meta,
        )

    def emit_heartbeat(self) -> HeartbeatData:
        """
        Generate, dispatch, and return a single HeartbeatData instance immediately.
        """
        hb = self._collect_current_heartbeat()
        try:
            self.callback(hb)
        except Exception as e:
            logger.error("Error in heartbeat callback: %s", e, exc_info=True)
        return hb

    def _run_loop(self) -> None:
        """Background worker loop executing periodic heartbeat emissions."""
        logger.debug("HeartbeatMonitor thread started with interval=%.2fs", self.interval)
        while not self._stop_event.is_set():
            # Wait for interval or immediate wake-up if stop_event is signaled
            if self._stop_event.wait(timeout=self.interval):
                break
            if not self._stop_event.is_set():
                self.emit_heartbeat()
        logger.debug("HeartbeatMonitor thread exiting.")

    def start(self) -> None:
        """Start the periodic heartbeat monitor on a background daemon thread."""
        with self._lock:
            if self._is_running:
                logger.warning("HeartbeatMonitor is already running.")
                return

            self._start_time = time.time()
            self._stop_event.clear()
            self._is_running = True

            self._thread = threading.Thread(
                target=self._run_loop,
                daemon=True,
                name="WatchdogHeartbeatThread",
            )
            self._thread.start()
            logger.info("HeartbeatMonitor started (interval=%.1fs)", self.interval)

    def stop(self) -> None:
        """Stop the heartbeat monitor gracefully."""
        with self._lock:
            if not self._is_running:
                return

            logger.info("Stopping HeartbeatMonitor...")
            self._stop_event.set()
            if self._thread and self._thread.is_alive():
                self._thread.join(timeout=2.0)
            self._thread = None
            self._is_running = False
            logger.info("HeartbeatMonitor stopped.")

    def is_alive(self) -> bool:
        """Check if the heartbeat monitor is running and healthy."""
        with self._lock:
            return self._is_running and (self._thread.is_alive() if self._thread else False)

    def __enter__(self) -> HeartbeatMonitor:
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()
