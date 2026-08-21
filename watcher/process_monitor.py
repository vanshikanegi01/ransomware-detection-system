"""
Process Telemetry Monitor for Windows Watchdog Agent (Member 1).

Collects passive, defensive process telemetry using `psutil`.
Gathers process metrics (PID, name, executable path, CPU %, Memory %) safely
without performing any invasive, destructive, or process-terminating actions.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure project root is in sys.path when executed directly or imported in isolation
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from watcher.models import ProcessTelemetry

logger = logging.getLogger("watcher.process_monitor")

try:
    import psutil

    PSUTIL_AVAILABLE = True
except ImportError:  # pragma: no cover
    PSUTIL_AVAILABLE = False
    psutil = None


class ProcessMonitor:
    """
    Defensive Process Telemetry Collector.
    
    Reads passive metrics for running processes on the system.
    Strictly read-only; does not terminate, inject, or modify running processes.
    """

    def __init__(self) -> None:
        self.is_psutil_available = PSUTIL_AVAILABLE

    def get_process_telemetry(self, pid: int) -> Optional[ProcessTelemetry]:
        """
        Safely fetch defensive telemetry for a specific process ID.

        Args:
            pid: The Process Identifier (PID) to inspect.

        Returns:
            ProcessTelemetry object if process exists, otherwise None.
        """
        if not self.is_psutil_available or psutil is None:
            return ProcessTelemetry(pid=pid, name="unknown_no_psutil")

        try:
            proc = psutil.Process(pid)
            
            # Safe defensive telemetry extraction
            name = "unknown"
            try:
                name = proc.name()
            except (psutil.AccessDenied, psutil.NoSuchProcess, Exception):
                pass

            exe_path: Optional[str] = None
            try:
                exe_path = proc.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess, Exception):
                # Executable path may be protected by OS security; fail safely
                exe_path = None

            cpu_percent = 0.0
            try:
                # interval=None returns instantaneous/cached CPU without blocking
                cpu_percent = float(proc.cpu_percent(interval=None))
            except (psutil.AccessDenied, psutil.NoSuchProcess, Exception):
                pass

            memory_percent = 0.0
            memory_rss = None
            try:
                memory_percent = float(proc.memory_percent())
                mem_info = proc.memory_info()
                memory_rss = int(mem_info.rss)
            except (psutil.AccessDenied, psutil.NoSuchProcess, Exception):
                pass

            status_str: Optional[str] = None
            try:
                status_str = str(proc.status())
            except (psutil.AccessDenied, psutil.NoSuchProcess, Exception):
                pass

            return ProcessTelemetry(
                pid=pid,
                name=name,
                exe_path=exe_path,
                cpu_percent=cpu_percent,
                memory_percent=memory_percent,
                memory_rss_bytes=memory_rss,
                status=status_str,
            )

        except psutil.NoSuchProcess:
            return None
        except Exception as e:
            logger.debug("Non-fatal error reading PID %d: %s", pid, e)
            return None

    def get_current_process_telemetry(self) -> ProcessTelemetry:
        """Fetch defensive telemetry for the current running process."""
        current_pid = os.getpid()
        telemetry = self.get_process_telemetry(current_pid)
        if telemetry is None:
            return ProcessTelemetry(pid=current_pid, name="python")
        return telemetry

    def get_top_active_processes(self, limit: int = 5, sort_by: str = "cpu") -> List[ProcessTelemetry]:
        """
        Sample the most resource-active processes for threat context correlation.

        Args:
            limit: Maximum number of process records to return.
            sort_by: Metric to sort by ('cpu' or 'memory').

        Returns:
            List of ProcessTelemetry objects sorted descending.
        """
        if not self.is_psutil_available or psutil is None:
            return []

        results: List[ProcessTelemetry] = []
        attrs = ["pid", "name", "exe", "cpu_percent", "memory_percent", "memory_info", "status"]

        try:
            for p in psutil.process_iter(attrs=attrs):
                try:
                    p_info = p.info
                    pid = p_info.get("pid", 0)
                    name = p_info.get("name") or "unknown"
                    exe = p_info.get("exe")
                    cpu = float(p_info.get("cpu_percent") or 0.0)
                    mem = float(p_info.get("memory_percent") or 0.0)
                    mem_info = p_info.get("memory_info")
                    rss = mem_info.rss if mem_info else None
                    status = str(p_info.get("status")) if p_info.get("status") else None

                    results.append(
                        ProcessTelemetry(
                            pid=pid,
                            name=name,
                            exe_path=exe,
                            cpu_percent=cpu,
                            memory_percent=mem,
                            memory_rss_bytes=rss,
                            status=status,
                        )
                    )
                except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
                    continue
        except Exception as e:
            logger.debug("Non-fatal error iterating processes: %s", e)

        # Sort by specified metric
        if sort_by.lower() == "memory":
            results.sort(key=lambda x: x.memory_percent, reverse=True)
        else:
            results.sort(key=lambda x: x.cpu_percent, reverse=True)

        return results[:limit]

    def snapshot_all_processes(self) -> Dict[int, ProcessTelemetry]:
        """
        Capture a full system process snapshot.

        Returns:
            Dictionary mapping PID to ProcessTelemetry.
        """
        if not self.is_psutil_available or psutil is None:
            return {}

        snapshot: Dict[int, ProcessTelemetry] = {}
        for proc_telemetry in self.get_top_active_processes(limit=1000):
            snapshot[proc_telemetry.pid] = proc_telemetry
        return snapshot
