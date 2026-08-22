"""
Windows Background Service for TRINETRA Watchdog Agent (Member 1).

Provides a production-grade, testable Windows Background Service architecture
with clean start/stop lifecycle management, non-admin test abstractions,
and full coordination of FileMonitor, CanaryMonitor, and HeartbeatMonitor.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

# Ensure project root is in sys.path when executed directly or imported in isolation
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from watcher.models import EventData, HeartbeatData
from watcher.watcher import WatchdogAgent

logger = logging.getLogger("watcher.service")

# Optional import of win32service modules for native Windows Service Manager integration
try:
    import win32event
    import win32service
    import win32serviceutil

    PYWIN32_AVAILABLE = True
except ImportError:  # pragma: no cover
    PYWIN32_AVAILABLE = False
    win32serviceutil = None
    win32service = None
    win32event = None


class ServiceState(str, Enum):
    """Lifecycle states for the Windows Watchdog Service."""
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    ERROR = "error"


@dataclass
class ServiceConfig:
    """
    Configuration parameters for the Windows Watchdog Service.
    
    Attributes:
        service_name: Windows internal service identifier name.
        display_name: User-facing service display name in Windows Services Manager.
        description: Description string registered with Windows Service Control Manager.
        watch_dir: Path to directory monitored by the Watchdog Agent.
        recursive: Whether subdirectories are monitored recursively.
        enable_canary: Whether honeypot/canary decoy tripwires are enabled.
        enable_heartbeat: Whether periodic liveness heartbeats are emitted.
        heartbeat_interval: Interval in seconds between heartbeat emissions.
        correlate_processes: Whether process telemetry is correlated with events.
        log_file: Optional log file path for service event logging.
    """
    service_name: str = "TrinetraWatchdog"
    display_name: str = "TRINETRA Ransomware Watchdog Agent"
    description: str = "TRINETRA Cyber Resilience Platform - Passive Watchdog & Canary Monitor"
    watch_dir: str = "./disposable_test_sandbox"
    recursive: bool = True
    enable_canary: bool = True
    enable_heartbeat: bool = True
    heartbeat_interval: float = 30.0
    correlate_processes: bool = True
    log_file: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert ServiceConfig to dictionary."""
        return asdict(self)

    def to_json(self, indent: Optional[int] = None) -> str:
        """Serialize ServiceConfig to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ServiceConfig:
        """Reconstruct ServiceConfig from dictionary."""
        return cls(
            service_name=str(data.get("service_name", "TrinetraWatchdog")),
            display_name=str(data.get("display_name", "TRINETRA Ransomware Watchdog Agent")),
            description=str(data.get("description", "")),
            watch_dir=str(data.get("watch_dir", "./disposable_test_sandbox")),
            recursive=bool(data.get("recursive", True)),
            enable_canary=bool(data.get("enable_canary", True)),
            enable_heartbeat=bool(data.get("enable_heartbeat", True)),
            heartbeat_interval=float(data.get("heartbeat_interval", 30.0)),
            correlate_processes=bool(data.get("correlate_processes", True)),
            log_file=data.get("log_file"),
        )


class WatchdogService:
    """
    Core Testable Windows Service Host for the Watchdog Agent.
    
    Decoupled from native OS service handles so that unit and integration tests
    can run safely without requiring Windows Administrator privileges.
    """

    def __init__(
        self,
        config: Optional[ServiceConfig] = None,
        agent: Optional[WatchdogAgent] = None,
        status_callbacks: Optional[List[Callable[[ServiceState], None]]] = None,
    ) -> None:
        """
        Initialize the WatchdogService.

        Args:
            config: Service configuration options.
            agent: Optional pre-configured WatchdogAgent instance.
            status_callbacks: Callbacks receiving service state changes.
        """
        self.config = config or ServiceConfig()
        self.state = ServiceState.STOPPED
        self._agent: Optional[WatchdogAgent] = agent
        self._stop_event = threading.Event()
        self._supervisor_thread: Optional[threading.Thread] = None
        self._status_callbacks: List[Callable[[ServiceState], None]] = list(status_callbacks or [])
        self._lock = threading.Lock()

    @property
    def agent(self) -> Optional[WatchdogAgent]:
        """Return the underlying WatchdogAgent instance."""
        return self._agent

    def add_status_callback(self, callback: Callable[[ServiceState], None]) -> None:
        """Register a callback for service state transitions."""
        if callback not in self._status_callbacks:
            self._status_callbacks.append(callback)

    def remove_status_callback(self, callback: Callable[[ServiceState], None]) -> None:
        """Unregister a service state callback."""
        if callback in self._status_callbacks:
            self._status_callbacks.remove(callback)

    def _set_state(self, new_state: ServiceState) -> None:
        """Update service state and notify registered listeners."""
        self.state = new_state
        logger.info("WatchdogService state changed to: %s", new_state.value.upper())
        for cb in self._status_callbacks:
            try:
                cb(new_state)
            except Exception as e:
                logger.error("Error in service status callback: %s", e, exc_info=True)

    def start(self, async_mode: bool = True) -> None:
        """
        Start the Watchdog Service and all underlying monitoring engines.

        Args:
            async_mode: If True, runs supervisor in background thread. If False, blocks.
        """
        with self._lock:
            if self.state in (ServiceState.RUNNING, ServiceState.STARTING):
                logger.warning("WatchdogService is already active or starting.")
                return

            self._set_state(ServiceState.STARTING)
            self._stop_event.clear()

            # Initialize WatchdogAgent if not provided
            if self._agent is None:
                self._agent = WatchdogAgent(
                    watch_dir=self.config.watch_dir,
                    recursive=self.config.recursive,
                    correlate_processes=self.config.correlate_processes,
                    enable_canary=self.config.enable_canary,
                    enable_heartbeat=self.config.enable_heartbeat,
                    heartbeat_interval=self.config.heartbeat_interval,
                )

            try:
                # Start agent (which starts FileMonitor, CanaryMonitor, HeartbeatMonitor)
                self._agent.start()
                self._set_state(ServiceState.RUNNING)
            except Exception as e:
                logger.error("Failed to start WatchdogAgent within service: %s", e, exc_info=True)
                self._set_state(ServiceState.ERROR)
                raise

            if async_mode:
                self._supervisor_thread = threading.Thread(
                    target=self._run_supervisor_loop,
                    daemon=True,
                    name="WatchdogServiceSupervisor",
                )
                self._supervisor_thread.start()

    def _run_supervisor_loop(self) -> None:
        """Internal background supervisor loop waiting on service shutdown signal."""
        logger.debug("WatchdogService supervisor thread running.")
        self._stop_event.wait()
        logger.debug("WatchdogService supervisor thread completed.")

    def run_blocking(self) -> None:
        """Run the service synchronously in the foreground until stopped."""
        self.start(async_mode=False)
        try:
            while not self._stop_event.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            logger.info("KeyboardInterrupt received in service foreground run.")
        finally:
            self.stop()

    def stop(self) -> None:
        """Gracefully stop the Watchdog Service and all child monitoring components."""
        with self._lock:
            if self.state in (ServiceState.STOPPED, ServiceState.STOPPING):
                return

            self._set_state(ServiceState.STOPPING)
            self._stop_event.set()

            if self._agent is not None:
                try:
                    self._agent.stop()
                except Exception as e:
                    logger.error("Error stopping WatchdogAgent: %s", e)

            if self._supervisor_thread and self._supervisor_thread.is_alive():
                self._supervisor_thread.join(timeout=2.0)
            self._supervisor_thread = None

            self._set_state(ServiceState.STOPPED)

    def is_running(self) -> bool:
        """Check if the service and its agent are actively running."""
        with self._lock:
            if self.state != ServiceState.RUNNING:
                return False
            return self._agent.is_alive() if self._agent else False

    def get_service_status(self) -> Dict[str, Any]:
        """
        Query comprehensive service operational health snapshot.
        """
        uptime = self._agent.get_uptime() if self._agent else 0.0
        events_count = self._agent._events_processed_count if self._agent else 0
        return {
            "service_name": self.config.service_name,
            "display_name": self.config.display_name,
            "state": self.state.value,
            "pid": os.getpid(),
            "uptime_seconds": round(uptime, 2),
            "events_processed": events_count,
            "watch_dir": str(Path(self.config.watch_dir).resolve()),
            "canary_enabled": self.config.enable_canary,
            "heartbeat_enabled": self.config.enable_heartbeat,
            "pywin32_available": PYWIN32_AVAILABLE,
        }

    def __enter__(self) -> WatchdogService:
        self.start(async_mode=True)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()


# ---------------------------------------------------------------------------
# Native Windows Service Integration (Subclasses win32serviceutil if available)
# ---------------------------------------------------------------------------

if PYWIN32_AVAILABLE and win32serviceutil is not None:

    class WindowsWatchdogService(win32serviceutil.ServiceFramework):
        """
        Native Windows Service wrapper for TRINETRA Watchdog Agent.
        Binds Windows Service Control Manager (SCM) signals to WatchdogService.
        """

        _svc_name_ = "TrinetraWatchdog"
        _svc_display_name_ = "TRINETRA Ransomware Watchdog Agent"
        _svc_description_ = "TRINETRA Cyber Resilience Platform - Passive Watchdog & Canary Monitor"

        def __init__(self, args: Any) -> None:
            super().__init__(args)
            self.stop_event = win32event.CreateEvent(None, 0, 0, None)
            self.service = WatchdogService(
                config=ServiceConfig(
                    service_name=self._svc_name_,
                    display_name=self._svc_display_name_,
                    description=self._svc_description_,
                )
            )

        def SvcStop(self) -> None:
            """Handler for Windows Service Control Manager STOP request."""
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self.service.stop()
            win32event.SetEvent(self.stop_event)

        def SvcDoRun(self) -> None:
            """Main Windows Service execution entry point."""
            self.service.start(async_mode=True)
            win32event.WaitForSingleObject(self.stop_event, win32event.INFINITE)
            self.service.stop()

else:

    class WindowsWatchdogService:  # type: ignore
        """Fallback mock wrapper when pywin32 is not installed."""
        _svc_name_ = "TrinetraWatchdog"
        _svc_display_name_ = "TRINETRA Ransomware Watchdog Agent"
        _svc_description_ = "TRINETRA Cyber Resilience Platform - Passive Watchdog & Canary Monitor"

        def __init__(self, args: Any = None) -> None:
            self.service = WatchdogService()


def main() -> None:
    """CLI entrypoint for managing and running the Watchdog Windows Service."""
    parser = argparse.ArgumentParser(
        description="TRINETRA Member 1: Windows Watchdog Service Manager",
    )
    parser.add_argument(
        "--run-standalone",
        action="store_true",
        help="Run the service in standalone foreground mode (non-admin safe)",
    )
    parser.add_argument(
        "--watch-dir",
        type=str,
        default="./disposable_test_sandbox",
        help="Directory to monitor (default: ./disposable_test_sandbox)",
    )
    parser.add_argument(
        "--heartbeat-interval",
        type=float,
        default=10.0,
        help="Heartbeat emission interval in seconds (default: 10.0s)",
    )

    args, unknown = parser.parse_known_args()

    if args.run_standalone or not PYWIN32_AVAILABLE:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] (WatchdogService) %(message)s",
        )
        print("=" * 75)
        print(f"  TRINETRA — Member 1: Windows Watchdog Service (Standalone Mode)")
        print(f"  Target Watch Directory: {Path(args.watch_dir).resolve()}")
        print("  Press Ctrl+C to stop.")
        print("=" * 75)

        config = ServiceConfig(
            watch_dir=args.watch_dir,
            heartbeat_interval=args.heartbeat_interval,
        )
        service = WatchdogService(config=config)
        service.run_blocking()
    else:
        # Pass control to standard win32serviceutil CLI dispatcher (install, start, stop, etc.)
        win32serviceutil.HandleCommandLine(WindowsWatchdogService)


if __name__ == "__main__":
    main()
