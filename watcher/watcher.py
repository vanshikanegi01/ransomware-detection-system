"""
Watchdog Agent Coordinator (Member 1 - Windows Watchdog Agent).

Orchestrates file system event monitoring (FileMonitor) and defensive process
telemetry collection (ProcessMonitor). Emits structured EventData telemetry,
manages callback hooks for downstream pipeline integration (e.g., RiskAnalyser,
Policy Engine), and provides formatted logging.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from collections import deque
from pathlib import Path
from typing import Callable, Deque, List, Optional

# Ensure project root is in sys.path when executed directly as a standalone script
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from watcher.canary_monitor import CanaryMonitor
from watcher.file_monitor import FileMonitor
from watcher.heartbeat import HeartbeatMonitor
from watcher.models import EventData, EventType, HeartbeatData, ProcessTelemetry
from watcher.process_monitor import ProcessMonitor

# Configure structured logging
logger = logging.getLogger("watcher.agent")


class WatchdogAgent:
    """
    Main Coordinator for Member 1: Windows Watchdog Agent.
    
    Coordinates FileMonitor, ProcessMonitor, CanaryMonitor, and HeartbeatMonitor
    to capture, enrich, and dispatch structured defensive telemetry events.
    """

    def __init__(
        self,
        watch_dir: str | Path,
        recursive: bool = True,
        correlate_processes: bool = True,
        enable_canary: bool = True,
        canary_monitor: Optional[CanaryMonitor] = None,
        enable_heartbeat: bool = True,
        heartbeat_interval: float = 30.0,
        heartbeat_monitor: Optional[HeartbeatMonitor] = None,
        heartbeat_callbacks: Optional[List[Callable[[HeartbeatData], None]]] = None,
        max_event_history: int = 200,
        callbacks: Optional[List[Callable[[EventData], None]]] = None,
        log_json: bool = False,
    ) -> None:
        """
        Initialize the WatchdogAgent.

        Args:
            watch_dir: Target directory path to monitor.
            recursive: Whether to monitor subdirectories recursively.
            correlate_processes: Whether to enrich events with top active process telemetry.
            enable_canary: Whether to enable honeypot/canary decoy monitoring.
            canary_monitor: Custom CanaryMonitor instance (or auto-created if enable_canary is True).
            enable_heartbeat: Whether to enable periodic liveness heartbeats.
            heartbeat_interval: Heartbeat emission interval in seconds (default: 30.0s).
            heartbeat_monitor: Custom HeartbeatMonitor instance.
            heartbeat_callbacks: Optional list of callbacks receiving `HeartbeatData`.
            max_event_history: Maximum number of recent events to store in memory.
            callbacks: Optional list of callback functions receiving `EventData`.
            log_json: If True, log events as single-line JSON strings.
        """
        self.watch_dir = Path(watch_dir).resolve()
        self.recursive = recursive
        self.correlate_processes = correlate_processes
        self.log_json = log_json

        self.process_monitor = ProcessMonitor()
        self._start_time: Optional[float] = None
        self._events_processed_count: int = 0
        
        # Initialize Canary Monitor
        if canary_monitor is not None:
            self.canary_monitor = canary_monitor
        elif enable_canary:
            self.canary_monitor = CanaryMonitor(canary_dir=self.watch_dir)
        else:
            self.canary_monitor = None

        # Initialize Heartbeat Monitor
        self._heartbeat_callbacks: List[Callable[[HeartbeatData], None]] = list(heartbeat_callbacks or [])
        if heartbeat_monitor is not None:
            self.heartbeat_monitor = heartbeat_monitor
            self.heartbeat_monitor.set_callback(self._handle_heartbeat)
        elif enable_heartbeat:
            self.heartbeat_monitor = HeartbeatMonitor(
                interval=heartbeat_interval,
                callback=self._handle_heartbeat,
                get_status_fn=self._get_agent_status_metrics,
                process_monitor=self.process_monitor,
                watch_dir=self.watch_dir,
            )
        else:
            self.heartbeat_monitor = None

        self._callbacks: List[Callable[[EventData], None]] = list(callbacks or [])
        self._event_history: Deque[EventData] = deque(maxlen=max_event_history)

        self.file_monitor = FileMonitor(
            watch_dir=self.watch_dir,
            callback=self._handle_file_event,
            recursive=self.recursive,
        )

    def add_callback(self, callback: Callable[[EventData], None]) -> None:
        """
        Register a subscriber callback for downstream pipeline integration.

        Args:
            callback: Function accepting an `EventData` instance.
        """
        if callback not in self._callbacks:
            self._callbacks.append(callback)

    def remove_callback(self, callback: Callable[[EventData], None]) -> None:
        """Unregister a subscriber callback."""
        if callback in self._callbacks:
            self._callbacks.remove(callback)

    def add_heartbeat_callback(self, callback: Callable[[HeartbeatData], None]) -> None:
        """
        Register a subscriber callback for heartbeat telemetry events.

        Args:
            callback: Function accepting a `HeartbeatData` instance.
        """
        if callback not in self._heartbeat_callbacks:
            self._heartbeat_callbacks.append(callback)

    def remove_heartbeat_callback(self, callback: Callable[[HeartbeatData], None]) -> None:
        """Unregister a heartbeat subscriber callback."""
        if callback in self._heartbeat_callbacks:
            self._heartbeat_callbacks.remove(callback)

    def get_uptime(self) -> float:
        """Return total elapsed running time in seconds."""
        if self._start_time is None:
            return 0.0
        return max(0.0, time.time() - self._start_time)

    def _get_agent_status_metrics(self) -> Dict[str, Any]:
        """Internal status metric provider for HeartbeatMonitor."""
        return {
            "uptime_seconds": self.get_uptime(),
            "events_processed": self._events_processed_count,
            "status": "active" if self.is_alive() else "idle",
            "metadata": {
                "canary_enabled": self.canary_monitor is not None,
                "recursive": self.recursive,
            },
        }

    def emit_heartbeat(self) -> Optional[HeartbeatData]:
        """
        Emit a heartbeat event immediately on demand.

        Returns:
            HeartbeatData instance, or None if heartbeats are disabled.
        """
        if self.heartbeat_monitor:
            return self.heartbeat_monitor.emit_heartbeat()
        return None

    def _handle_heartbeat(self, heartbeat: HeartbeatData) -> None:
        """Internal handler for emitted heartbeat events."""
        if self.log_json:
            print(heartbeat.to_json())
        else:
            proc_info = ""
            if heartbeat.process_telemetry:
                proc_info = f" [PID: {heartbeat.pid} CPU: {heartbeat.process_telemetry.cpu_percent:.1f}% RAM: {heartbeat.process_telemetry.memory_percent:.1f}%]"
            logger.info(
                "[HEARTBEAT] Status: %s | Uptime: %.1fs | Events: %d%s",
                heartbeat.status.upper(),
                heartbeat.uptime_seconds,
                heartbeat.events_processed,
                proc_info,
            )

        for cb in self._heartbeat_callbacks:
            try:
                cb(heartbeat)
            except Exception as e:
                logger.error("Error in heartbeat subscriber callback: %s", e, exc_info=True)

    def deploy_canaries(self, filenames: Optional[List[str]] = None) -> List[Path]:
        """
        Deploy inert canary decoy files in the monitored directory.

        Args:
            filenames: Optional list of filenames to deploy as canaries.

        Returns:
            List of Path objects for the deployed canary files.
        """
        if self.canary_monitor is None:
            self.canary_monitor = CanaryMonitor(canary_dir=self.watch_dir)
        return self.canary_monitor.deploy_canaries(target_dir=self.watch_dir, filenames=filenames)

    def cleanup_canaries(self) -> int:
        """
        Remove deployed synthetic canary files from the monitored directory.

        Returns:
            Count of removed canary files.
        """
        if self.canary_monitor:
            return self.canary_monitor.cleanup_canaries(target_dir=self.watch_dir)
        return 0

    def _handle_file_event(self, event: EventData) -> None:
        """
        Internal handler invoked when FileMonitor detects an event.
        Enriches with defensive process telemetry and notifies subscribers.
        """
        self._events_processed_count += 1

        # Inspect and tag canary events
        if self.canary_monitor is not None:
            event = self.canary_monitor.inspect_and_tag_event(event)

        # Optionally correlate with active system process activity
        if self.correlate_processes and self.process_monitor.is_psutil_available:
            top_procs = self.process_monitor.get_top_active_processes(limit=1, sort_by="cpu")
            if top_procs:
                event.process_telemetry = top_procs[0]

        # Record in history buffer
        self._event_history.append(event)

        # Log event
        if self.log_json:
            print(event.to_json())
        else:
            proc_info = ""
            if event.process_telemetry:
                proc_info = f" [Top Proc: {event.process_telemetry.name} (PID: {event.process_telemetry.pid}) CPU: {event.process_telemetry.cpu_percent:.1f}%]"
            dest_info = f" -> {event.dest_path}" if event.dest_path else ""
            size_info = f" ({event.file_size_bytes} bytes)" if event.file_size_bytes is not None else ""
            
            if event.is_canary:
                logger.warning(
                    "[CANARY ALERT - HIGH SEVERITY] [%s] %s%s%s%s",
                    event.event_type.upper(),
                    event.file_path,
                    dest_info,
                    size_info,
                    proc_info,
                )
            else:
                logger.info(
                    "[%s] %s%s%s%s",
                    event.event_type.upper(),
                    event.file_path,
                    dest_info,
                    size_info,
                    proc_info,
                )

        # Dispatch to all registered callbacks (e.g. RiskAnalyser / ML pipeline)
        for cb in self._callbacks:
            try:
                cb(event)
            except Exception as e:
                logger.error("Error in event subscriber callback: %s", e, exc_info=True)

    def get_recent_events(self, limit: Optional[int] = None) -> List[EventData]:
        """
        Retrieve a snapshot list of recent telemetry events.

        Args:
            limit: Maximum number of events to return (default: all in history).

        Returns:
            List of EventData objects.
        """
        events = list(self._event_history)
        if limit is not None:
            return events[-limit:]
        return events

    def start(self) -> None:
        """Start the watchdog monitoring agent and heartbeat emitter."""
        if not self.watch_dir.exists():
            self.watch_dir.mkdir(parents=True, exist_ok=True)
            logger.info("Created target watch directory: %s", self.watch_dir)

        self._start_time = time.time()
        logger.info("WatchdogAgent starting on: %s", self.watch_dir)
        self.file_monitor.start()

        if self.heartbeat_monitor is not None:
            self.heartbeat_monitor.start()

        logger.info("WatchdogAgent active. Monitoring file operations and emitting heartbeats.")

    def stop(self) -> None:
        """Stop the watchdog monitoring agent and heartbeat emitter."""
        logger.info("Stopping WatchdogAgent...")
        if self.heartbeat_monitor is not None:
            self.heartbeat_monitor.stop()

        self.file_monitor.stop()
        logger.info("WatchdogAgent stopped.")

    def is_alive(self) -> bool:
        """Check if the agent is actively monitoring."""
        return self.file_monitor.is_alive()

    def __enter__(self) -> WatchdogAgent:
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()


def run_standalone_demo(target_dir: str | Path, duration_seconds: Optional[int] = None) -> None:
    """
    Run a safe standalone demonstration of the Watchdog Agent.

    Args:
        target_dir: Path to directory to safely monitor.
        duration_seconds: Duration to run (in seconds), or None to run until Ctrl+C.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] (WatchdogAgent) %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    path = Path(target_dir).resolve()
    print("=" * 70)
    print("  TRINETRA - Member 1: Windows Watchdog Agent (Defensive Telemetry)")
    print(f"  Target Watch Directory: {path}")
    print("  Mode: Read-only, defensive telemetry collection")
    print("=" * 70)

    # Example subscriber callback for downstream pipeline integration
    def sample_downstream_receiver(event: EventData) -> None:
        # Downstream modules (RiskAnalyser / Policy Engine) receive standard EventData
        pass

    agent = WatchdogAgent(
        watch_dir=path,
        recursive=True,
        correlate_processes=True,
        callbacks=[sample_downstream_receiver],
    )

    try:
        agent.start()
        print("\n[+] Monitoring active. Perform file operations in the target folder to view telemetry.")
        print("[+] Press Ctrl+C to stop.\n")

        start_time = time.time()
        while True:
            time.sleep(0.5)
            if duration_seconds is not None and (time.time() - start_time) >= duration_seconds:
                break
    except KeyboardInterrupt:
        print("\n[*] Stopping Watchdog Agent...")
    finally:
        agent.stop()
        print(f"[+] Total events captured: {len(agent.get_recent_events())}")
        print("[+] Shutdown complete.")


def main() -> None:
    """Command-line interface entry point for the Watchdog Agent."""
    parser = argparse.ArgumentParser(
        description="TRINETRA Member 1: Windows Watchdog Agent (Defensive Telemetry)",
    )
    parser.add_argument(
        "--watch-dir",
        "-d",
        type=str,
        default="./disposable_test_sandbox",
        help="Directory to monitor (default: ./disposable_test_sandbox)",
    )
    parser.add_argument(
        "--duration",
        "-t",
        type=int,
        default=None,
        help="Run for N seconds and exit (default: run until Ctrl+C)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON telemetry lines instead of formatted log messages",
    )

    args = parser.parse_args()

    if args.json:
        # Suppress standard logging to stdout to keep JSON output clean
        logging.basicConfig(level=logging.WARNING)
        agent = WatchdogAgent(watch_dir=args.watch_dir, log_json=True)
        try:
            agent.start()
            start_time = time.time()
            while True:
                time.sleep(0.5)
                if args.duration is not None and (time.time() - start_time) >= args.duration:
                    break
        except KeyboardInterrupt:
            pass
        finally:
            agent.stop()
    else:
        run_standalone_demo(target_dir=args.watch_dir, duration_seconds=args.duration)


if __name__ == "__main__":
    main()
