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

from watcher.file_monitor import FileMonitor
from watcher.models import EventData, EventType, ProcessTelemetry
from watcher.process_monitor import ProcessMonitor

# Configure structured logging
logger = logging.getLogger("watcher.agent")


class WatchdogAgent:
    """
    Main Coordinator for Member 1: Windows Watchdog Agent.
    
    Coordinates FileMonitor and ProcessMonitor to capture, enrich, and
    dispatch structured defensive telemetry events.
    """

    def __init__(
        self,
        watch_dir: str | Path,
        recursive: bool = True,
        correlate_processes: bool = True,
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
            max_event_history: Maximum number of recent events to store in memory.
            callbacks: Optional list of callback functions receiving `EventData`.
            log_json: If True, log events as single-line JSON strings.
        """
        self.watch_dir = Path(watch_dir).resolve()
        self.recursive = recursive
        self.correlate_processes = correlate_processes
        self.log_json = log_json

        self.process_monitor = ProcessMonitor()
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

    def _handle_file_event(self, event: EventData) -> None:
        """
        Internal handler invoked when FileMonitor detects an event.
        Enriches with defensive process telemetry and notifies subscribers.
        """
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
        """Start the watchdog monitoring agent."""
        if not self.watch_dir.exists():
            self.watch_dir.mkdir(parents=True, exist_ok=True)
            logger.info("Created target watch directory: %s", self.watch_dir)

        logger.info("WatchdogAgent starting on: %s", self.watch_dir)
        self.file_monitor.start()
        logger.info("WatchdogAgent active. Monitoring file operations.")

    def stop(self) -> None:
        """Stop the watchdog monitoring agent."""
        logger.info("Stopping WatchdogAgent...")
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
