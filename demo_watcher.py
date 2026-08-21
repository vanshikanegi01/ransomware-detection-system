"""
TRINETRA - Member 1: Windows Watchdog Agent (Manual Safe Demonstration).

Safe, standalone demonstration script that monitors `./disposable_test_sandbox`
in real-time for file creation, modification, deletion, and rename operations.
Displays defensive telemetry and associated process information.

Safety Guardrail:
- Monitors ONLY the designated disposable sandbox directory.
- Strictly passive/defensive; never creates, encrypts, modifies, or deletes files.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

# Enable immediate stdout flush across all platforms
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(line_buffering=True)

# Ensure project root is in sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from watcher import EventData, WatchdogAgent

# Target directory restricted strictly to disposable sandbox
SANDBOX_DIR = _PROJECT_ROOT / "disposable_test_sandbox"


def print_telemetry_event(event: EventData) -> None:
    """
    Format and print structured telemetry events captured by the Watchdog Agent.
    """
    event_badge = f"[{event.event_type.upper()}]"
    file_info = event.file_path
    
    if event.dest_path:
        file_info += f"  -->  {event.dest_path}"
    
    size_str = f"{event.file_size_bytes:,} bytes" if event.file_size_bytes is not None else "N/A"
    
    print("\n" + "-" * 75)
    print(f"  Event:     {event_badge:<12} | Time: {event.timestamp}")
    print(f"  Target:    {file_info}")
    print(f"  Extension: {event.file_extension or 'None':<12} | Size: {size_str}")
    
    # Print process telemetry if captured
    if event.process_telemetry:
        proc = event.process_telemetry
        exe = proc.exe_path or "restricted"
        print(f"  Process:   PID {proc.pid} ({proc.name}) | CPU: {proc.cpu_percent:.1f}% | RAM: {proc.memory_percent:.1f}%")
        print(f"  Binary:    {exe}")
    else:
        print("  Process:   [No high-activity process correlated]")
    print("-" * 75)


def main() -> None:
    """Main execution entry point."""
    # Ensure disposable sandbox folder exists
    SANDBOX_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 75)
    print("  TRINETRA — Member 1: Windows Watchdog Agent (Safe Interactive Demo)")
    print("=" * 75)
    print(f"  [+] Target Watch Directory: {SANDBOX_DIR.resolve()}")
    print("  [+] Mode:                   Passive Defensive Telemetry")
    print("  [+] Guardrail:              Monitors ONLY the disposable sandbox")
    print("=" * 75)
    print("\n[+] Initializing Watchdog Agent...")

    # Initialize WatchdogAgent with event callback
    agent = WatchdogAgent(
        watch_dir=SANDBOX_DIR,
        recursive=True,
        correlate_processes=True,
        callbacks=[print_telemetry_event],
    )

    try:
        agent.start()
        print("[+] Watchdog Agent is RUNNING.")
        print("\n>>> Instructions:")
        print(f"    Create, edit, rename, or delete files inside:")
        print(f"    {SANDBOX_DIR.resolve()}")
        print("    Telemetry will appear below in real-time.")
        print("\n[+] Press Ctrl+C at any time to stop monitoring safely.\n")

        # Keep running until user issues Ctrl+C
        while True:
            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\n\n[*] Caught Ctrl+C (KeyboardInterrupt). Shutting down...")
    finally:
        agent.stop()
        total_events = len(agent.get_recent_events())
        print(f"[+] Total events recorded in session: {total_events}")
        print("[+] Watchdog Agent shut down cleanly. Goodbye!\n")


if __name__ == "__main__":
    main()
