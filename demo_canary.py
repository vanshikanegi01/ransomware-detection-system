"""
TRINETRA - Member 1: Windows Watchdog Agent (Canary Decoy Demonstration).

Demonstrates real-time ransomware honeypot / canary tripwire detection.
Deploys harmless dummy canary files into `./disposable_test_sandbox` and
monitors for unauthorized modifications, renames, or deletions with HIGH severity alerts.

Safety Guardrail:
- Operates ONLY inside `./disposable_test_sandbox`.
- Strictly passive/defensive; never creates, encrypts, or deletes non-canary files.
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

from watcher import CanaryMonitor, EventData, WatchdogAgent

SANDBOX_DIR = _PROJECT_ROOT / "disposable_test_sandbox"


def print_telemetry_event(event: EventData) -> None:
    """
    Format and print structured telemetry events, clearly highlighting canary tripwires.
    """
    file_info = event.file_path
    if event.dest_path:
        file_info += f"  -->  {event.dest_path}"

    size_str = f"{event.file_size_bytes:,} bytes" if event.file_size_bytes is not None else "N/A"

    if event.is_canary:
        # Highlighted Canary Alert
        border = "!" * 75
        print("\n" + border)
        print("  *** CANARY ALERT ***")
        print(f"  Alert:     CANARY ALERT (is_canary=True, severity={event.severity})")
        print(f"  Operation: [{event.event_type.upper()}] on Canary Honeypot File")
        print(f"  Target:    {file_info}")
        print(f"  Extension: {event.file_extension or 'None':<12} | Size: {size_str} | is_canary={event.is_canary} | severity={event.severity}")
        if event.process_telemetry:
            proc = event.process_telemetry
            exe = proc.exe_path or "restricted"
            print(f"  Process:   PID {proc.pid} ({proc.name}) | CPU: {proc.cpu_percent:.1f}% | RAM: {proc.memory_percent:.1f}%")
            print(f"  Binary:    {exe}")
        print(border)
    else:
        # Standard Normal Event Display
        border = "-" * 75
        print("\n" + border)
        print(f"  [NORMAL EVENT] [{event.event_type.upper()}] | is_canary=False | severity={event.severity}")
        print(f"  Target:    {file_info}")
        print(f"  Extension: {event.file_extension or 'None':<12} | Size: {size_str}")
        if event.process_telemetry:
            proc = event.process_telemetry
            print(f"  Process:   PID {proc.pid} ({proc.name}) | CPU: {proc.cpu_percent:.1f}%")
        print(border)


def main() -> None:
    """Main execution entry point."""
    SANDBOX_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 75)
    print("  TRINETRA — Member 1: Canary Decoy Monitoring (Interactive Demo)")
    print("=" * 75)
    print(f"  [+] Target Watch Directory: {SANDBOX_DIR.resolve()}")
    print("  [+] Mode:                   Canary Tripwire & Defensive Telemetry")
    print("  [+] Guardrail:              Monitors ONLY the disposable sandbox")
    print("=" * 75)

    # Initialize WatchdogAgent with Canary monitoring enabled
    agent = WatchdogAgent(
        watch_dir=SANDBOX_DIR,
        recursive=True,
        correlate_processes=True,
        enable_canary=True,
        callbacks=[print_telemetry_event],
    )

    print("\n[+] Deploying inert canary decoy files in sandbox...")
    canary_files = agent.deploy_canaries([
        "!_canary_01_financial_ledger.docx",
        "!_canary_02_passwords.xlsx",
        "000_canary_database_backup.pdf",
    ])
    for cf in canary_files:
        print(f"    - {cf.name}")

    try:
        agent.start()
        print("\n[+] Watchdog Agent is RUNNING with Canary Tripwires active.")
        print("\n>>> Simulated Ransomware Test:")
        print(f"    1. Modify or delete a canary file in {SANDBOX_DIR.name}/ (e.g. '!_canary_01_financial_ledger.docx')")
        print("       --> Triggers immediate HIGH-SEVERITY CANARY ALERT.")
        print(f"    2. Create a normal file in {SANDBOX_DIR.name}/ (e.g. 'notes.txt')")
        print("       --> Emits standard NORMAL telemetry.")
        print("\n[+] Press Ctrl+C at any time to stop monitoring.\n")

        while True:
            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\n\n[*] Caught Ctrl+C. Stopping Watchdog Agent...")
    finally:
        agent.stop()
        total_events = len(agent.get_recent_events())
        canary_triggers = sum(1 for e in agent.get_recent_events() if e.is_canary)
        print(f"[+] Total events recorded: {total_events} (Canary alerts: {canary_triggers})")
        print("[+] Demonstration ended cleanly.\n")


if __name__ == "__main__":
    main()
