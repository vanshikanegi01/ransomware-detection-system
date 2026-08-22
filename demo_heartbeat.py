"""
TRINETRA - Member 1: Windows Watchdog Agent (Heartbeat Telemetry Demonstration).

Demonstrates real-time periodic heartbeat telemetry alongside file monitoring
and canary tripwire alerts inside `./disposable_test_sandbox`.

Safety Guardrail:
- Operates ONLY inside `./disposable_test_sandbox`.
- Strictly passive/defensive; never terminates processes or modifies real user files.
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

from watcher import EventData, HeartbeatData, WatchdogAgent

SANDBOX_DIR = _PROJECT_ROOT / "disposable_test_sandbox"


def print_heartbeat(hb: HeartbeatData) -> None:
    """Format and print periodic heartbeat telemetry."""
    border = "=" * 75
    print("\n" + border)
    print(f"  [HEARTBEAT PULSE] Status: {hb.status.upper()} | Uptime: {hb.uptime_seconds:.1f}s | Events: {hb.events_processed}")
    print(f"  Timestamp: {hb.timestamp} | PID: {hb.pid}")
    if hb.process_telemetry:
        proc = hb.process_telemetry
        print(f"  Agent Resources: CPU: {proc.cpu_percent:.1f}% | RAM: {proc.memory_percent:.1f}% ({proc.name})")
    print(border)


def print_file_event(event: EventData) -> None:
    """Format and print file telemetry and canary alerts."""
    if event.is_canary:
        border = "!" * 75
        print("\n" + border)
        print("  *** CANARY ALERT ***")
        print(f"  Alert:     CANARY ALERT (is_canary=True, severity={event.severity})")
        print(f"  Operation: [{event.event_type.upper()}] on Canary Honeypot File")
        print(f"  Target:    {event.file_path}")
        print(border)
    else:
        border = "-" * 75
        print("\n" + border)
        print(f"  [FILE EVENT] [{event.event_type.upper()}] | Target: {event.file_path}")
        print(border)


def main() -> None:
    """Main execution entry point."""
    SANDBOX_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 75)
    print("  TRINETRA — Member 1: Heartbeat Telemetry & Watchdog Demo")
    print("=" * 75)
    print(f"  [+] Target Watch Directory: {SANDBOX_DIR.resolve()}")
    print("  [+] Heartbeat Interval:     3.0 seconds")
    print("  [+] Mode:                   Liveness Heartbeat + File Telemetry")
    print("=" * 75)

    agent = WatchdogAgent(
        watch_dir=SANDBOX_DIR,
        recursive=True,
        enable_canary=True,
        enable_heartbeat=True,
        heartbeat_interval=3.0,
        callbacks=[print_file_event],
        heartbeat_callbacks=[print_heartbeat],
    )

    print("\n[+] Deploying inert canary decoy files in sandbox...")
    canary_files = agent.deploy_canaries(["!_canary_tripwire_01.docx"])
    for cf in canary_files:
        print(f"    - {cf.name}")

    try:
        agent.start()
        print("\n[+] Watchdog Agent is RUNNING with Heartbeat Emitter active.")
        print("\n>>> Instructions:")
        print("    - Watch periodic heartbeat pulses every 3.0 seconds.")
        print(f"    - Create/modify files in {SANDBOX_DIR.name}/ to observe event counter incrementing.")
        print("\n[+] Press Ctrl+C at any time to stop monitoring.\n")

        while True:
            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\n\n[*] Caught Ctrl+C. Stopping Watchdog Agent...")
    finally:
        agent.stop()
        print(f"[+] Total running uptime: {agent.get_uptime():.1f}s")
        print("[+] Demonstration ended cleanly.\n")


if __name__ == "__main__":
    main()
