"""
TRINETRA — Gatekeeper Agent: Safe Interactive Demonstration.

Provides a safe, interactive CLI demo for preventive URL and file screening
without performing any network calls, file execution, or system modifications.
All evaluations are performed purely via local, explainable heuristics.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

# Enable immediate stdout flush
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(line_buffering=True)

# Ensure project root is on sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from gatekeeper import GatekeeperAgent, ScreeningResult, ScreeningVerdict, TargetType


def print_banner() -> None:
    """Display clean startup banner."""
    print("=" * 75)
    print("  TRINETRA — Gatekeeper Agent (Safe Interactive Demo)")
    print("=" * 75)
    print("  [+] First-Line Preventive Screening Layer")
    print("  [+] URL, Domain, and File Metadata Analysis")
    print("  [+] Defensive Risk Assessment & Policy Verdicts")
    print("  [+] Fully Offline & Safe (No network/execution)")
    print("=" * 75)


def print_menu() -> None:
    """Display interactive CLI menu options."""
    print("\n[ MENU OPTIONS ]")
    print("  [1] Screen a URL")
    print("  [2] Screen a file name / path")
    print("  [3] View Gatekeeper statistics")
    print("  [4] View recent screening history")
    print("  [5] Run built-in safe demo examples")
    print("  [0] Exit")


def display_result(result: ScreeningResult) -> None:
    """Format and print structured screening results."""
    # Convert risk score [0.0 - 1.0] to intuitive 0 - 100 format
    risk_percentage = int(round(result.risk_score * 100))
    verdict_badge = result.verdict.value

    # Color/visual marker based on verdict
    marker = "[ALLOW]" if result.is_allowed else f"[{verdict_badge}]"

    print("\n" + "-" * 75)
    print(f"  Target Type: {result.target_type.upper()}")
    print(f"  Target:      {result.target or '[Empty / None]'}")
    print(f"  Timestamp:   {result.timestamp}")
    print()
    print(f"  Risk Score:  {risk_percentage}/100 ({result.risk_score:.2f})")
    print(f"  Verdict:     {marker} — {verdict_badge}")
    print()
    print("  Indicators / Reasons:")
    if result.reasons:
        for reason in result.reasons:
            print(f"    - {reason}")
    else:
        print("    - No suspicious indicators detected")

    if result.metadata:
        relevant_meta = {k: v for k, v in result.metadata.items() if v not in (None, False, [], "")}
        if relevant_meta:
            print()
            print("  Metadata Snapshot:")
            for k, v in relevant_meta.items():
                print(f"    * {k}: {v}")
    print("-" * 75)


def screen_url_interactive(agent: GatekeeperAgent) -> None:
    """Interactive handler for screening user-supplied URL strings."""
    print("\n--- Screen a URL ---")
    print("Examples: 'https://example.com', 'http://192.168.1.10/login', 'https://paypal-security.example'")
    try:
        url_input = input("Enter URL to screen: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\n[*] Operation cancelled.")
        return

    result = agent.screen_url(url_input)
    display_result(result)


def screen_file_interactive(agent: GatekeeperAgent) -> None:
    """Interactive handler for screening user-supplied filename or path strings."""
    print("\n--- Screen a File Name / Path ---")
    print("Examples: 'report.pdf', 'invoice.pdf.exe', 'photo.jpg.scr', 'urgent_payment.bat'")
    try:
        file_input = input("Enter file name or path to screen: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\n[*] Operation cancelled.")
        return

    result = agent.screen_file(file_input)
    display_result(result)


def show_statistics(agent: GatekeeperAgent) -> None:
    """Display cumulative operational statistics from the GatekeeperAgent."""
    status = agent.get_status()
    counts = status.get("verdict_counts", {})

    print("\n" + "=" * 75)
    print("  TRINETRA Gatekeeper — Operational Status & Statistics")
    print("=" * 75)
    print(f"  Agent Status:           {status.get('status', 'active').upper()}")
    print(f"  Total Screenings:       {status.get('total_screenings', 0)}")
    print(f"  History Buffer Usage:   {status.get('history_size', 0)} / {status.get('max_history_size', 1000)}")
    print()
    print("  Verdict Distribution:")
    print(f"    - ALLOW:              {counts.get(ScreeningVerdict.ALLOW.value, 0)}")
    print(f"    - MONITOR:            {counts.get(ScreeningVerdict.MONITOR.value, 0)}")
    print(f"    - SUSPICIOUS:         {counts.get(ScreeningVerdict.SUSPICIOUS.value, 0)}")
    print(f"    - BLOCK:              {counts.get(ScreeningVerdict.BLOCK.value, 0)}")
    print()
    thresholds = status.get("policy_thresholds", {})
    if thresholds:
        print("  Configured Risk Thresholds:")
        print(f"    - 0.00 – {thresholds.get('allow_threshold', 0.29):.2f} : ALLOW")
        print(f"    - {thresholds.get('allow_threshold', 0.29) + 0.01:.2f} – {thresholds.get('monitor_threshold', 0.59):.2f} : MONITOR")
        print(f"    - {thresholds.get('monitor_threshold', 0.59) + 0.01:.2f} – {thresholds.get('suspicious_threshold', 0.79):.2f} : SUSPICIOUS")
        print(f"    - {thresholds.get('block_threshold', 0.80):.2f} – 1.00 : BLOCK")
    print("=" * 75)


def show_history(agent: GatekeeperAgent) -> None:
    """Display recent chronological screening history."""
    history = agent.get_recent_results()
    if not history:
        print("\n[!] No screening history recorded yet in this session.")
        return

    print("\n" + "=" * 75)
    print(f"  Recent Screening History ({len(history)} total entries)")
    print("=" * 75)
    for idx, res in enumerate(history, 1):
        risk_pct = int(round(res.risk_score * 100))
        target_display = res.target if len(res.target) <= 45 else f"{res.target[:42]}..."
        print(
            f"  [{idx:02d}] {res.target_type.upper():<5} | "
            f"Verdict: {res.verdict.value:<10} | "
            f"Risk: {risk_pct:>3}/100 | "
            f"Target: {target_display}"
        )
    print("=" * 75)


def run_demo_examples(agent: GatekeeperAgent) -> None:
    """Automatically run built-in safe URL and file scenarios."""
    print("\n" + "=" * 75)
    print("  Running Built-In Safe Demonstration Scenarios...")
    print("=" * 75)

    sample_urls = [
        ("https://example.com/about", "Clean benign corporate URL"),
        ("http://192.168.1.100/login", "Raw IP address host with login path"),
        ("https://secure-paypal-login.example/verify", "Impersonation domain with security keywords"),
        ("https://example.com@evil.example/login", "Deceptive '@' credential trick in URL"),
    ]

    sample_files = [
        ("quarterly_report.pdf", "Standard benign document (.pdf)"),
        ("photo.jpg", "Standard benign image (.jpg)"),
        ("invoice.pdf.exe", "Double extension attack (.pdf masquerading as .exe)"),
        ("photo.jpg.scr", "Double extension screensaver payload (.jpg.scr)"),
        ("urgent_payment.bat", "Dangerous batch script with urgent payment keywords"),
        ("update.exe", "Standalone executable file (.exe)"),
    ]

    print("\n--- 1. URL Screening Examples ---")
    for url, desc in sample_urls:
        print(f"\n>> Screening URL Scenario: {desc}")
        res = agent.screen_url(url)
        display_result(res)

    print("\n--- 2. File Screening Examples ---")
    for fname, desc in sample_files:
        print(f"\n>> Screening File Scenario: {desc}")
        res = agent.screen_file(fname)
        display_result(res)

    print("\n[+] All built-in demo scenarios completed.")


def main() -> None:
    """Main interactive loop entry point."""
    print_banner()
    agent = GatekeeperAgent()

    while True:
        print_menu()
        try:
            choice = input("\nSelect option [0-5]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n")
            break

        if choice == "1":
            screen_url_interactive(agent)
        elif choice == "2":
            screen_file_interactive(agent)
        elif choice == "3":
            show_statistics(agent)
        elif choice == "4":
            show_history(agent)
        elif choice == "5":
            run_demo_examples(agent)
        elif choice == "0":
            break
        else:
            print(f"\n[!] Invalid option '{choice}'. Please select a number from 0 to 5.")

    status = agent.get_status()
    print("\n" + "=" * 75)
    print("  [+] Gatekeeper demo stopped safely.")
    print(f"  [+] Total screenings performed during this session: {status.get('total_screenings', 0)}")
    print("=" * 75 + "\n")


if __name__ == "__main__":
    main()
