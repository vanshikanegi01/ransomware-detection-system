"""
TRINETRA Safe Ransomware Simulation Mode

Generates FAKE behavioral signals and dummy sandbox files to exercise
the full detection -> policy -> enforcement -> recovery pipeline. This
module NEVER encrypts, deletes, or damages real user data - it only
ever touches files inside sandbox_data/test_target, which it creates
itself, and copies of which are pre-backed-up via Vaultkeeper so
recovery has something real to restore.

No actual malicious code, exploit, or ransomware logic is implemented
here - it is purely a data generator that feeds the existing pipeline.
"""
from __future__ import annotations

import random
import time
from pathlib import Path
from typing import Callable, Optional

from .models import BehavioralSignal

BASE_DIR = Path(__file__).parent.parent
SANDBOX_DIR = BASE_DIR / "sandbox_data" / "test_target"

DUMMY_FILENAMES = [
    "quarterly_report.docx", "budget.xlsx", "family_photo.jpg",
    "invoice_2026.pdf", "notes.txt", "presentation.pptx",
    "contacts.csv", "vacation.jpg",
]


def ensure_dummy_files() -> list:
    SANDBOX_DIR.mkdir(parents=True, exist_ok=True)
    created = []
    for name in DUMMY_FILENAMES:
        p = SANDBOX_DIR / name
        if not p.exists():
            p.write_text(f"DUMMY TEST CONTENT for {name} - safe to modify/restore.\n" * 5)
        created.append(str(p))
    return created


class RansomwareSimulator:
    """
    Drives a scripted, safe attack scenario through the full TRINETRA
    pipeline: Watchdog signal -> ML risk score -> Policy Engine ->
    Enforcer -> Vaultkeeper -> Dashboard.
    """

    def __init__(self, policy_engine, vaultkeeper, event_sink: Optional[Callable[[dict], None]] = None):
        self.policy_engine = policy_engine
        self.vaultkeeper = vaultkeeper
        self.event_sink = event_sink or (lambda e: None)

    def run(self, ramp_up: bool = True) -> dict:
        dummy_files = ensure_dummy_files()

        # Ensure Vaultkeeper has clean backups BEFORE the "attack" so
        # recovery has legitimate clean versions to restore.
        self.vaultkeeper.snapshot([str(SANDBOX_DIR)])

        self.event_sink({"event": "SIMULATION_STARTED",
                          "sandbox_directory": str(SANDBOX_DIR)})

        pid = random.randint(4000, 9000)
        process_name = "simulated_malware.exe"
        process_location = str(SANDBOX_DIR / process_name)

        if ramp_up:
            # Early low/medium reading, mirroring the example demo timeline
            early_signal = BehavioralSignal(
                risk_score=35,
                process_name=process_name,
                process_id=pid,
                entropy=4.1,
                file_modification_rate=12,
                files_modified=6,
                file_extensions=[".txt"],
                process_location=process_location,
                network_activity=False,
                suspicious_behavior=False,
            )
            self.event_sink({"event": "SUSPICIOUS_PROCESS_DETECTED", "pid": pid,
                              "process": process_name})
            self.policy_engine.evaluate(early_signal)
            time.sleep(0.4)

        # Simulate the "attack" touching dummy files (safe: sandbox only,
        # content is rewritten with high-entropy-looking placeholder
        # bytes, nothing is deleted, originals are already backed up)
        self._simulate_file_touch(dummy_files)

        final_signal = BehavioralSignal(
            risk_score=85,
            process_name=process_name,
            process_id=pid,
            entropy=7.92,
            file_modification_rate=150,
            files_modified=250,
            file_extensions=[".docx", ".xlsx", ".pdf", ".jpg"],
            process_location=process_location,
            network_activity=True,
            suspicious_behavior=True,
            affected_paths=[str(SANDBOX_DIR)],
        )

        self.event_sink({"event": "RISK_ESCALATION_DETECTED", "risk_score": 85})
        decision = self.policy_engine.evaluate(final_signal)

        return {
            "pid": pid,
            "process_name": process_name,
            "decision": decision.decision,
            "risk_score": decision.risk_score,
            "enforcement_result": decision.enforcement_result,
        }

    def _simulate_file_touch(self, files: list) -> None:
        """Rewrites dummy sandbox files with placeholder 'scrambled'
        content to emulate a modification burst for the demo, WITHOUT
        deleting anything and WITHOUT real encryption. Originals were
        already snapshotted by Vaultkeeper before this runs."""
        for f in files:
            try:
                p = Path(f)
                p.write_text("[SIMULATED-ENCRYPTED-PLACEHOLDER] " + p.name + "\n" * 3)
            except Exception:
                continue
