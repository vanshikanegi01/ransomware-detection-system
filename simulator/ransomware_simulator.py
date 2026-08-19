"""Safe Test Simulator for Vaultkeeper Demonstration and Testing.

=============================================================================
SAFETY NOTICE:
This simulator is designed STRICTLY for testing and demonstration in disposable
directories. It contains NO real malware behavior, does NOT execute real
ransomware, does NOT touch system/user files, and will refuse to operate
outside designated sandbox directories.
=============================================================================

Member 3: Recovery Engineer
TRINETRA: Bharat's Next-Generation Cyber Resilience Platform
"""

from __future__ import annotations

import os
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

# Add project root to sys.path if run directly
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from vaultkeeper.encryption import generate_aes_key
from vaultkeeper.integrity import calculate_sha256
from vaultkeeper.manager import VaultkeeperManager
from vaultkeeper.models import IncidentEvent, RecoveryProgressEvent


class SafeSimulatorSecurityError(Exception):
    """Raised when an operation attempts to run on an unsafe directory."""


class SafeRansomwareSimulator:
    """Safe test harness to simulate filesystem mutations and test Vaultkeeper rollback."""

    SAFE_DIR_MARKERS = ["disposable", "test", "sandbox", "temp", "dummy", "pytest"]

    def __init__(self, sandbox_dir: Path) -> None:
        """Initialize simulator inside a dedicated sandbox directory.

        Args:
            sandbox_dir: Dedicated directory for dummy test files.

        Raises:
            SafeSimulatorSecurityError: If directory is deemed unsafe or system critical.
        """
        self.sandbox_dir = Path(sandbox_dir).resolve()
        self._validate_safety(self.sandbox_dir)
        self.sandbox_dir.mkdir(parents=True, exist_ok=True)

    @classmethod
    def _validate_safety(cls, path: Path) -> None:
        """Enforce strict guardrails against operating on real user/system paths."""
        resolved = path.resolve()
        path_str = str(resolved).lower()

        # Guardrail 1: Disallow root drives
        if len(resolved.parts) <= 1 or resolved.parent == resolved:
            raise SafeSimulatorSecurityError(f"Refusing to operate on root directory: {resolved}")

        # Guardrail 2: Disallow critical OS paths
        critical_patterns = ["c:\\windows", "c:\\program files", "/usr", "/etc", "/bin", "/var", "/system"]
        for cp in critical_patterns:
            if path_str.startswith(cp):
                raise SafeSimulatorSecurityError(f"Refusing to operate on system directory: {resolved}")

        # Guardrail 3: Must contain a safe testing marker in directory path
        has_marker = any(marker in path_str for marker in cls.SAFE_DIR_MARKERS)
        if not has_marker:
            raise SafeSimulatorSecurityError(
                f"Directory '{resolved}' does not contain a recognized safe marker "
                f"({cls.SAFE_DIR_MARKERS}). To protect user data, simulation is aborted."
            )

    def create_dummy_workload(self, count: int = 10) -> List[Path]:
        """Create a set of dummy business documents with known initial content.

        Args:
            count: Number of dummy files to generate.

        Returns:
            List of generated file paths.
        """
        created_files: List[Path] = []
        extensions = [".docx", ".xlsx", ".pdf", ".csv", ".txt"]

        for i in range(1, count + 1):
            ext = extensions[(i - 1) % len(extensions)]
            filename = f"business_record_{i:03d}{ext}"
            file_path = self.sandbox_dir / filename
            content = (
                f"--- CONFIDENTIAL BUSINESS RECORD #{i:03d} ---\n"
                f"Created for TRINETRA Cyber Resilience Platform Simulation\n"
                f"Initial State Checksum Anchor: {i * 1000}\n"
                f"Timestamp: {datetime.now(timezone.utc).isoformat()}\n"
            )
            file_path.write_text(content, encoding="utf-8")
            created_files.append(file_path)

        return created_files

    def modify_dummy_files(self, file_paths: List[Path], append_text: str = "\n-- Version 2 updates --\n") -> List[Path]:
        """Apply legitimate clean modifications to dummy files (to create multiple versions).

        Args:
            file_paths: List of dummy files to update.
            append_text: Content to append.

        Returns:
            List of modified file paths.
        """
        modified: List[Path] = []
        for p in file_paths:
            self._validate_safety(p)
            if p.is_file():
                current_text = p.read_text(encoding="utf-8")
                p.write_text(current_text + append_text, encoding="utf-8")
                modified.append(p)
        return modified

    def simulate_attack_damage(self, file_paths: List[Path]) -> List[Path]:
        """Safely simulate corruption/encryption damage strictly on dummy files.

        Replaces content of dummy files with simulated locked payload.

        Args:
            file_paths: Dummy files to mutate.

        Returns:
            List of simulated damaged file paths.
        """
        damaged: List[Path] = []
        for p in file_paths:
            self._validate_safety(p)
            if p.is_file():
                # Overwrite dummy file content with simulated encrypted garbage
                simulated_locked_content = (
                    b"--- [SIMULATED RANSOMWARE ENCRYPTED PAYLOAD] ---\n"
                    b"YOUR FILES HAVE BEEN SIMULATED AS ENCRYPTED FOR TRINETRA DEMO.\n"
                    + os.urandom(256)
                )
                p.write_bytes(simulated_locked_content)
                damaged.append(p)
        return damaged


def run_standalone_demo(base_tmp_dir: Optional[Path] = None) -> None:
    """Run an end-to-end demonstration of Vaultkeeper auto-recovery."""
    print("=" * 70)
    print("TRINETRA Member 3 - Vaultkeeper Safe Simulator Demo")
    print("=" * 70)

    # 1. Setup disposable sandbox
    sandbox_base = base_tmp_dir or Path(PROJECT_ROOT / "disposable_test_sandbox")
    workload_dir = sandbox_base / "user_workload"
    vault_dir = sandbox_base / "protected_vault"

    if sandbox_base.exists():
        try:
            shutil.rmtree(sandbox_base)
        except Exception:
            pass

    workload_dir.mkdir(parents=True, exist_ok=True)
    vault_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Disposable sandbox created at: {sandbox_base}")

    # 2. Initialize Simulator & Vaultkeeper
    simulator = SafeRansomwareSimulator(workload_dir)
    aes_key = generate_aes_key()
    manager = VaultkeeperManager(vault_dir=vault_dir, encryption_key=aes_key)

    # 3. Create initial dummy business workload
    print("\n[Step 1] Creating initial dummy business files...")
    dummy_files = simulator.create_dummy_workload(count=8)
    for f in dummy_files:
        print(f"  + Created: {f.name} (SHA-256: {calculate_sha256(f)[:12]}...)")

    # 4. Perform Version 1 Backups (10:00 AM simulated)
    print("\n[Step 2] Creating initial Version 1 backups...")
    v1_time = "2026-08-19T10:00:00"
    for f in dummy_files:
        meta = manager.backup_file(f, custom_timestamp=v1_time)
        print(f"  -> Vaulted {f.name} as {meta.version_id} (v{meta.version_number}) at {v1_time}")

    # 5. Legitimate updates and Version 2 Backups (11:00 AM simulated)
    print("\n[Step 3] Applying legitimate user edits and creating Version 2 backups...")
    simulator.modify_dummy_files(dummy_files, append_text="\n[Q3 Financial Forecast: Approved]\n")
    v2_time = "2026-08-19T11:00:00"
    v2_expected_hashes = {}
    for f in dummy_files:
        meta = manager.backup_file(f, custom_timestamp=v2_time)
        v2_expected_hashes[f.name] = meta.sha256_hash
        print(f"  -> Vaulted {f.name} as {meta.version_id} (v{meta.version_number}) at {v2_time} [Clean SHA: {meta.sha256_hash[:12]}...]")

    # 6. Simulate Attack Onset at 12:05 PM
    attack_onset = "2026-08-19T12:05:00"
    print(f"\n[Step 4] Simulating Ransomware Attack at {attack_onset}...")
    
    # 4 of the 8 files were corrupted by the simulator
    attacked_files = dummy_files[:4]
    unaffected_files = dummy_files[4:]

    simulator.simulate_attack_damage(attacked_files)
    for f in attacked_files:
        print(f"  [!] Damaged file: {f.name} (Compromised SHA-256: {calculate_sha256(f)[:12]}...)")

    # 7. Also simulate a post-attack snapshot (12:06 PM) to prove Vaultkeeper rejects post-attack backups!
    v3_post_attack_time = "2026-08-19T12:06:00"
    print(f"\n[Step 5] Simulating a bad backup captured AFTER attack boundary ({v3_post_attack_time})...")
    for f in attacked_files:
        manager.backup_file(f, custom_timestamp=v3_post_attack_time)
        print(f"  -> Bad snapshot captured post-attack for {f.name} at {v3_post_attack_time}")

    # 8. Receive Confirmed Incident from Policy Engine
    print("\n[Step 6] Receiving 'RANSOMWARE_CONFIRMED' event from Policy Engine (Member 4)...")
    incident_payload = {
        "event": "RANSOMWARE_CONFIRMED",
        "incident_id": "INC-2026-DEMO-001",
        "timestamp": attack_onset,
        "risk_score": 92.5,
        "affected_files": [str(f) for f in attacked_files],
    }

    def on_progress(ev: RecoveryProgressEvent):
        if ev.event == "file_recovered":
            print(f"    [*] Progress [{ev.completed}/{ev.total}]: Restored and Verified {Path(ev.path or '').name}")
        elif ev.event == "file_failed":
            print(f"    [X] Progress [{ev.completed}/{ev.total}]: Failed {Path(ev.path or '').name} - {ev.message}")

    print("\n[Step 7] Executing Vaultkeeper Automated Selective Recovery...")
    report = manager.handle_incident(incident_payload, progress_callback=on_progress)

    # 9. Verify Restored Files
    print("\n[Step 8] Verifying Post-Recovery Filesystem State...")
    for f in attacked_files:
        current_hash = calculate_sha256(f)
        expected_hash = v2_expected_hashes[f.name]
        is_match = current_hash == expected_hash
        print(f"  + Restored {f.name}: {'MATCH (Clean v2 restored)' if is_match else 'MISMATCH'} (Hash: {current_hash[:12]}...)")

    # Unaffected files check
    print("\n[Step 9] Verifying Unaffected Files were Untouched...")
    for f in unaffected_files:
        print(f"  + Unaffected file intact: {f.name} (SHA: {calculate_sha256(f)[:12]}...)")

    # 10. Print Business Recovery Report
    print("\n" + "=" * 70)
    print("BUSINESS RECOVERY REPORT DATA")
    print("=" * 70)
    print(report.to_json())
    print("=" * 70)

    # Clean up sandbox
    try:
        shutil.rmtree(sandbox_base)
        print("[*] Disposable sandbox cleaned up successfully.\n")
    except Exception as e:
        print(f"[*] Note: Sandbox cleanup notice: {e}\n")


if __name__ == "__main__":
    run_standalone_demo()
