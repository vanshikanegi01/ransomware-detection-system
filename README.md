# TRINETRA — Member 3: Vaultkeeper (Backup & Automated Recovery Engine)

> **Bharat's Next-Generation Cyber Resilience Platform**  
> *Tagline:* Detect $\rightarrow$ Defend $\rightarrow$ Auto-Recover

---

## 1. What Vaultkeeper Does

**Vaultkeeper** is the automated recovery and data resilience core of the **TRINETRA** platform. Its mission is to maintain protected, versioned file snapshots, ensure tamper-evident cryptographic integrity, and perform automated, selective rollback of affected files after a confirmed ransomware attack.

Vaultkeeper guarantees that **no file is ever restored blindly**:
1. It enforces the **Attack Timestamp Boundary** so that only snapshots captured strictly *prior* to the attack onset are eligible candidates.
2. It performs **Dual-Stage Cryptographic Verification (SHA-256 & AES-256-GCM)** before candidate restoration and after disk write-back.
3. It performs **Selective Restoration**, restoring only corrupted/affected files without altering unaffected user data.
4. It tracks recovery on a **per-file basis** and outputs comprehensive **Business Recovery Reports**.

---

## 2. Architecture & Pipeline

In TRINETRA, the 6-member cross-functional workflow operates as follows:

```
[Member 1: Watchdog]   --> Detects suspicious file modifications & entropy spikes
        ↓
[Member 2: ML Analyzer]--> Calculates anomaly risk score
        ↓
[Member 4: Policy Engine] -> Confirms threat & triggers containment & recovery
        ↓
   ┌────┴───────────────────────────┐
   ▼                                ▼
[Member 6: Enforcer]        [Member 3: Vaultkeeper]
Process Kill & Locking       Automated Rollback & Integrity Verification
                                    ↓
                            [Member 5: Frontend / Dashboard]
                            Real-time Progress & Business Recovery Report
```

### Vaultkeeper Internal Component Layout:

```
vaultkeeper/
├── models.py            # Data schemas (BackupMetadata, IncidentEvent, RecoveryReport, State Machine)
├── integrity.py         # Chunked streaming SHA-256 hashing & comparison
├── encryption.py        # AES-256-GCM authenticated encryption at rest
├── metadata.py          # SQLite persistence store for backup catalogs & incident reports
├── remberall_adapter.py # Decoupled adapter interface for Remberall versioning/deduplication
├── backup.py            # Snapshot creation, hashing, AES encryption, and cataloging
├── versioning.py        # Multi-version indexing & attack-boundary filtering
├── restore.py           # Pre-restore verification, atomic write-back, and post-restore verification
├── recovery.py          # Multi-file recovery coordinator & state machine
└── manager.py           # Unified high-level orchestrator facade
```

---

## 3. Installation

### Requirements
* Python 3.11+ (Tested on Python 3.11 – 3.14)
* OS: Windows / Linux / macOS

### Setup Virtual Environment
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

---

## 4. How to Run Tests

Execute the automated test suite with pytest:

```powershell
python -m pytest -v
```

The test suite covers:
* SHA-256 stability, single-byte mutation detection, and chunked streaming.
* Backup creation, metadata cataloging, and AES-256-GCM encryption at rest.
* Multi-version preservation ($v_1, v_2, v_3$) without overwrites.
* Attack timestamp filtering ($T_{\text{candidate}} < T_{\text{attack}}$).
* Dual-stage integrity verification (pre-restore & post-restore).
* Fallback candidate selection when newest candidate is tampered/corrupted.
* Selective recovery (only affected files restored, unaffected files untouched).
* Partial, complete, and failed recovery scenarios.
* Business Recovery Report JSON serialization.
* Remberall adapter contract and mock deduplication metrics.

---

## 5. How to Run the Safe Test Simulator

Run the safe, standalone demo script:

```powershell
python simulator/ransomware_simulator.py
```

> **SAFETY GUARDRAIL:** The simulator operates **STRICTLY** on disposable test directories (e.g. `disposable_test_sandbox/`) containing synthetic dummy files. It will refuse to run against root or system directories.

---

## 6. Example Usage: Backup Creation

```python
from pathlib import Path
from vaultkeeper import VaultkeeperManager
from vaultkeeper.encryption import generate_aes_key

# 1. Initialize Vaultkeeper with AES-256 key and vault directory
aes_key = generate_aes_key()
manager = VaultkeeperManager(
    vault_dir=Path("./vault_storage"),
    encryption_key=aes_key
)

# 2. Back up an individual critical file
file_to_protect = Path("./my_documents/financial_report.xlsx")
meta = manager.backup_file(file_to_protect)

print(f"Created version: {meta.version_id} (v{meta.version_number})")
print(f"SHA-256: {meta.sha256_hash}")
print(f"Encrypted in vault: {meta.vault_path}")
```

---

## 7. Example Usage: Incident Handling & Auto-Recovery

```python
from datetime import datetime, timezone
from vaultkeeper import VaultkeeperManager

manager = VaultkeeperManager(vault_dir="./vault_storage", encryption_key=aes_key)

# Incident payload received from Member 4 (Policy Engine / FastAPI)
incident_payload = {
    "event": "RANSOMWARE_CONFIRMED",
    "incident_id": "INC-2026-001",
    "timestamp": "2026-08-19T12:05:00",  # Attack onset boundary
    "risk_score": 94.0,
    "affected_files": [
        "C:/my_documents/financial_report.xlsx",
        "C:/my_documents/customers.csv"
    ]
}

# Progress callback for WebSocket / UI streaming
def on_progress(event):
    print(f"[{event.event}] {event.path or ''} ({event.completed}/{event.total})")

# Execute automated rollback
report = manager.handle_incident(incident_payload, progress_callback=on_progress)

# View recovery summary
print(f"Status: {report.recovery_status}")
print(f"Files Recovered: {report.files_recovered}/{report.files_at_risk}")
print(report.to_json())
```

---

## 8. The Recovery Algorithm

```
                  [CONFIRMED INCIDENT RECEIVED]
                                │
                                ▼
                   [Parse Attack Timestamp T_attack]
                                │
                 ┌──────────────┴──────────────┐
                 ▼                             ▼
        [Affected File #1]            [Affected File #N]
                 │                             │
                 ▼                             ▼
   [Query Versions where T < T_attack]
                 │
                 ▼
   [Sort Candidates: Newest → Oldest]
                 │
                 ▼
   [Pre-Restore Integrity Verification (SHA-256)]
                 │
        ┌────────┴────────┐
     (Valid)           (Corrupted)
        │                 │
        ▼                 ▼
   [Restore to Disk]  [Try Next Older Candidate]
        │                 │
        ▼                 └────────┐
   [Post-Restore Verification]     ▼
        │                    (No more candidates)
   ┌────┴────┐                     │
(Match)   (Mismatch)               ▼
   │         │               [Mark FAILED]
   ▼         ▼
[Mark RECOVERED] [Try Older Candidate]
        │
        ▼
   [Generate Aggregate Business Recovery Report]
```

---

## 9. Remberall Adapter Design

The project specification calls for **Remberall** integration as the file versioning, deduplication, and snapshotting layer. Because the specific third-party Python SDK signatures are not published in the upstream document, Vaultkeeper applies the **Adapter Pattern** (`vaultkeeper/remberall_adapter.py`).

* `RemberallAdapter (ABC)` defines the required interface (`create_snapshot`, `list_snapshots`, `verify_snapshot`, `restore_snapshot`, `get_deduplication_metrics`).
* `MockRemberallAdapter` provides an in-memory, fully functional mock for testing and local prototypes.
* When the concrete Remberall SDK is published, a production adapter implementing `RemberallAdapter` will be plugged in without changing any core Vaultkeeper logic.

---

## 10. Current Prototype Boundaries & Limitations

1. **Key Management:** In this prototype, AES-256 keys are supplied programmatically or generated at runtime. Production deployments should bind key storage to an enterprise KMS, HSM, or OS-level keystore (e.g., Windows DPAPI).
2. **Local Workstation Scope:** Designed for local agent deployment with SQLite metadata persistence.
3. **Third-Party Upstream SDKs:** Remberall is wrapped via an adapter until upstream C-bindings / Python package specs are released.

---

## 11. Team Integration Points (Members 4, 5, & 6)

* **Member 4 (Backend & Policy Engine):** Calls `manager.handle_incident(incident_dict)` upon threat validation; subscribes to progress events.
* **Member 5 (Frontend / UI Dashboard):** Consumes `RecoveryProgressEvent` streams over WebSocket and renders the final `RecoveryReport` JSON.
* **Member 6 (Enforcer / QA):** Ensures process termination and file locking occur *before* Vaultkeeper begins restoration; utilizes `simulator/ransomware_simulator.py` for end-to-end integration tests.
