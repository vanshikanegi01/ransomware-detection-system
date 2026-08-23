# TRINETRA — Policy Engine + Enforcer Module

A working backend prototype implementing:

```
WATCHDOG → ML ANALYZER (risk score) → POLICY ENGINE → ENFORCER → VAULTKEEPER → DASHBOARD
```

## Quick start

```bash
cd trinetra
python3 -m venv venv && source venv/bin/activate      # optional but recommended
pip install -r requirements.txt

uvicorn backend.main:app --reload --port 8000
```

Open http://127.0.0.1:8000/docs for interactive API docs, or connect a
dashboard client to `ws://127.0.0.1:8000/ws` for real-time events.

Run the safe demo attack simulation:

```bash
curl -X POST http://127.0.0.1:8000/simulate/start
```

This creates dummy files in `sandbox_data/test_target/`, backs them up
via Vaultkeeper, "attacks" them with placeholder content (never real
encryption), and drives the full pipeline: risk escalation → policy
decision → enforcement → recovery. Watch `/dashboard/events` or the
WebSocket feed to see it happen in real time.

## Project layout

```
trinetra/
├── policy_engine/       # Risk scoring, explainable rules, decision thresholds
│   ├── policy_engine.py     # Orchestrator: evaluate() -> decision -> enforcement hand-off
│   ├── rules.py              # Explainable behavioral rules (+points, reasons)
│   ├── risk_calculator.py    # Combines ML score with rule-based score
│   ├── decision.py           # Score -> SAFE/SUSPICIOUS/HIGH_RISK/THREAT_CONFIRMED
│   ├── models.py             # Pydantic request/response models
│   └── config.json           # Thresholds + enforcer config (hot-reloadable via API)
│
├── enforcer/             # Automated containment (defensive only)
│   ├── enforcer.py           # Public contain() entry point used by Policy Engine
│   ├── process_manager.py    # PID validation + safe termination + protected allowlist
│   ├── file_locker.py        # Read-only lock/unlock, sandbox-root restricted
│   ├── network_isolator.py   # Windows Firewall isolation w/ safe simulation fallback
│   ├── actions.py            # Orchestrates the containment sequence
│   └── logger.py             # JSONL audit log of every enforcement action
│
├── vaultkeeper/
│   └── vaultkeeper.py     # Backup snapshotting, integrity hash verification, restore
│
├── simulator/
│   └── simulator.py       # SAFE demo attack generator (sandbox-only, no real ransomware)
│
├── backend/
│   ├── main.py             # FastAPI app: REST + WebSocket, wires everything together
│   ├── database.py         # SQLite event persistence
│   └── websocket_manager.py
│
├── sandbox_data/test_target/   # Demo-only dummy files (safe to modify/destroy)
├── backups/                    # Vaultkeeper's clean-version store for the demo
├── logs/                       # enforcer_actions.jsonl audit log
├── db/trinetra.db              # SQLite event history (created on first run)
└── requirements.txt
```

## API summary

| Method | Path | Purpose |
|---|---|---|
| POST | `/policy/evaluate` | Submit a behavioral signal, get a policy decision (+ triggers enforcement if THREAT_CONFIRMED) |
| GET | `/policy/config` | Current thresholds + enforcer config |
| POST | `/policy/config/thresholds` | Update SAFE/SUSPICIOUS/HIGH_RISK/ransomware thresholds |
| POST | `/policy/config/enforcer` | Toggle `enabled` / `dry_run` / `kill_switch` |
| POST | `/enforcer/unlock-all` | Reverse all active file locks |
| GET | `/enforcer/log` | Recent enforcement audit log |
| POST | `/vaultkeeper/snapshot` | Take a clean backup snapshot of given paths |
| POST | `/simulate/start` | Run the full safe demo attack scenario |
| GET | `/dashboard/state` | Current status + recent events, for the dashboard's initial load |
| GET | `/dashboard/events` | Full recent event history |
| WS | `/ws` | Real-time event stream (same events written to SQLite) |

## Decision thresholds (configurable, default demo values)

| Score | Decision | Action |
|---|---|---|
| 0–29 | SAFE | Monitor only |
| 30–43 | SUSPICIOUS | Increase monitoring, log, no termination |
| 44–69 | HIGH_RISK | Restrict/validate; escalates to THREAT_CONFIRMED if ≥3 strong ransomware indicators co-occur |
| 70–100 | THREAT_CONFIRMED | Enforcer activates: terminate, lock, isolate, notify Vaultkeeper |

`RANSOMWARE_THRESHOLD` defaults to **44**, matching the spec. Edit
`policy_engine/config.json` or call `POST /policy/config/thresholds`
to change it live.

## Safety guarantees baked into the Enforcer

- **Never deletes or encrypts files** — file "locking" only flips a
  read-only bit and is fully reversible via `/enforcer/unlock-all`.
- **Protected-process allowlist** (`enforcer/process_manager.py`) — core
  OS processes (svchost, explorer.exe, lsass.exe, etc.) can never be
  terminated, regardless of what a compromised upstream signal claims.
- **Sandbox-root restriction** on file locking — the Enforcer refuses
  to lock any path outside `sandbox_data/` in this prototype config.
- **`dry_run` and `kill_switch`** — both configurable live via the
  Policy Engine API; `kill_switch` fully disables the Enforcer without
  redeploying.
- **Every action is logged** to `logs/enforcer_actions.jsonl` and to
  SQLite/WebSocket for the dashboard.
- Network isolation uses the real Windows Firewall (`netsh advfirewall`)
  only when running on Windows with admin rights and a resolvable
  process path; otherwise it safely simulates the action so the demo
  never breaks on a dev machine or fails destructively.

## Notes for going further

- `process_manager.py`, `network_isolator.py` are written to run for
  real on Windows (psutil + netsh) and to gracefully simulate on any
  other OS — no code changes needed to demo on macOS/Linux dev boxes.
- The frontend dashboard (React/TypeScript/Tailwind/Recharts) is not
  included here — this deliverable is the backend/API layer. Point a
  dashboard at `GET /dashboard/state` for the initial paint and
  `WS /ws` for the live event stream shown in the spec's example
  timeline.
- `PolicyEngine.evaluate()` returns `score_breakdown` with per-rule
  point contributions, matching the explainable-risk format in the
  spec (`+35 file mod rate`, `+40 entropy`, etc.).
