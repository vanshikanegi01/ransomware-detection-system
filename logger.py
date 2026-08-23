"""
Structured logging for every Enforcer action. Appends JSON Lines so the
log is both human-inspectable and trivially machine-parseable for
audit/compliance review.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


class EnforcerLogger:
    def __init__(self, log_path: str):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, action: str, details: dict) -> None:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "action": action,
            "details": details,
        }
        with open(self.log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def read_recent(self, limit: int = 100) -> list:
        if not self.log_path.exists():
            return []
        lines = self.log_path.read_text().strip().splitlines()
        recent = lines[-limit:]
        out = []
        for line in recent:
            try:
                out.append(json.loads(line))
            except Exception:
                continue
        return out
