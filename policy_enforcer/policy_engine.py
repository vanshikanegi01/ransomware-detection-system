"""
TRINETRA Policy Engine

Orchestrates: BehavioralSignal -> risk scoring -> decision -> (optional)
Enforcer invocation -> Vaultkeeper notification -> event emission.

The engine is transport-agnostic: it takes an `event_sink` callable that
is invoked with every event dict it produces. The FastAPI backend wires
this to SQLite persistence + WebSocket broadcast.
"""
from __future__ import annotations

import json
import os
import copy
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from .models import BehavioralSignal, PolicyDecisionResponse
from .risk_calculator import compute_final_score
from .decision import classify

CONFIG_PATH = Path(__file__).parent / "config.json"

EventSink = Callable[[dict], None]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class PolicyEngine:
    def __init__(self, event_sink: Optional[EventSink] = None,
                 enforcer=None, vaultkeeper=None):
        self.event_sink = event_sink or (lambda e: None)
        self.enforcer = enforcer
        self.vaultkeeper = vaultkeeper
        self.config = self._load_config()

    # ------------------------------------------------------------------
    # Config management
    # ------------------------------------------------------------------
    def _load_config(self) -> dict:
        with open(CONFIG_PATH, "r") as f:
            return json.load(f)

    def _save_config(self) -> None:
        with open(CONFIG_PATH, "w") as f:
            json.dump(self.config, f, indent=2)

    def get_config(self) -> dict:
        return copy.deepcopy(self.config)

    def update_thresholds(self, updates: dict) -> dict:
        for key, value in updates.items():
            if value is not None and key in self.config["thresholds"]:
                self.config["thresholds"][key] = value
        self._save_config()
        self._emit({"event": "CONFIG_UPDATED", "section": "thresholds",
                     "config": self.config["thresholds"]})
        return self.config["thresholds"]

    def update_enforcer_config(self, updates: dict) -> dict:
        for key, value in updates.items():
            if value is not None and key in self.config["enforcer"]:
                self.config["enforcer"][key] = value
        self._save_config()
        self._emit({"event": "CONFIG_UPDATED", "section": "enforcer",
                     "config": self.config["enforcer"]})
        return self.config["enforcer"]

    # ------------------------------------------------------------------
    # Event emission
    # ------------------------------------------------------------------
    def _emit(self, event: dict) -> None:
        event.setdefault("timestamp", _utc_now())
        self.event_sink(event)

    # ------------------------------------------------------------------
    # Core evaluation
    # ------------------------------------------------------------------
    def evaluate(self, sig: BehavioralSignal) -> PolicyDecisionResponse:
        final_score, reasons, breakdown = compute_final_score(sig)
        decision, severity, action, escalated = classify(final_score, sig, self.config)

        if escalated:
            reasons.append(
                "Escalated from HIGH_RISK to THREAT_CONFIRMED: multiple "
                "independent ransomware indicators co-occurred"
            )

        self._emit({
            "event": decision,
            "risk_score": final_score,
            "process": sig.process_name,
            "pid": sig.process_id,
            "severity": severity,
            "reasons": reasons,
        })

        enforcement_result = None

        if decision == "THREAT_CONFIRMED" and action == "ENFORCE":
            enforcement_result = self._trigger_enforcement(sig, reasons)
        elif decision == "HIGH_RISK":
            self._emit({
                "event": "HIGH_RISK_MONITORING_INCREASED",
                "pid": sig.process_id,
                "process": sig.process_name,
            })
        elif decision == "SUSPICIOUS":
            self._emit({
                "event": "SUSPICIOUS_ACTIVITY_LOGGED",
                "pid": sig.process_id,
                "process": sig.process_name,
            })

        return PolicyDecisionResponse(
            decision=decision,
            risk_score=final_score,
            severity=severity,
            action=action,
            process_id=sig.process_id,
            process_name=sig.process_name,
            reasons=reasons,
            score_breakdown=breakdown,
            enforcement_result=enforcement_result,
        )

    # ------------------------------------------------------------------
    # Enforcement + recovery hand-off
    # ------------------------------------------------------------------
    def _trigger_enforcement(self, sig: BehavioralSignal, reasons: list) -> dict:
        enforcer_cfg = self.config["enforcer"]

        if enforcer_cfg.get("kill_switch"):
            self._emit({"event": "ENFORCER_DISABLED_KILL_SWITCH",
                         "pid": sig.process_id})
            return {"enforced": False, "reason": "kill_switch_engaged"}

        if not enforcer_cfg.get("enabled", True):
            self._emit({"event": "ENFORCER_DISABLED", "pid": sig.process_id})
            return {"enforced": False, "reason": "enforcer_disabled"}

        self._emit({"event": "ENFORCER_ACTIVATED", "pid": sig.process_id,
                     "process": sig.process_name})

        if self.enforcer is None:
            return {"enforced": False, "reason": "enforcer_not_wired"}

        affected_paths = sig.affected_paths or []
        command = {
            "action": "CONTAIN",
            "process_id": sig.process_id,
            "process_name": sig.process_name,
            "affected_paths": affected_paths,
            "dry_run": enforcer_cfg.get("dry_run", False),
        }

        result = self.enforcer.contain(command, event_sink=self._emit)

        # Hand off to Vaultkeeper for recovery once containment succeeds
        if result.get("contained") and self.vaultkeeper is not None:
            self._emit({"event": "VAULTKEEPER_NOTIFIED", "pid": sig.process_id,
                         "affected_paths": affected_paths})
            recovery_result = self.vaultkeeper.recover(
                sig, affected_paths, event_sink=self._emit
            )
            result["recovery"] = recovery_result

        return result
