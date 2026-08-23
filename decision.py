"""
Maps a final risk score (+ behavioral indicators) to a Policy Engine
decision category, severity, and recommended action.

Categories (default thresholds, configurable via config.json):
    0-29   -> SAFE
    30-43  -> SUSPICIOUS
    44-69  -> HIGH_RISK        (escalates to THREAT_CONFIRMED if enough
                                 independent strong indicators co-occur)
    70-100 -> THREAT_CONFIRMED
"""
from __future__ import annotations

from typing import Tuple
from .models import BehavioralSignal
from .rules import count_strong_indicators


def classify(final_score: int, sig: BehavioralSignal, cfg: dict) -> Tuple[str, str, str, bool]:
    """
    Returns:
        decision: SAFE | SUSPICIOUS | HIGH_RISK | THREAT_CONFIRMED
        severity: LOW | MEDIUM | HIGH | CRITICAL
        action:   MONITOR | LOG | RESTRICT | ENFORCE
        escalated: whether a HIGH_RISK score was escalated to THREAT_CONFIRMED
    """
    t = cfg["thresholds"]
    escalated = False

    if final_score <= t["safe_max"]:
        return "SAFE", "LOW", "MONITOR", escalated

    if final_score <= t["suspicious_max"]:
        return "SUSPICIOUS", "MEDIUM", "LOG", escalated

    if final_score <= t["high_risk_max"]:
        # HIGH_RISK band: check escalation to THREAT_CONFIRMED
        strong_indicators = count_strong_indicators(sig, cfg)
        required = cfg.get("escalation", {}).get(
            "high_risk_indicator_count_to_escalate", 3
        )
        if strong_indicators >= required and final_score >= t["ransomware_threshold"]:
            escalated = True
            return "THREAT_CONFIRMED", "CRITICAL", "ENFORCE", escalated
        return "HIGH_RISK", "HIGH", "RESTRICT", escalated

    # final_score > high_risk_max (i.e. >= ransomware_threshold band, up to 100)
    return "THREAT_CONFIRMED", "CRITICAL", "ENFORCE", escalated
