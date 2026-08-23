"""
Behavioral rule set for TRINETRA Policy Engine.

Each rule inspects the incoming BehavioralSignal and, if triggered,
contributes an explainability entry: (points, reason_text).

The rules are intentionally conservative and additive; they exist to
(a) produce human-readable justification for a decision, and
(b) allow the Policy Engine to escalate a HIGH RISK score to
    THREAT_CONFIRMED when multiple independent ransomware indicators
    are present, even if the raw ML risk_score alone would not cross
    the configured threshold.
"""
from __future__ import annotations

from typing import List, Tuple
from .models import BehavioralSignal

BUSINESS_EXTENSIONS = {
    ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".pdf",
    ".jpg", ".jpeg", ".png", ".csv", ".txt", ".zip", ".rar",
    ".db", ".sql", ".psd", ".ai",
}

RANSOM_NOTE_HINTS = (
    "readme", "decrypt", "how_to", "how-to", "restore_files",
    "recover", "ransom", "unlock",
)


def rule_file_modification_rate(sig: BehavioralSignal) -> Tuple[int, str] | None:
    rate = sig.file_modification_rate or 0
    if rate >= 100:
        return 35, f"Extremely high file modification rate ({rate:.0f} files/sec)"
    if rate >= 50:
        return 20, f"Elevated file modification rate ({rate:.0f} files/sec)"
    if rate >= 20:
        return 8, f"Above-normal file modification rate ({rate:.0f} files/sec)"
    return None


def rule_entropy(sig: BehavioralSignal) -> Tuple[int, str] | None:
    entropy = sig.entropy or 0
    if entropy >= 7.8:
        return 40, f"Abnormal entropy ({entropy:.2f}/8.0) indicating likely encryption"
    if entropy >= 7.0:
        return 22, f"High entropy ({entropy:.2f}/8.0) consistent with compression/encryption"
    return None


def rule_suspicious_behavior_flag(sig: BehavioralSignal) -> Tuple[int, str] | None:
    if sig.suspicious_behavior:
        return 10, "Process flagged with suspicious behavioral characteristics"
    return None


def rule_business_extensions(sig: BehavioralSignal) -> Tuple[int, str] | None:
    exts = {e.lower() for e in (sig.file_extensions or [])}
    hits = exts & BUSINESS_EXTENSIONS
    if len(hits) >= 3:
        return 15, f"Multiple business file extensions affected ({', '.join(sorted(hits))})"
    if len(hits) >= 1:
        return 5, f"Business file extensions affected ({', '.join(sorted(hits))})"
    return None


def rule_files_modified_volume(sig: BehavioralSignal) -> Tuple[int, str] | None:
    count = sig.files_modified or 0
    if count >= 200:
        return 15, f"Very large number of files modified ({count})"
    if count >= 50:
        return 8, f"Significant number of files modified ({count})"
    return None


def rule_process_location(sig: BehavioralSignal) -> Tuple[int, str] | None:
    loc = (sig.process_location or "").lower()
    suspicious_paths = ("\\temp\\", "\\appdata\\local\\temp\\", "/tmp/", "\\downloads\\")
    if any(p in loc for p in suspicious_paths):
        return 8, f"Process executing from suspicious/transient location ({sig.process_location})"
    return None


def rule_network_activity(sig: BehavioralSignal) -> Tuple[int, str] | None:
    if sig.network_activity:
        return 7, "Suspicious outbound network activity detected (possible C2 / exfiltration)"
    return None


def rule_ransom_note_hint(sig: BehavioralSignal) -> Tuple[int, str] | None:
    name = (sig.process_name or "").lower()
    if any(h in name for h in RANSOM_NOTE_HINTS):
        return 20, f"Process name matches known ransomware/ransom-note naming pattern ({sig.process_name})"
    return None


ALL_RULES = [
    rule_file_modification_rate,
    rule_entropy,
    rule_suspicious_behavior_flag,
    rule_business_extensions,
    rule_files_modified_volume,
    rule_process_location,
    rule_network_activity,
    rule_ransom_note_hint,
]


def evaluate_rules(sig: BehavioralSignal) -> Tuple[int, List[str], List[dict]]:
    """
    Run all behavioral rules against a signal.

    Returns:
        total_points: sum of all triggered rule point contributions
        reasons: list of human-readable reason strings
        breakdown: list of {"points": int, "reason": str} for the dashboard
    """
    total_points = 0
    reasons: List[str] = []
    breakdown: List[dict] = []

    for rule in ALL_RULES:
        result = rule(sig)
        if result:
            points, reason = result
            total_points += points
            reasons.append(reason)
            breakdown.append({"points": points, "reason": reason})

    return total_points, reasons, breakdown


def count_strong_indicators(sig: BehavioralSignal, cfg: dict) -> int:
    """
    Count independent strong ransomware indicators for escalation logic,
    e.g. bumping a HIGH RISK score to THREAT_CONFIRMED when several
    hallmark ransomware behaviors co-occur.
    """
    esc = cfg.get("escalation", {})
    indicators = 0

    if (sig.entropy or 0) >= esc.get("min_entropy_for_encryption_flag", 7.5):
        indicators += 1
    if (sig.file_modification_rate or 0) >= esc.get("min_file_modification_rate_flag", 50):
        indicators += 1
    if (sig.files_modified or 0) >= esc.get("min_files_modified_flag", 100):
        indicators += 1
    if sig.suspicious_behavior:
        indicators += 1
    if sig.network_activity:
        indicators += 1
    exts = {e.lower() for e in (sig.file_extensions or [])}
    if len(exts & BUSINESS_EXTENSIONS) >= 3:
        indicators += 1

    return indicators
