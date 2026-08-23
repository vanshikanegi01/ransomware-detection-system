"""
Configurable policies and threshold evaluation for TRINETRA Gatekeeper Agent.

Defines configurable thresholds for risk evaluation, mapping numerical risk
scores (0.0 - 1.0) into discrete explainable ScreeningVerdict decisions.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set

from gatekeeper.models import ScreeningVerdict


# Default lists of known sensitive/dangerous patterns for rule-based heuristics
DEFAULT_DANGEROUS_EXTENSIONS: List[str] = [
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".ps1", ".ps1xml", ".ps2", ".psc1", ".psc2",
    ".msh", ".msh1", ".msh2", ".mshxml", ".msh1xml", ".msh2xml",
    ".hta", ".cpl", ".msi", ".msp", ".jar", ".reg", ".pif",
    ".com", ".gadget", ".iso", ".img", ".vhd", ".vhdx"
]

DEFAULT_SUSPICIOUS_DOUBLE_EXTENSIONS: List[str] = [
    ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".docx", ".doc",
    ".xlsx", ".xls", ".pptx", ".ppt", ".txt", ".rtf", ".csv", ".zip",
    ".rar", ".7z", ".tar", ".gz", ".mp3", ".mp4", ".avi", ".mov"
]

DEFAULT_SUSPICIOUS_KEYWORDS: List[str] = [
    "login", "verify", "verification", "secure", "account", "update",
    "password", "banking", "signin", "auth", "credential", "wallet",
    "recover", "billing", "invoice", "payment", "payroll", "receipt",
    "statement", "security", "support", "confirm", "validate",
    "suspended", "unauthorized", "urgent", "decrypt", "locked", "ransom"
]

DEFAULT_ALLOWED_EXTENSIONS: List[str] = [
    ".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt",
    ".txt", ".csv", ".json", ".xml", ".png", ".jpg", ".jpeg",
    ".gif", ".svg", ".zip", ".md", ".log"
]


@dataclass
class RiskPolicy:
    """
    Configurable risk policy containing score thresholds and detection rules.

    Default Thresholds:
        0.00 – 0.29  -> ALLOW
        0.30 – 0.59  -> MONITOR
        0.60 – 0.79  -> SUSPICIOUS
        0.80 – 1.00  -> BLOCK
    """
    allow_threshold: float = 0.29
    monitor_threshold: float = 0.59
    suspicious_threshold: float = 0.79
    block_threshold: float = 0.80

    dangerous_extensions: List[str] = field(default_factory=lambda: list(DEFAULT_DANGEROUS_EXTENSIONS))
    suspicious_double_extensions: List[str] = field(default_factory=lambda: list(DEFAULT_SUSPICIOUS_DOUBLE_EXTENSIONS))
    suspicious_keywords: List[str] = field(default_factory=lambda: list(DEFAULT_SUSPICIOUS_KEYWORDS))
    allowed_extensions: List[str] = field(default_factory=lambda: list(DEFAULT_ALLOWED_EXTENSIONS))

    url_allowlist: List[str] = field(default_factory=list)
    url_blocklist: List[str] = field(default_factory=list)
    domain_allowlist: List[str] = field(default_factory=list)
    domain_blocklist: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Validate thresholds order and consistency."""
        if not (0.0 <= self.allow_threshold <= self.monitor_threshold <= self.suspicious_threshold <= 1.0):
            raise ValueError(
                f"Invalid threshold ordering: allow_threshold ({self.allow_threshold}) "
                f"<= monitor_threshold ({self.monitor_threshold}) "
                f"<= suspicious_threshold ({self.suspicious_threshold}) <= 1.0 required."
            )

    def evaluate_verdict(self, risk_score: float) -> ScreeningVerdict:
        """
        Evaluate a numeric risk score against configured thresholds to produce a ScreeningVerdict.

        Args:
            risk_score: Numerical risk score between 0.0 and 1.0.

        Returns:
            ScreeningVerdict (ALLOW, MONITOR, SUSPICIOUS, or BLOCK).
        """
        clamped_score = max(0.0, min(1.0, float(risk_score)))

        if clamped_score <= self.allow_threshold:
            return ScreeningVerdict.ALLOW
        elif clamped_score <= self.monitor_threshold:
            return ScreeningVerdict.MONITOR
        elif clamped_score <= self.suspicious_threshold:
            return ScreeningVerdict.SUSPICIOUS
        else:
            return ScreeningVerdict.BLOCK

    def to_dict(self) -> Dict[str, Any]:
        """Convert policy to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RiskPolicy:
        """Construct RiskPolicy from dictionary."""
        return cls(
            allow_threshold=float(data.get("allow_threshold", 0.29)),
            monitor_threshold=float(data.get("monitor_threshold", 0.59)),
            suspicious_threshold=float(data.get("suspicious_threshold", 0.79)),
            block_threshold=float(data.get("block_threshold", 0.80)),
            dangerous_extensions=list(data.get("dangerous_extensions", DEFAULT_DANGEROUS_EXTENSIONS)),
            suspicious_double_extensions=list(data.get("suspicious_double_extensions", DEFAULT_SUSPICIOUS_DOUBLE_EXTENSIONS)),
            suspicious_keywords=list(data.get("suspicious_keywords", DEFAULT_SUSPICIOUS_KEYWORDS)),
            allowed_extensions=list(data.get("allowed_extensions", DEFAULT_ALLOWED_EXTENSIONS)),
            url_allowlist=list(data.get("url_allowlist", [])),
            url_blocklist=list(data.get("url_blocklist", [])),
            domain_allowlist=list(data.get("domain_allowlist", [])),
            domain_blocklist=list(data.get("domain_blocklist", [])),
        )


# Global default risk policy instance
DEFAULT_RISK_POLICY = RiskPolicy()


def evaluate_risk_score(risk_score: float, policy: Optional[RiskPolicy] = None) -> ScreeningVerdict:
    """
    Convenience function to evaluate a risk score using the given or default policy.

    Args:
        risk_score: Numerical risk score in range [0.0, 1.0].
        policy: Optional RiskPolicy instance. Uses DEFAULT_RISK_POLICY if None.

    Returns:
        ScreeningVerdict enum decision.
    """
    active_policy = policy or DEFAULT_RISK_POLICY
    return active_policy.evaluate_verdict(risk_score)
