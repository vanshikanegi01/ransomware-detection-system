"""
Data models and schemas for TRINETRA Gatekeeper Agent.

Defines structured representations for screening verdicts, target types,
and screening results with complete serialization support.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union


class ScreeningVerdict(str, Enum):
    """
    Enumeration of screening verdict decisions produced by Gatekeeper Agent.
    """
    ALLOW = "ALLOW"
    MONITOR = "MONITOR"
    SUSPICIOUS = "SUSPICIOUS"
    BLOCK = "BLOCK"

    @classmethod
    def from_str(cls, value: Union[str, ScreeningVerdict]) -> ScreeningVerdict:
        """
        Safely parse a string or existing verdict enum into ScreeningVerdict.
        
        Defaults to SUSPICIOUS if unknown or unparseable.
        """
        if isinstance(value, cls):
            return value
        if not value or not isinstance(value, str):
            return cls.SUSPICIOUS
        normalized = value.strip().upper()
        for item in cls:
            if item.value == normalized:
                return item
        return cls.SUSPICIOUS


class TargetType(str, Enum):
    """
    Enumeration of supported target types for screening.
    """
    URL = "url"
    FILE = "file"
    DOMAIN = "domain"
    UNKNOWN = "unknown"

    @classmethod
    def from_str(cls, value: Union[str, TargetType]) -> TargetType:
        """Safely parse a string into TargetType enum."""
        if isinstance(value, cls):
            return value
        if not value or not isinstance(value, str):
            return cls.UNKNOWN
        normalized = value.strip().lower()
        for item in cls:
            if item.value == normalized:
                return item
        return cls.UNKNOWN


@dataclass
class ScreeningResult:
    """
    Structured result returned by Gatekeeper Agent screening operations.
    
    Attributes:
        target: The raw target string screened (URL, file path, filename, domain).
        target_type: Type of target ('url', 'file', 'domain', 'unknown').
        verdict: Final decision verdict (ALLOW, MONITOR, SUSPICIOUS, BLOCK).
        risk_score: Calculated risk score normalized to range [0.0, 1.0].
        reasons: List of explainable human-readable reasons justifying the verdict.
        timestamp: ISO-8601 UTC timestamp of the screening operation.
        metadata: Optional contextual metadata dictionary (e.g. parsed components).
    """
    target: str
    target_type: str = TargetType.UNKNOWN.value
    verdict: ScreeningVerdict = ScreeningVerdict.ALLOW
    risk_score: float = 0.0
    reasons: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate and normalize fields after initialization."""
        # Ensure verdict is a ScreeningVerdict enum
        if not isinstance(self.verdict, ScreeningVerdict):
            self.verdict = ScreeningVerdict.from_str(str(self.verdict))
        
        # Ensure risk_score is clamped to [0.0, 1.0] and rounded
        try:
            self.risk_score = round(max(0.0, min(1.0, float(self.risk_score))), 4)
        except (ValueError, TypeError):
            self.risk_score = 0.0

        # Normalize target_type string
        if isinstance(self.target_type, TargetType):
            self.target_type = self.target_type.value
        elif isinstance(self.target_type, str):
            self.target_type = self.target_type.strip().lower()
        else:
            self.target_type = TargetType.UNKNOWN.value

    @property
    def is_allowed(self) -> bool:
        """Check if verdict is ALLOW."""
        return self.verdict == ScreeningVerdict.ALLOW

    @property
    def is_monitored(self) -> bool:
        """Check if verdict is MONITOR."""
        return self.verdict == ScreeningVerdict.MONITOR

    @property
    def is_suspicious(self) -> bool:
        """Check if verdict is SUSPICIOUS."""
        return self.verdict == ScreeningVerdict.SUSPICIOUS

    @property
    def is_blocked(self) -> bool:
        """Check if verdict is BLOCK."""
        return self.verdict == ScreeningVerdict.BLOCK

    def to_dict(self) -> Dict[str, Any]:
        """Convert ScreeningResult to a serializable dictionary."""
        data = asdict(self)
        data["verdict"] = self.verdict.value if isinstance(self.verdict, ScreeningVerdict) else str(self.verdict)
        return data

    def to_json(self, indent: Optional[int] = None) -> str:
        """Serialize ScreeningResult to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ScreeningResult:
        """Reconstruct ScreeningResult from a dictionary."""
        verdict_val = data.get("verdict", ScreeningVerdict.ALLOW)
        verdict = ScreeningVerdict.from_str(verdict_val)
        
        return cls(
            target=str(data.get("target", "")),
            target_type=str(data.get("target_type", TargetType.UNKNOWN.value)),
            verdict=verdict,
            risk_score=float(data.get("risk_score", 0.0)),
            reasons=list(data.get("reasons", [])),
            timestamp=str(data.get("timestamp", datetime.now(timezone.utc).isoformat())),
            metadata=dict(data.get("metadata", {})),
        )

    @classmethod
    def from_json(cls, json_str: str) -> ScreeningResult:
        """Reconstruct ScreeningResult from a JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)
