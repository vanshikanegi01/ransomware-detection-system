"""
Data models for RiskAnalyser service.
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List
import json
from datetime import datetime, timezone
import uuid

@dataclass
class RiskResult:
    """
    Structured outcome of ML model evaluation on a file event.
    """
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    ransomware_probability: float = 0.0
    risk_score: float = 0.0
    threshold_met: bool = False
    gatekeeper_context: Dict[str, Any] = field(default_factory=dict)
    watchdog_context: Dict[str, Any] = field(default_factory=dict)
    features: List[float] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)
