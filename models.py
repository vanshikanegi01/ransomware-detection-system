"""
Pydantic models used by the Policy Engine API.
"""
from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, Field


class BehavioralSignal(BaseModel):
    """Incoming signal from the ML Analyzer / Watchdog pipeline."""

    risk_score: int = Field(..., ge=0, le=100)
    process_name: str
    process_id: int
    entropy: Optional[float] = 0.0
    file_modification_rate: Optional[float] = 0.0
    files_modified: Optional[int] = 0
    file_extensions: Optional[List[str]] = Field(default_factory=list)
    process_location: Optional[str] = ""
    network_activity: Optional[bool] = False
    suspicious_behavior: Optional[bool] = False
    affected_paths: Optional[List[str]] = Field(default_factory=list)


class PolicyDecisionResponse(BaseModel):
    decision: str
    risk_score: int
    severity: str
    action: str
    process_id: int
    process_name: str
    reasons: List[str]
    score_breakdown: dict
    enforcement_result: Optional[dict] = None


class ThresholdUpdate(BaseModel):
    safe_max: Optional[int] = None
    suspicious_max: Optional[int] = None
    high_risk_max: Optional[int] = None
    ransomware_threshold: Optional[int] = None


class EnforcerConfigUpdate(BaseModel):
    enabled: Optional[bool] = None
    dry_run: Optional[bool] = None
    kill_switch: Optional[bool] = None
