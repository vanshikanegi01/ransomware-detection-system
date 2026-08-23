"""
TRINETRA — Gatekeeper Agent Module.

First-line defensive screening layer for URLs, domains, and files
before reaching the Watchdog Agent or filesystem.
"""

from gatekeeper.file_screening import (
    FileScreener,
    screen_file,
)
from gatekeeper.gatekeeper import (
    GatekeeperAgent,
)
from gatekeeper.models import (
    ScreeningResult,
    ScreeningVerdict,
    TargetType,
)
from gatekeeper.policies import (
    DEFAULT_RISK_POLICY,
    RiskPolicy,
    evaluate_risk_score,
)
from gatekeeper.url_screening import (
    URLScreener,
    screen_url,
)

__all__ = [
    "GatekeeperAgent",
    "ScreeningVerdict",
    "ScreeningResult",
    "TargetType",
    "RiskPolicy",
    "DEFAULT_RISK_POLICY",
    "evaluate_risk_score",
    "URLScreener",
    "screen_url",
    "FileScreener",
    "screen_file",
]
