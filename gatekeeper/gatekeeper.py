"""
TRINETRA — Gatekeeper Agent Core Orchestrator.

Main entry point for first-line preventive screening of incoming URLs,
domains, file paths, and filenames. Coordinates specialized offline heuristic
screeners, maintains thread-safe screening history, and produces explainable
ScreeningResult decisions before inputs reach the Watchdog Agent or filesystem.
"""

from __future__ import annotations

import threading
from collections import deque
from typing import Any, Dict, List, Optional, Union

from gatekeeper.file_screening import FileScreener, screen_file
from gatekeeper.models import ScreeningResult, ScreeningVerdict, TargetType
from gatekeeper.policies import DEFAULT_RISK_POLICY, RiskPolicy
from gatekeeper.url_screening import URLScreener, screen_url


class GatekeeperAgent:
    """
    Preventive First-Line Screening Agent for TRINETRA.

    Acts as the defensive gatekeeper coordinating URL, Domain, and File
    screening modules. Provides a unified API, maintains in-memory history
    and statistics with thread-safety, and maps heuristics to discrete verdicts.
    """

    def __init__(
        self,
        policy: Optional[RiskPolicy] = None,
        max_history: int = 1000,
        url_allowlist: Optional[List[str]] = None,
        url_blocklist: Optional[List[str]] = None,
        domain_allowlist: Optional[List[str]] = None,
        domain_blocklist: Optional[List[str]] = None,
        dangerous_extensions: Optional[List[str]] = None,
        allowed_extensions: Optional[List[str]] = None,
        suspicious_keywords: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize the GatekeeperAgent with optional policy and rule overrides.

        Args:
            policy: Configured RiskPolicy instance. Uses DEFAULT_RISK_POLICY if None.
            max_history: Maximum number of recent screening results to store in memory.
            url_allowlist: Optional override list of trusted URL substrings.
            url_blocklist: Optional override list of blocked URL substrings.
            domain_allowlist: Optional override list of trusted domains.
            domain_blocklist: Optional override list of blocked domains.
            dangerous_extensions: Optional override list of dangerous extensions.
            allowed_extensions: Optional override list of allowed benign extensions.
            suspicious_keywords: Optional override list of suspicious heuristic keywords.
        """
        # Build or adapt policy
        if policy is None:
            self.policy = RiskPolicy()
        else:
            # Create a copy so modifications don't mutate caller's policy object
            self.policy = RiskPolicy.from_dict(policy.to_dict())

        # Apply any explicit parameter overrides to the policy
        if url_allowlist is not None:
            self.policy.url_allowlist = list(url_allowlist)
        if url_blocklist is not None:
            self.policy.url_blocklist = list(url_blocklist)
        if domain_allowlist is not None:
            self.policy.domain_allowlist = list(domain_allowlist)
        if domain_blocklist is not None:
            self.policy.domain_blocklist = list(domain_blocklist)
        if dangerous_extensions is not None:
            self.policy.dangerous_extensions = list(dangerous_extensions)
        if allowed_extensions is not None:
            self.policy.allowed_extensions = list(allowed_extensions)
        if suspicious_keywords is not None:
            self.policy.suspicious_keywords = list(suspicious_keywords)

        self.max_history = max(1, int(max_history))

        # Specialized sub-screeners
        self.url_screener = URLScreener(policy=self.policy)
        self.file_screener = FileScreener(policy=self.policy)

        # Thread-safe history and statistics tracking
        self._lock = threading.Lock()
        self._history: deque[ScreeningResult] = deque(maxlen=self.max_history)
        self._total_screenings: int = 0
        self._verdict_counts: Dict[str, int] = {
            ScreeningVerdict.ALLOW.value: 0,
            ScreeningVerdict.MONITOR.value: 0,
            ScreeningVerdict.SUSPICIOUS.value: 0,
            ScreeningVerdict.BLOCK.value: 0,
        }

    def screen_url(self, url: str) -> ScreeningResult:
        """
        Screen a URL or domain string.

        Args:
            url: Target URL or domain string.

        Returns:
            ScreeningResult decision.
        """
        result = self.url_screener.screen(url)
        self._record_result(result)
        return result

    def screen_file(self, file_path_or_name: str) -> ScreeningResult:
        """
        Screen a file path or filename.

        Args:
            file_path_or_name: Target path or filename string.

        Returns:
            ScreeningResult decision.
        """
        result = self.file_screener.screen(file_path_or_name)
        self._record_result(result)
        return result

    def screen(self, target: Any, target_type: Union[str, TargetType]) -> ScreeningResult:
        """
        Generic screening dispatcher supporting both URL and FILE targets.

        Args:
            target: Target string (URL, path, filename).
            target_type: TargetType enum or string ("url", "file", "domain").

        Returns:
            ScreeningResult decision.
        """
        normalized_type = TargetType.from_str(target_type)

        if normalized_type in (TargetType.URL, TargetType.DOMAIN):
            return self.screen_url(str(target) if target is not None else "")
        elif normalized_type == TargetType.FILE:
            return self.screen_file(str(target) if target is not None else "")
        else:
            # Handle invalid / unsupported target types gracefully
            type_str = str(target_type) if target_type is not None else "None"
            result = ScreeningResult(
                target=str(target) if target is not None else "",
                target_type=TargetType.UNKNOWN.value,
                verdict=ScreeningVerdict.BLOCK,
                risk_score=0.80,
                reasons=[f"Unsupported or invalid target type '{type_str}' for Gatekeeper screening"],
                metadata={"error": "unsupported_target_type", "provided_type": type_str},
            )
            self._record_result(result)
            return result

    def get_recent_results(self, limit: Optional[int] = None) -> List[ScreeningResult]:
        """
        Retrieve recent screening results in chronological order.

        Args:
            limit: Maximum number of recent results to return. If None, returns all history.

        Returns:
            List of ScreeningResult objects.
        """
        with self._lock:
            history_list = list(self._history)
            if limit is not None and limit > 0:
                return history_list[-limit:]
            return history_list

    def get_status(self) -> Dict[str, Any]:
        """
        Retrieve operational status, history size, and cumulative screening statistics.

        Returns:
            Dictionary containing status telemetry and verdict distribution.
        """
        with self._lock:
            return {
                "agent_name": "GatekeeperAgent",
                "status": "active",
                "total_screenings": self._total_screenings,
                "verdict_counts": dict(self._verdict_counts),
                "history_size": len(self._history),
                "max_history_size": self.max_history,
                "policy_thresholds": {
                    "allow_threshold": self.policy.allow_threshold,
                    "monitor_threshold": self.policy.monitor_threshold,
                    "suspicious_threshold": self.policy.suspicious_threshold,
                    "block_threshold": self.policy.block_threshold,
                },
            }

    def clear_history(self) -> None:
        """Clear recorded history and reset screening counters."""
        with self._lock:
            self._history.clear()
            self._total_screenings = 0
            for k in self._verdict_counts:
                self._verdict_counts[k] = 0

    def _record_result(self, result: ScreeningResult) -> None:
        """Thread-safe recording of screening results and metric counters."""
        with self._lock:
            self._history.append(result)
            self._total_screenings += 1
            verdict_key = result.verdict.value if isinstance(result.verdict, ScreeningVerdict) else str(result.verdict)
            if verdict_key in self._verdict_counts:
                self._verdict_counts[verdict_key] += 1
            else:
                self._verdict_counts[verdict_key] = 1
