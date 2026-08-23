"""
Defensive File Screening Module for TRINETRA Gatekeeper Agent.

Performs deterministic, rule-based, offline metadata and filename-based screening
to detect dangerous executable extensions, double extensions, suspicious decoy
patterns, hidden executables, and deceptive character manipulations before files
reach the filesystem or downstream processes.

IMPORTANT SAFETY NOTICE:
This module operates exclusively on file metadata and string paths. It never
executes, opens for execution, or executes binary payloads.
"""

from __future__ import annotations

import os
import re
from pathlib import PurePath, PureWindowsPath
from typing import Any, Dict, List, Optional, Set, Tuple

from gatekeeper.models import ScreeningResult, ScreeningVerdict, TargetType
from gatekeeper.policies import DEFAULT_RISK_POLICY, RiskPolicy


# Common Unicode bidirectional formatting and spoofing control characters (e.g. RTLO)
SUSPICIOUS_CONTROL_CHARS = {
    "\u202e": "Right-to-Left Override (RTLO)",
    "\u202a": "Left-to-Right Embedding (LRE)",
    "\u202b": "Right-to-Left Embedding (RLE)",
    "\u202c": "Pop Directional Formatting (PDF)",
    "\u202d": "Left-to-Right Override (LTRO)",
    "\u200e": "Left-to-Right Mark (LRM)",
    "\u200f": "Right-to-Left Mark (RLM)",
    "\u061c": "Arabic Letter Mark (ALM)",
    "\x00": "Null Byte character",
}


class FileScreener:
    """
    Offline defensive analyzer for filename and path screening.
    
    Evaluates risk based on explainable rule-based heuristics:
    - Dangerous executable and script extension detection (.exe, .scr, .bat, .ps1, etc.)
    - Double extension masquerading (.pdf.exe, .jpg.scr, etc.)
    - Suspicious filename keywords (invoice, urgent, decrypt, locked, etc.)
    - Hidden executable detection (.hidden.exe)
    - Deceptive padding and excessive dot patterns (document...pdf.exe)
    - Unicode spoofing and RTLO character detection
    """

    def __init__(
        self,
        policy: Optional[RiskPolicy] = None,
        weight_dangerous_ext: float = 0.80,
        weight_double_ext: float = 0.90,
        weight_keyword: float = 0.08,
        weight_keyword_on_dangerous: float = 0.15,
        max_keyword_score: float = 0.24,
        weight_hidden_executable: float = 0.20,
        weight_excessive_dots: float = 0.20,
        weight_unicode_spoofing: float = 0.85,
        weight_whitespace_padding: float = 0.25,
    ) -> None:
        """
        Initialize FileScreener with policy and configurable heuristic weights.

        Args:
            policy: Configured RiskPolicy instance. Uses DEFAULT_RISK_POLICY if None.
            weight_dangerous_ext: Base risk for dangerous standalone extension.
            weight_double_ext: Base risk for double extension deception.
            weight_keyword: Risk per suspicious keyword in benign files.
            weight_keyword_on_dangerous: Risk per keyword when paired with risky extensions.
            max_keyword_score: Maximum cumulative risk contributed by keywords.
            weight_hidden_executable: Risk increment for hidden executable files.
            weight_excessive_dots: Risk increment for excessive/consecutive dot obfuscation.
            weight_unicode_spoofing: Risk increment for RTLO/control character spoofing.
            weight_whitespace_padding: Risk increment for deceptive space padding before extension.
        """
        self.policy = policy or DEFAULT_RISK_POLICY
        self.weight_dangerous_ext = weight_dangerous_ext
        self.weight_double_ext = weight_double_ext
        self.weight_keyword = weight_keyword
        self.weight_keyword_on_dangerous = weight_keyword_on_dangerous
        self.max_keyword_score = max_keyword_score
        self.weight_hidden_executable = weight_hidden_executable
        self.weight_excessive_dots = weight_excessive_dots
        self.weight_unicode_spoofing = weight_unicode_spoofing
        self.weight_whitespace_padding = weight_whitespace_padding

    def screen(self, file_path_or_name: str) -> ScreeningResult:
        """
        Screen a file name or file path against defensive heuristic rules.

        Args:
            file_path_or_name: Path or filename string to inspect.

        Returns:
            ScreeningResult with verdict, risk score, reasons, and metadata.
        """
        if not file_path_or_name or not isinstance(file_path_or_name, str) or not file_path_or_name.strip():
            return ScreeningResult(
                target=str(file_path_or_name),
                target_type=TargetType.FILE.value,
                verdict=ScreeningVerdict.BLOCK,
                risk_score=0.90,
                reasons=["Filename target is empty or invalid string"],
                metadata={"error": "empty_target"},
            )

        raw_target = file_path_or_name.strip()
        reasons: List[str] = []
        metadata: Dict[str, Any] = {}
        risk_score: float = 0.0

        # 1. Extract basename safely (handling both Windows and POSIX separators)
        filename = self._extract_filename(raw_target)
        metadata["extracted_filename"] = filename

        # 2. Check for suspicious Unicode / Control Character / RTLO Spoofing
        has_unicode_spoof, spoof_reasons = self._check_unicode_spoofing(filename)
        metadata["has_unicode_spoofing"] = has_unicode_spoof
        if has_unicode_spoof:
            risk_score += self.weight_unicode_spoofing
            reasons.extend(spoof_reasons)

        # 3. Check for Deceptive Whitespace Padding before extension (e.g. "invoice.pdf    .exe")
        if re.search(r"\.[a-zA-Z0-9]+\s+\.[a-zA-Z0-9]+", filename):
            risk_score += self.weight_whitespace_padding
            reasons.append("Deceptive whitespace padding detected before file extension")
            metadata["has_whitespace_padding"] = True

        # 4. Check for Excessive or Consecutive Dots (e.g. "document...pdf.exe")
        if ".." in filename or filename.count(".") >= 4:
            risk_score += self.weight_excessive_dots
            reasons.append(f"Excessive or consecutive dot obfuscation detected in filename ({filename.count('.')} dots)")
            metadata["has_excessive_dots"] = True

        # 5. Extract and Analyze Extensions
        ext_info = self._analyze_extensions(filename)
        primary_ext = ext_info["primary_extension"]
        inner_ext = ext_info["inner_extension"]
        is_double_ext = ext_info["is_double_extension"]
        is_dangerous = ext_info["is_dangerous"]
        is_hidden = ext_info["is_hidden"]

        metadata.update({
            "primary_extension": primary_ext,
            "inner_extension": inner_ext,
            "all_extensions": ext_info["all_extensions"],
            "is_double_extension": is_double_ext,
            "is_dangerous_extension": is_dangerous,
            "is_hidden": is_hidden,
        })

        # Heuristic 5a: Double Extension with Dangerous Final Extension
        if is_double_ext and is_dangerous:
            risk_score += self.weight_double_ext
            reasons.append(
                f"Double extension detected: decoy extension '{inner_ext}' masquerading with "
                f"dangerous executable extension '{primary_ext}'"
            )
        elif is_dangerous:
            # Heuristic 5b: Single Dangerous Executable Extension
            risk_score += self.weight_dangerous_ext
            reasons.append(f"Dangerous executable or script file extension: '{primary_ext}'")

        # Heuristic 5c: Hidden File / Hidden Executable
        if is_hidden:
            if is_dangerous:
                risk_score += self.weight_hidden_executable
                reasons.append(f"Hidden executable file detected (starts with dot): '{filename}'")
            else:
                metadata["is_hidden_config"] = True

        # 6. Check Suspicious Filename Keywords
        matched_keywords = self._find_suspicious_keywords(filename)
        metadata["matched_keywords"] = matched_keywords
        if matched_keywords:
            kw_weight = self.weight_keyword_on_dangerous if is_dangerous else self.weight_keyword
            max_kw = 0.30 if is_dangerous else self.max_keyword_score
            kw_contribution = min(len(matched_keywords) * kw_weight, max_kw)
            risk_score += kw_contribution
            kw_str = ", ".join(f"'{k}'" for k in matched_keywords)
            reasons.append(f"Suspicious filename keyword(s) detected: {kw_str}")

        # 7. Check Allowed Extension Clean Baseline
        is_allowed_format = primary_ext.lower() in [e.lower() for e in self.policy.allowed_extensions]
        metadata["is_allowed_extension"] = is_allowed_format

        # 8. Normalize Risk Score and Evaluate Verdict
        final_risk_score = round(max(0.0, min(1.0, risk_score)), 4)
        verdict = self.policy.evaluate_verdict(final_risk_score)

        if not reasons:
            if is_allowed_format:
                reasons.append(f"Clean standard file format ({primary_ext}); no suspicious indicators")
            else:
                reasons.append("Standard filename structure; no high-risk indicators detected")

        return ScreeningResult(
            target=raw_target,
            target_type=TargetType.FILE.value,
            verdict=verdict,
            risk_score=final_risk_score,
            reasons=reasons,
            metadata=metadata,
        )

    def _extract_filename(self, path_or_name: str) -> str:
        """Extract filename component handling Windows and POSIX path separators."""
        # Normalize slashes
        normalized = path_or_name.replace("/", "\\")
        base = PureWindowsPath(normalized).name
        if not base:
            base = os.path.basename(path_or_name.rstrip("/\\"))
        return base or path_or_name

    def _check_unicode_spoofing(self, filename: str) -> Tuple[bool, List[str]]:
        """Check for presence of RTLO and unprintable control characters."""
        reasons: List[str] = []
        has_spoof = False

        for char, char_name in SUSPICIOUS_CONTROL_CHARS.items():
            if char in filename:
                has_spoof = True
                reasons.append(f"Suspicious Unicode/control character detected ({char_name})")

        # Check for unprintable low-ASCII control characters (< 32, excluding tab/newline)
        if any(ord(c) < 32 and c not in "\t\n\r" for c in filename):
            if not has_spoof:
                has_spoof = True
                reasons.append("Unprintable ASCII control characters detected in filename")

        return has_spoof, reasons

    def _analyze_extensions(self, filename: str) -> Dict[str, Any]:
        """Analyze filename extension structure for double extensions and dangerous types."""
        clean_name = filename.strip()
        is_hidden = clean_name.startswith(".") and len(clean_name) > 1

        # Strip leading dot for hidden file tokenization
        name_for_split = clean_name[1:] if is_hidden else clean_name

        # Split tokens by dot
        raw_parts = name_for_split.split(".")
        parts = [p.strip() for p in raw_parts if p.strip()]

        normalized_dangerous = {ext.lower() for ext in self.policy.dangerous_extensions}
        normalized_double = {ext.lower() for ext in self.policy.suspicious_double_extensions}

        if not parts or len(parts) == 1:
            return {
                "primary_extension": "",
                "inner_extension": "",
                "all_extensions": [],
                "is_double_extension": False,
                "is_dangerous": False,
                "is_hidden": is_hidden,
            }

        primary_ext = f".{parts[-1].lower()}"
        all_exts = [f".{p.lower()}" for p in parts[1:]]

        is_dangerous = primary_ext in normalized_dangerous
        is_double_ext = False
        inner_ext = ""

        if len(parts) >= 3:
            candidate_inner = f".{parts[-2].lower()}"
            # A double extension occurs if the inner extension is a known decoy extension
            # or if the final extension is dangerous and an inner extension is present
            if candidate_inner in normalized_double or (is_dangerous and len(parts) >= 3):
                is_double_ext = True
                inner_ext = candidate_inner

        return {
            "primary_extension": primary_ext,
            "inner_extension": inner_ext,
            "all_extensions": all_exts,
            "is_double_extension": is_double_ext,
            "is_dangerous": is_dangerous,
            "is_hidden": is_hidden,
        }

    def _find_suspicious_keywords(self, filename: str) -> List[str]:
        """Detect presence of suspicious keywords in the filename stem."""
        keywords_to_check = set(self.policy.suspicious_keywords)
        matched: Set[str] = set()

        clean_lower = filename.lower()
        # Tokenize by common delimiters
        tokens = set(re.split(r"[_\-.\s\(\)\[\]]+", clean_lower))

        for kw in keywords_to_check:
            kw_clean = kw.strip().lower()
            if not kw_clean:
                continue

            if kw_clean in tokens or kw_clean in clean_lower:
                matched.add(kw_clean)

        return sorted(list(matched))


def screen_file(file_path_or_name: str, policy: Optional[RiskPolicy] = None) -> ScreeningResult:
    """
    Screen a file name or path with the default or customized RiskPolicy.

    Args:
        file_path_or_name: File path or name string to screen.
        policy: Optional RiskPolicy. Uses DEFAULT_RISK_POLICY if None.

    Returns:
        ScreeningResult instance.
    """
    screener = FileScreener(policy=policy)
    return screener.screen(file_path_or_name)
