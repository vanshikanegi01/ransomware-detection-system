"""
Defensive URL and Domain Screening Module for TRINETRA Gatekeeper Agent.

Performs deterministic, rule-based, offline heuristic screening of URLs and
domains to detect suspicious indicators such as raw IP hosts, suspicious
keywords (phishing markers), excessive subdomains, malformed structures,
and allowlist/blocklist matches before requests or links are processed.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit, unquote

from gatekeeper.models import ScreeningResult, ScreeningVerdict, TargetType
from gatekeeper.policies import DEFAULT_RISK_POLICY, RiskPolicy


class URLScreener:
    """
    Offline heuristic analyzer for URL and domain screening.
    
    Evaluates risk based on explainable rule-based heuristics including:
    - Format and structure validity (malformed detection)
    - Host verification (raw IP detection)
    - Phishing and credential harvesting keyword detection
    - Subdomain hierarchy and domain structure anomalies
    - Policy allowlist and blocklist checks
    """

    def __init__(
        self,
        policy: Optional[RiskPolicy] = None,
        weight_raw_ip: float = 0.65,
        weight_keyword: float = 0.20,
        max_keyword_score: float = 0.60,
        weight_excessive_subdomains: float = 0.35,
        weight_at_symbol: float = 0.70,
        weight_hyphen_heavy: float = 0.25,
        weight_long_hostname: float = 0.20,
        weight_unusual_port: float = 0.15,
        max_subdomains_threshold: int = 3,
    ) -> None:
        """
        Initialize URLScreener with policy and configurable heuristic weights.

        Args:
            policy: Configured RiskPolicy instance. Uses DEFAULT_RISK_POLICY if None.
            weight_raw_ip: Risk increment when host is a raw IP address.
            weight_keyword: Risk increment per unique suspicious keyword matched.
            max_keyword_score: Maximum cumulative risk from keyword matches.
            weight_excessive_subdomains: Risk increment when subdomains exceed threshold.
            weight_at_symbol: Risk increment when '@' authority separator is present.
            weight_hyphen_heavy: Risk increment when hostname contains >= 2 hyphens.
            weight_long_hostname: Risk increment when hostname length > 50 characters.
            weight_unusual_port: Risk increment for non-standard ports.
            max_subdomains_threshold: Number of subdomains considered standard.
        """
        self.policy = policy or DEFAULT_RISK_POLICY
        self.weight_raw_ip = weight_raw_ip
        self.weight_keyword = weight_keyword
        self.max_keyword_score = max_keyword_score
        self.weight_excessive_subdomains = weight_excessive_subdomains
        self.weight_at_symbol = weight_at_symbol
        self.weight_hyphen_heavy = weight_hyphen_heavy
        self.weight_long_hostname = weight_long_hostname
        self.weight_unusual_port = weight_unusual_port
        self.max_subdomains_threshold = max_subdomains_threshold

    def screen(self, url: str) -> ScreeningResult:
        """
        Screen a URL or domain string against defensive heuristic rules.

        Args:
            url: Target URL or domain string to inspect.

        Returns:
            ScreeningResult with verdict, risk score, reasons, and metadata.
        """
        if not url or not isinstance(url, str) or not url.strip():
            return ScreeningResult(
                target=str(url),
                target_type=TargetType.URL.value,
                verdict=ScreeningVerdict.BLOCK,
                risk_score=0.90,
                reasons=["URL target is empty or invalid string"],
                metadata={"error": "empty_target"},
            )

        target = url.strip()
        reasons: List[str] = []
        metadata: Dict[str, Any] = {}
        risk_score: float = 0.0

        # 1. Parse URL safely
        parsed_data = self._safe_parse_url(target)
        if parsed_data.get("is_malformed"):
            return ScreeningResult(
                target=target,
                target_type=TargetType.URL.value,
                verdict=ScreeningVerdict.BLOCK,
                risk_score=0.85,
                reasons=[f"Malformed URL structure: {parsed_data.get('malform_reason', 'Unparseable URL')}"],
                metadata=parsed_data,
            )

        scheme = parsed_data.get("scheme", "")
        hostname = parsed_data.get("hostname", "")
        port = parsed_data.get("port")
        path = parsed_data.get("path", "")
        query = parsed_data.get("query", "")
        raw_netloc = parsed_data.get("raw_netloc", "")

        metadata.update({
            "scheme": scheme,
            "hostname": hostname,
            "port": port,
            "path": path,
            "query": query,
        })

        # 2. Check allowlist (Immediate ALLOW if matched)
        if self._is_allowlisted(target, hostname):
            return ScreeningResult(
                target=target,
                target_type=TargetType.URL.value,
                verdict=ScreeningVerdict.ALLOW,
                risk_score=0.0,
                reasons=["Target matches configured allowlist"],
                metadata=metadata,
            )

        # 3. Check blocklist (Immediate BLOCK if matched)
        if self._is_blocklisted(target, hostname):
            return ScreeningResult(
                target=target,
                target_type=TargetType.URL.value,
                verdict=ScreeningVerdict.BLOCK,
                risk_score=1.0,
                reasons=["Target matches configured blocklist"],
                metadata=metadata,
            )

        # 4. Check for high-risk schemes (e.g., javascript:, data:, vbscript:)
        if scheme in {"javascript", "data", "vbscript", "file"}:
            risk_score += 0.85
            reasons.append(f"Potentially dangerous URI scheme detected: '{scheme}:'")

        # 5. Check for '@' symbol in netloc/authority (credential phishing / redirect trick)
        if "@" in raw_netloc:
            risk_score += self.weight_at_symbol
            reasons.append("Contains '@' symbol in authority component (potential deceptive redirect/phishing marker)")
            metadata["has_at_symbol"] = True

        # 6. Check for Raw IP Address in Hostname
        is_raw_ip, ip_version = self._check_raw_ip(hostname)
        metadata["is_raw_ip"] = is_raw_ip
        if is_raw_ip:
            risk_score += self.weight_raw_ip
            reasons.append(f"Host uses raw IPv{ip_version} address instead of a domain name")

        # 7. Check Subdomain Structure (if not a raw IP)
        if not is_raw_ip and hostname:
            subdomain_count = self._count_subdomains(hostname)
            metadata["subdomain_count"] = subdomain_count
            if subdomain_count >= self.max_subdomains_threshold:
                risk_score += self.weight_excessive_subdomains
                reasons.append(
                    f"Excessive subdomains detected ({subdomain_count} subdomains; threshold is {self.max_subdomains_threshold})"
                )

        # 8. Check Suspicious Hostname Characteristics (Multiple hyphens, excessive length)
        if not is_raw_ip and hostname:
            hyphen_count = hostname.count("-")
            metadata["hyphen_count"] = hyphen_count
            if hyphen_count >= 2:
                risk_score += self.weight_hyphen_heavy
                reasons.append(f"Suspicious domain structure with multiple hyphens ({hyphen_count} hyphens)")

            if len(hostname) > 50:
                risk_score += self.weight_long_hostname
                reasons.append(f"Unusually long hostname ({len(hostname)} characters)")

        # 9. Check Non-Standard Port
        if port is not None and port not in (80, 443, 8080, 8443):
            risk_score += self.weight_unusual_port
            reasons.append(f"Non-standard service port specified: {port}")

        # 10. Check Suspicious Keywords (Phishing / Impersonation Heuristics)
        matched_keywords = self._find_suspicious_keywords(target, hostname, path, query)
        metadata["matched_keywords"] = matched_keywords
        if matched_keywords:
            kw_score = min(len(matched_keywords) * self.weight_keyword, self.max_keyword_score)
            risk_score += kw_score
            kw_list_str = ", ".join(f"'{k}'" for k in matched_keywords)
            reasons.append(f"Suspicious phishing/security keyword(s) detected: {kw_list_str}")

        # 11. Normalize and Finalize Risk Score & Verdict
        final_risk_score = round(max(0.0, min(1.0, risk_score)), 4)
        verdict = self.policy.evaluate_verdict(final_risk_score)

        if not reasons:
            reasons.append("No suspicious URL indicators detected; standard structure")

        return ScreeningResult(
            target=target,
            target_type=TargetType.URL.value,
            verdict=verdict,
            risk_score=final_risk_score,
            reasons=reasons,
            metadata=metadata,
        )

    def _safe_parse_url(self, url: str) -> Dict[str, Any]:
        """Safely parse URL string into components, handling schemeless URLs and formatting anomalies."""
        try:
            # Handle URLs without scheme for proper parsing
            url_to_parse = url
            has_explicit_scheme = "://" in url or (":" in url and not url.startswith("http"))
            if not has_explicit_scheme:
                url_to_parse = f"http://{url}"

            parsed = urlsplit(url_to_parse)

            # Check for invalid characters in host
            hostname = parsed.hostname or ""
            if not hostname and not parsed.path:
                return {"is_malformed": True, "malform_reason": "No valid hostname or path found"}

            # Basic hostname sanity check
            if hostname:
                # Hostname should not contain whitespace or unescaped control chars
                if any(c in hostname for c in " \t\r\n<>{}|^`"):
                    return {"is_malformed": True, "malform_reason": "Hostname contains invalid characters"}

            return {
                "is_malformed": False,
                "scheme": parsed.scheme.lower() if parsed.scheme else ("http" if not has_explicit_scheme else ""),
                "hostname": hostname.lower(),
                "port": parsed.port,
                "path": unquote(parsed.path or ""),
                "query": parsed.query or "",
                "raw_netloc": parsed.netloc or "",
            }
        except Exception as err:
            return {"is_malformed": True, "malform_reason": f"Parsing exception: {str(err)}"}

    def _check_raw_ip(self, hostname: str) -> Tuple[bool, Optional[int]]:
        """Check if hostname string is an IPv4 or IPv6 address."""
        if not hostname:
            return False, None
        
        # Remove brackets if IPv6
        clean_host = hostname.strip("[]")
        try:
            ip_obj = ipaddress.ip_address(clean_host)
            return True, ip_obj.version
        except ValueError:
            return False, None

    def _count_subdomains(self, hostname: str) -> int:
        """Calculate number of subdomain levels preceding the primary domain and TLD."""
        clean = hostname.rstrip(".")
        parts = clean.split(".")
        if len(parts) <= 2:
            return 0
        
        # Common two-part TLD handling (e.g. .co.uk, .com.au, .gov.in)
        second_level_tlds = {"co.uk", "gov.uk", "ac.uk", "org.uk", "com.au", "net.au", "gov.in", "co.in", "edu.in"}
        last_two = ".".join(parts[-2:])
        if last_two in second_level_tlds:
            domain_parts_count = 3
        else:
            domain_parts_count = 2

        subdomain_parts = len(parts) - domain_parts_count
        return max(0, subdomain_parts)

    def _find_suspicious_keywords(
        self, raw_url: str, hostname: str, path: str, query: str
    ) -> List[str]:
        """Detect presence of suspicious keywords in host, path, and query string."""
        keywords_to_check = set(self.policy.suspicious_keywords)
        matched: Set[str] = set()

        text_to_search = f"{hostname} {path} {query}".lower()

        # Tokenize host and path by standard delimiters (., -, _, /, ?, &, =)
        tokens = set(re.split(r"[\.\-_/\?&=%:\+]+", text_to_search))

        for kw in keywords_to_check:
            kw_clean = kw.strip().lower()
            if not kw_clean:
                continue

            # Exact token match or substring match in domain/path
            if kw_clean in tokens or kw_clean in text_to_search:
                matched.add(kw_clean)

        return sorted(list(matched))

    def _is_allowlisted(self, url: str, hostname: str) -> bool:
        """Check if URL or hostname matches allowlist entries."""
        url_lower = url.lower()
        host_lower = hostname.lower()

        # Check policy allowlists
        for item in self.policy.url_allowlist:
            if item.lower() in url_lower:
                return True

        for domain in self.policy.domain_allowlist:
            d_lower = domain.lower()
            if host_lower == d_lower or host_lower.endswith(f".{d_lower}"):
                return True

        return False

    def _is_blocklisted(self, url: str, hostname: str) -> bool:
        """Check if URL or hostname matches blocklist entries."""
        url_lower = url.lower()
        host_lower = hostname.lower()

        # Check policy blocklists
        for item in self.policy.url_blocklist:
            if item.lower() in url_lower:
                return True

        for domain in self.policy.domain_blocklist:
            d_lower = domain.lower()
            if host_lower == d_lower or host_lower.endswith(f".{d_lower}"):
                return True

        return False


def screen_url(url: str, policy: Optional[RiskPolicy] = None) -> ScreeningResult:
    """
    Screen a URL with the default or customized RiskPolicy.

    Args:
        url: URL string to screen.
        policy: Optional RiskPolicy. Uses DEFAULT_RISK_POLICY if None.

    Returns:
        ScreeningResult instance.
    """
    screener = URLScreener(policy=policy)
    return screener.screen(url)
