"""
Unit tests for TRINETRA Gatekeeper Agent:
- Step 1: Models & Policies
- Step 2: URL & Domain Screening
- Step 3: File & Filename Screening
- Step 4: GatekeeperAgent Unified Orchestrator
"""

import json
import threading
import pytest

from gatekeeper.file_screening import (
    FileScreener,
    screen_file,
)
from gatekeeper.gatekeeper import (
    GatekeeperAgent,
)
from gatekeeper.models import ScreeningResult, ScreeningVerdict, TargetType
from gatekeeper.policies import (
    DEFAULT_RISK_POLICY,
    RiskPolicy,
    evaluate_risk_score,
)
from gatekeeper.url_screening import (
    URLScreener,
    screen_url,
)


class TestScreeningVerdict:
    """Tests for ScreeningVerdict enumeration."""

    def test_verdict_enum_values(self):
        assert ScreeningVerdict.ALLOW.value == "ALLOW"
        assert ScreeningVerdict.MONITOR.value == "MONITOR"
        assert ScreeningVerdict.SUSPICIOUS.value == "SUSPICIOUS"
        assert ScreeningVerdict.BLOCK.value == "BLOCK"

    def test_verdict_from_str_valid(self):
        assert ScreeningVerdict.from_str("ALLOW") == ScreeningVerdict.ALLOW
        assert ScreeningVerdict.from_str("allow") == ScreeningVerdict.ALLOW
        assert ScreeningVerdict.from_str("Monitor") == ScreeningVerdict.MONITOR
        assert ScreeningVerdict.from_str("SUSPICIOUS") == ScreeningVerdict.SUSPICIOUS
        assert ScreeningVerdict.from_str("block") == ScreeningVerdict.BLOCK

    def test_verdict_from_str_existing_enum(self):
        assert ScreeningVerdict.from_str(ScreeningVerdict.BLOCK) == ScreeningVerdict.BLOCK

    def test_verdict_from_str_invalid_and_empty(self):
        assert ScreeningVerdict.from_str("invalid_verdict") == ScreeningVerdict.SUSPICIOUS
        assert ScreeningVerdict.from_str("") == ScreeningVerdict.SUSPICIOUS
        assert ScreeningVerdict.from_str(None) == ScreeningVerdict.SUSPICIOUS  # type: ignore


class TestTargetType:
    """Tests for TargetType enumeration."""

    def test_target_type_values(self):
        assert TargetType.URL.value == "url"
        assert TargetType.FILE.value == "file"
        assert TargetType.DOMAIN.value == "domain"
        assert TargetType.UNKNOWN.value == "unknown"

    def test_target_type_from_str(self):
        assert TargetType.from_str("URL") == TargetType.URL
        assert TargetType.from_str("file") == TargetType.FILE
        assert TargetType.from_str("Domain") == TargetType.DOMAIN
        assert TargetType.from_str("other") == TargetType.UNKNOWN
        assert TargetType.from_str(TargetType.FILE) == TargetType.FILE


class TestScreeningResult:
    """Tests for ScreeningResult schema and serialization."""

    def test_screening_result_creation_defaults(self):
        res = ScreeningResult(
            target="normal_report.pdf",
            target_type="file",
            verdict=ScreeningVerdict.ALLOW,
            risk_score=0.05,
            reasons=["Clean file extension"],
        )
        assert res.target == "normal_report.pdf"
        assert res.target_type == "file"
        assert res.verdict == ScreeningVerdict.ALLOW
        assert res.risk_score == 0.05
        assert res.reasons == ["Clean file extension"]
        assert res.is_allowed is True
        assert res.is_blocked is False
        assert res.is_suspicious is False
        assert res.is_monitored is False
        assert res.timestamp is not None

    def test_screening_result_risk_clamping(self):
        # Risk score > 1.0 clamped to 1.0
        res_high = ScreeningResult(target="malicious.exe", risk_score=1.85)
        assert res_high.risk_score == 1.0

        # Risk score < 0.0 clamped to 0.0
        res_low = ScreeningResult(target="safe.txt", risk_score=-0.5)
        assert res_low.risk_score == 0.0

    def test_screening_result_status_properties(self):
        allow_res = ScreeningResult(target="test", verdict=ScreeningVerdict.ALLOW)
        monitor_res = ScreeningResult(target="test", verdict=ScreeningVerdict.MONITOR)
        suspicious_res = ScreeningResult(target="test", verdict=ScreeningVerdict.SUSPICIOUS)
        block_res = ScreeningResult(target="test", verdict=ScreeningVerdict.BLOCK)

        assert allow_res.is_allowed is True
        assert monitor_res.is_monitored is True
        assert suspicious_res.is_suspicious is True
        assert block_res.is_blocked is True

    def test_screening_result_dict_serialization(self):
        res = ScreeningResult(
            target="invoice.pdf.exe",
            target_type="file",
            verdict=ScreeningVerdict.BLOCK,
            risk_score=0.95,
            reasons=["Double extension detected", "Dangerous executable extension: .exe"],
            metadata={"primary_extension": ".exe", "inner_extension": ".pdf"},
        )
        d = res.to_dict()
        assert d["target"] == "invoice.pdf.exe"
        assert d["target_type"] == "file"
        assert d["verdict"] == "BLOCK"
        assert d["risk_score"] == 0.95
        assert len(d["reasons"]) == 2
        assert d["metadata"]["primary_extension"] == ".exe"

        # Reconstruct from dict
        restored = ScreeningResult.from_dict(d)
        assert restored.target == res.target
        assert restored.verdict == ScreeningVerdict.BLOCK
        assert restored.risk_score == res.risk_score
        assert restored.reasons == res.reasons
        assert restored.metadata == res.metadata

    def test_screening_result_json_serialization(self):
        res = ScreeningResult(
            target="http://192.168.1.10/login",
            target_type="url",
            verdict=ScreeningVerdict.SUSPICIOUS,
            risk_score=0.75,
            reasons=["IP address used instead of domain", "Suspicious keyword 'login' in path"],
            metadata={"hostname": "192.168.1.10", "is_raw_ip": True},
        )
        json_str = res.to_json(indent=2)
        assert isinstance(json_str, str)
        parsed = json.loads(json_str)
        assert parsed["target"] == "http://192.168.1.10/login"
        assert parsed["verdict"] == "SUSPICIOUS"
        assert parsed["metadata"]["is_raw_ip"] is True

        # Reconstruct from JSON
        restored = ScreeningResult.from_json(json_str)
        assert restored.target == res.target
        assert restored.verdict == ScreeningVerdict.SUSPICIOUS
        assert restored.risk_score == 0.75
        assert restored.metadata["hostname"] == "192.168.1.10"


class TestRiskPolicy:
    """Tests for RiskPolicy configurable thresholds and verdict evaluation."""

    def test_default_policy_thresholds(self):
        policy = DEFAULT_RISK_POLICY
        assert policy.allow_threshold == 0.29
        assert policy.monitor_threshold == 0.59
        assert policy.suspicious_threshold == 0.79
        assert policy.block_threshold == 0.80

    def test_default_policy_verdict_evaluations(self):
        policy = DEFAULT_RISK_POLICY

        # ALLOW: 0.00 – 0.29
        assert policy.evaluate_verdict(0.00) == ScreeningVerdict.ALLOW
        assert policy.evaluate_verdict(0.15) == ScreeningVerdict.ALLOW
        assert policy.evaluate_verdict(0.29) == ScreeningVerdict.ALLOW

        # MONITOR: 0.30 – 0.59
        assert policy.evaluate_verdict(0.30) == ScreeningVerdict.MONITOR
        assert policy.evaluate_verdict(0.45) == ScreeningVerdict.MONITOR
        assert policy.evaluate_verdict(0.59) == ScreeningVerdict.MONITOR

        # SUSPICIOUS: 0.60 – 0.79
        assert policy.evaluate_verdict(0.60) == ScreeningVerdict.SUSPICIOUS
        assert policy.evaluate_verdict(0.70) == ScreeningVerdict.SUSPICIOUS
        assert policy.evaluate_verdict(0.79) == ScreeningVerdict.SUSPICIOUS

        # BLOCK: 0.80 – 1.00
        assert policy.evaluate_verdict(0.80) == ScreeningVerdict.BLOCK
        assert policy.evaluate_verdict(0.95) == ScreeningVerdict.BLOCK
        assert policy.evaluate_verdict(1.00) == ScreeningVerdict.BLOCK

    def test_out_of_bounds_clamping(self):
        policy = DEFAULT_RISK_POLICY
        # Below 0.0 clamped to 0.0 -> ALLOW
        assert policy.evaluate_verdict(-0.2) == ScreeningVerdict.ALLOW
        # Above 1.0 clamped to 1.0 -> BLOCK
        assert policy.evaluate_verdict(1.5) == ScreeningVerdict.BLOCK

    def test_custom_risk_policy(self):
        # Stricter policy where anything above 0.5 is BLOCK
        strict_policy = RiskPolicy(
            allow_threshold=0.10,
            monitor_threshold=0.30,
            suspicious_threshold=0.50,
            block_threshold=0.51,
        )
        assert strict_policy.evaluate_verdict(0.05) == ScreeningVerdict.ALLOW
        assert strict_policy.evaluate_verdict(0.20) == ScreeningVerdict.MONITOR
        assert strict_policy.evaluate_verdict(0.40) == ScreeningVerdict.SUSPICIOUS
        assert strict_policy.evaluate_verdict(0.55) == ScreeningVerdict.BLOCK

    def test_invalid_policy_threshold_raises_error(self):
        with pytest.raises(ValueError):
            # Invalid order: allow_threshold > monitor_threshold
            RiskPolicy(allow_threshold=0.70, monitor_threshold=0.50)

    def test_policy_to_and_from_dict(self):
        policy = RiskPolicy(
            allow_threshold=0.20,
            monitor_threshold=0.50,
            suspicious_threshold=0.70,
            url_allowlist=["trusted.com"],
        )
        data = policy.to_dict()
        assert data["allow_threshold"] == 0.20
        assert "trusted.com" in data["url_allowlist"]

        restored = RiskPolicy.from_dict(data)
        assert restored.allow_threshold == 0.20
        assert restored.url_allowlist == ["trusted.com"]

    def test_evaluate_risk_score_helper(self):
        assert evaluate_risk_score(0.10) == ScreeningVerdict.ALLOW
        assert evaluate_risk_score(0.40) == ScreeningVerdict.MONITOR
        assert evaluate_risk_score(0.65) == ScreeningVerdict.SUSPICIOUS
        assert evaluate_risk_score(0.90) == ScreeningVerdict.BLOCK

        # With custom policy
        custom_policy = RiskPolicy(allow_threshold=0.05, monitor_threshold=0.10, suspicious_threshold=0.20)
        assert evaluate_risk_score(0.25, policy=custom_policy) == ScreeningVerdict.BLOCK


class TestURLScreening:
    """Tests for URLScreener defensive screening and heuristic rule analysis."""

    def test_safe_normal_url(self):
        result = screen_url("https://example.com/about/company")
        assert result.verdict == ScreeningVerdict.ALLOW
        assert result.risk_score == 0.0
        assert result.target_type == "url"
        assert len(result.reasons) > 0
        assert "standard structure" in result.reasons[0].lower() or "no suspicious" in result.reasons[0].lower()

    def test_empty_or_none_url(self):
        result = screen_url("")
        assert result.verdict == ScreeningVerdict.BLOCK
        assert result.risk_score >= 0.80
        assert "empty or invalid" in result.reasons[0].lower()

    def test_malformed_url(self):
        result = screen_url("http://invalid host with spaces.com")
        assert result.verdict == ScreeningVerdict.BLOCK
        assert result.risk_score >= 0.80
        assert "malformed" in result.reasons[0].lower()

    def test_raw_ip_address_ipv4(self):
        result = screen_url("http://192.168.1.10/dashboard")
        assert result.verdict == ScreeningVerdict.SUSPICIOUS
        assert result.risk_score >= 0.60
        assert any("raw ipv4" in r.lower() for r in result.reasons)
        assert result.metadata["is_raw_ip"] is True

    def test_raw_ip_address_ipv6(self):
        result = screen_url("http://[2001:db8::1]/status")
        assert result.verdict == ScreeningVerdict.SUSPICIOUS
        assert result.risk_score >= 0.60
        assert any("raw ipv6" in r.lower() for r in result.reasons)
        assert result.metadata["is_raw_ip"] is True

    def test_suspicious_phishing_keywords(self):
        result = screen_url("https://safe-domain.org/account/verify/update")
        # Matches 'account', 'verify', 'update' -> 3 * 0.20 = 0.60 -> SUSPICIOUS
        assert result.verdict in (ScreeningVerdict.SUSPICIOUS, ScreeningVerdict.BLOCK)
        assert result.risk_score >= 0.60
        assert any("keyword" in r.lower() for r in result.reasons)
        assert "account" in result.metadata["matched_keywords"]
        assert "verify" in result.metadata["matched_keywords"]
        assert "update" in result.metadata["matched_keywords"]

    def test_impersonation_domain_with_keywords_and_hyphens(self):
        result = screen_url("http://paypal-security-verify.example")
        # Keywords: 'security', 'verify' (0.40) + hyphens (0.25) = 0.65 -> SUSPICIOUS
        assert result.verdict == ScreeningVerdict.SUSPICIOUS
        assert result.risk_score >= 0.60
        assert any("hyphen" in r.lower() or "keyword" in r.lower() for r in result.reasons)

    def test_excessive_subdomains(self):
        result = screen_url("https://a.b.c.d.e.targetsite.com/home")
        assert result.verdict in (ScreeningVerdict.MONITOR, ScreeningVerdict.SUSPICIOUS)
        assert any("excessive subdomains" in r.lower() for r in result.reasons)
        assert result.metadata["subdomain_count"] >= 3

    def test_at_symbol_credential_deception(self):
        result = screen_url("http://google.com@evil-phish-domain.com/login")
        assert result.verdict == ScreeningVerdict.BLOCK
        assert result.risk_score >= 0.80
        assert any("@" in r for r in result.reasons)
        assert result.metadata["has_at_symbol"] is True

    def test_non_standard_port(self):
        result = screen_url("http://example.com:1337/api/test")
        assert result.risk_score >= 0.15
        assert any("port" in r.lower() for r in result.reasons)
        assert result.metadata["port"] == 1337

    def test_dangerous_uri_scheme(self):
        result = screen_url("javascript:alert(1)")
        assert result.verdict == ScreeningVerdict.BLOCK
        assert result.risk_score >= 0.80
        assert any("scheme" in r.lower() for r in result.reasons)

    def test_allowlist_matching(self):
        custom_policy = RiskPolicy(
            domain_allowlist=["trusted-partner.com"],
            url_allowlist=["http://192.168.1.50/internal-login"],
        )
        screener = URLScreener(policy=custom_policy)

        # Domain allowlist match (even with suspicious keyword)
        res1 = screener.screen("https://subdomain.trusted-partner.com/verify/login")
        assert res1.verdict == ScreeningVerdict.ALLOW
        assert res1.risk_score == 0.0
        assert "allowlist" in res1.reasons[0].lower()

        # Exact URL allowlist match (even on raw IP)
        res2 = screener.screen("http://192.168.1.50/internal-login")
        assert res2.verdict == ScreeningVerdict.ALLOW
        assert res2.risk_score == 0.0
        assert "allowlist" in res2.reasons[0].lower()

    def test_blocklist_matching(self):
        custom_policy = RiskPolicy(
            domain_blocklist=["known-phish.net"],
            url_blocklist=["https://innocent-looking.com/bad/payload"],
        )
        screener = URLScreener(policy=custom_policy)

        # Domain blocklist match
        res1 = screener.screen("https://known-phish.net/anything")
        assert res1.verdict == ScreeningVerdict.BLOCK
        assert res1.risk_score == 1.0
        assert "blocklist" in res1.reasons[0].lower()

        # URL blocklist match
        res2 = screener.screen("https://innocent-looking.com/bad/payload")
        assert res2.verdict == ScreeningVerdict.BLOCK
        assert res2.risk_score == 1.0
        assert "blocklist" in res2.reasons[0].lower()

    def test_multiple_suspicious_indicators_combined(self):
        # Raw IP (0.65) + keyword login (0.20) + keyword secure (0.20) = 1.0 (capped)
        result = screen_url("http://192.168.1.10/secure/login")
        assert result.verdict == ScreeningVerdict.BLOCK
        assert result.risk_score >= 0.80
        assert len(result.reasons) >= 2
        assert any("raw ipv4" in r.lower() for r in result.reasons)
        assert any("keyword" in r.lower() for r in result.reasons)


class TestFileScreening:
    """Tests for FileScreener defensive filename and metadata screening."""

    def test_normal_safe_files(self):
        for name in ["normal_report.pdf", "photo.jpg", "notes.txt", "data.csv", "presentation.pptx"]:
            res = screen_file(name)
            assert res.verdict == ScreeningVerdict.ALLOW
            assert res.risk_score <= 0.10
            assert res.target_type == "file"
            assert res.is_allowed is True
            assert res.metadata["is_allowed_extension"] is True

    def test_dangerous_executable_extensions(self):
        dangerous_samples = [
            ("malware.exe", ".exe"),
            ("payload.scr", ".scr"),
            ("installer.msi", ".msi"),
            ("script.bat", ".bat"),
            ("command.cmd", ".cmd"),
            ("automation.ps1", ".ps1"),
            ("macro.vbs", ".vbs"),
            ("trojan.jar", ".jar"),
            ("driver.pif", ".pif"),
        ]
        for fname, ext in dangerous_samples:
            res = screen_file(fname)
            assert res.verdict == ScreeningVerdict.BLOCK
            assert res.risk_score >= 0.80
            assert res.is_blocked is True
            assert any("dangerous executable" in r.lower() for r in res.reasons)
            assert res.metadata["primary_extension"] == ext

    def test_double_extension_detection(self):
        double_ext_samples = [
            ("invoice.pdf.exe", ".pdf", ".exe"),
            ("photo.jpg.scr", ".jpg", ".scr"),
            ("document.docx.exe", ".docx", ".exe"),
            ("archive.zip.js", ".zip", ".js"),
            ("spreadsheet.xlsx.vbs", ".xlsx", ".vbs"),
        ]
        for fname, inner, primary in double_ext_samples:
            res = screen_file(fname)
            assert res.verdict == ScreeningVerdict.BLOCK
            assert res.risk_score >= 0.80
            assert res.metadata["is_double_extension"] is True
            assert res.metadata["inner_extension"] == inner
            assert res.metadata["primary_extension"] == primary
            assert any("double extension detected" in r.lower() for r in res.reasons)

    def test_suspicious_keywords_on_benign_file(self):
        # Benign extension with keywords: slight increment (e.g. 0.08) but still ALLOW
        res = screen_file("invoice.pdf")
        assert res.verdict == ScreeningVerdict.ALLOW
        assert res.risk_score <= 0.20
        assert "invoice" in res.metadata["matched_keywords"]
        assert any("keyword" in r.lower() for r in res.reasons)

        res2 = screen_file("urgent_payment_receipt.txt")
        assert res2.verdict == ScreeningVerdict.ALLOW
        assert res2.risk_score <= 0.29
        assert "urgent" in res2.metadata["matched_keywords"]
        assert "payment" in res2.metadata["matched_keywords"]

    def test_suspicious_keywords_on_dangerous_file(self):
        # Dangerous extension + suspicious keywords: compound risk to 1.0 (BLOCK)
        res = screen_file("urgent_payment.bat")
        assert res.verdict == ScreeningVerdict.BLOCK
        assert res.risk_score >= 0.90
        assert any("dangerous executable" in r.lower() for r in res.reasons)
        assert any("keyword" in r.lower() for r in res.reasons)

    def test_hidden_executable_file(self):
        res = screen_file(".hidden_miner.exe")
        assert res.verdict == ScreeningVerdict.BLOCK
        assert res.risk_score >= 0.80
        assert res.metadata["is_hidden"] is True
        assert any("hidden executable" in r.lower() for r in res.reasons)

    def test_hidden_benign_file(self):
        res = screen_file(".gitignore")
        assert res.verdict == ScreeningVerdict.ALLOW
        assert res.risk_score <= 0.20
        assert res.metadata["is_hidden"] is True

    def test_excessive_dots_obfuscation(self):
        res = screen_file("document...pdf.exe")
        assert res.verdict == ScreeningVerdict.BLOCK
        assert res.risk_score >= 0.80
        assert res.metadata["has_excessive_dots"] is True
        assert any("excessive or consecutive dot" in r.lower() for r in res.reasons)

    def test_whitespace_padding_before_extension(self):
        res = screen_file("invoice.pdf   .exe")
        assert res.verdict == ScreeningVerdict.BLOCK
        assert res.risk_score >= 0.80
        assert res.metadata["has_whitespace_padding"] is True
        assert any("whitespace padding" in r.lower() for r in res.reasons)

    def test_unicode_rtlo_spoofing(self):
        # RTLO char (\u202e) flips display of "invoice[RTLO]exe.pdf" to look like a pdf
        spoofed_name = "invoice\u202edoc.exe"
        res = screen_file(spoofed_name)
        assert res.verdict == ScreeningVerdict.BLOCK
        assert res.risk_score >= 0.80
        assert res.metadata["has_unicode_spoofing"] is True
        assert any("rtlo" in r.lower() or "unicode" in r.lower() for r in res.reasons)

    def test_null_byte_control_char(self):
        res = screen_file("safe_file\x00.exe")
        assert res.verdict == ScreeningVerdict.BLOCK
        assert res.metadata["has_unicode_spoofing"] is True

    def test_empty_and_whitespace_filename(self):
        res_empty = screen_file("")
        assert res_empty.verdict == ScreeningVerdict.BLOCK
        assert res_empty.risk_score >= 0.80
        assert "empty or invalid" in res_empty.reasons[0].lower()

        res_none = screen_file(None)  # type: ignore
        assert res_none.verdict == ScreeningVerdict.BLOCK

    def test_windows_and_posix_paths(self):
        win_res = screen_file("C:\\Users\\Victim\\Downloads\\invoice.pdf.exe")
        assert win_res.verdict == ScreeningVerdict.BLOCK
        assert win_res.metadata["extracted_filename"] == "invoice.pdf.exe"
        assert win_res.metadata["is_double_extension"] is True

        posix_res = screen_file("/var/uploads/incoming/photo.jpg.scr")
        assert posix_res.verdict == ScreeningVerdict.BLOCK
        assert posix_res.metadata["extracted_filename"] == "photo.jpg.scr"
        assert posix_res.metadata["is_double_extension"] is True

    def test_custom_risk_policy_file_screening(self):
        # Custom policy where .custom_risk is dangerous and .pdf is disallowed
        custom_policy = RiskPolicy(
            dangerous_extensions=[".custom_risk"],
            allowed_extensions=[".custom_safe"],
        )
        screener = FileScreener(policy=custom_policy)

        res_custom_bad = screener.screen("test.custom_risk")
        assert res_custom_bad.verdict == ScreeningVerdict.BLOCK

        res_custom_good = screener.screen("test.custom_safe")
        assert res_custom_good.verdict == ScreeningVerdict.ALLOW


class TestGatekeeperAgent:
    """Tests for GatekeeperAgent unified orchestrator."""

    def test_agent_initialization_defaults(self):
        agent = GatekeeperAgent()
        assert agent.max_history == 1000
        assert agent.policy is not None
        assert agent.url_screener is not None
        assert agent.file_screener is not None
        status = agent.get_status()
        assert status["total_screenings"] == 0
        assert status["history_size"] == 0

    def test_agent_initialization_custom_policy_and_kwargs(self):
        custom_policy = RiskPolicy(allow_threshold=0.15)
        agent = GatekeeperAgent(
            policy=custom_policy,
            max_history=50,
            url_allowlist=["trusted-partner.com"],
            dangerous_extensions=[".custom_danger"],
        )
        assert agent.max_history == 50
        assert agent.policy.allow_threshold == 0.15
        assert "trusted-partner.com" in agent.policy.url_allowlist
        assert ".custom_danger" in agent.policy.dangerous_extensions

    def test_agent_screen_url_safe(self):
        agent = GatekeeperAgent()
        result = agent.screen_url("https://example.com/about")
        assert isinstance(result, ScreeningResult)
        assert result.verdict == ScreeningVerdict.ALLOW
        assert result.risk_score == 0.0
        assert result.target_type == "url"

    def test_agent_screen_url_suspicious(self):
        agent = GatekeeperAgent()
        result = agent.screen_url("http://192.168.1.10/login")
        assert isinstance(result, ScreeningResult)
        assert result.verdict in (ScreeningVerdict.SUSPICIOUS, ScreeningVerdict.BLOCK)
        assert result.risk_score >= 0.60
        assert result.target_type == "url"

    def test_agent_screen_file_safe(self):
        agent = GatekeeperAgent()
        result = agent.screen_file("monthly_report.pdf")
        assert isinstance(result, ScreeningResult)
        assert result.verdict == ScreeningVerdict.ALLOW
        assert result.risk_score <= 0.10
        assert result.target_type == "file"

    def test_agent_screen_file_suspicious(self):
        agent = GatekeeperAgent()
        result = agent.screen_file("invoice.pdf.exe")
        assert isinstance(result, ScreeningResult)
        assert result.verdict == ScreeningVerdict.BLOCK
        assert result.risk_score >= 0.80
        assert result.target_type == "file"

    def test_agent_generic_screen_with_target_type_enum(self):
        agent = GatekeeperAgent()
        res_url = agent.screen("https://safe.org", TargetType.URL)
        assert res_url.target_type == "url"
        assert res_url.verdict == ScreeningVerdict.ALLOW

        res_file = agent.screen("data.docx", TargetType.FILE)
        assert res_file.target_type == "file"
        assert res_file.verdict == ScreeningVerdict.ALLOW

    def test_agent_generic_screen_with_string_type(self):
        agent = GatekeeperAgent()
        res_url = agent.screen("https://safe.org", "url")
        assert res_url.target_type == "url"
        assert res_url.verdict == ScreeningVerdict.ALLOW

        res_file = agent.screen("photo.png", "file")
        assert res_file.target_type == "file"
        assert res_file.verdict == ScreeningVerdict.ALLOW

        # Case insensitive
        res_file_upper = agent.screen("photo.png", "FILE")
        assert res_file_upper.target_type == "file"

    def test_agent_generic_screen_unsupported_type(self):
        agent = GatekeeperAgent()
        result = agent.screen("some_payload", "unsupported_device_type")
        assert isinstance(result, ScreeningResult)
        assert result.verdict == ScreeningVerdict.BLOCK
        assert result.target_type == TargetType.UNKNOWN.value
        assert any("unsupported" in r.lower() for r in result.reasons)

    def test_agent_empty_and_none_targets(self):
        agent = GatekeeperAgent()
        res1 = agent.screen_url(None)  # type: ignore
        assert res1.verdict == ScreeningVerdict.BLOCK

        res2 = agent.screen_file(None)  # type: ignore
        assert res2.verdict == ScreeningVerdict.BLOCK

        res3 = agent.screen(None, TargetType.FILE)
        assert res3.verdict == ScreeningVerdict.BLOCK

    def test_agent_history_tracking_and_limit(self):
        agent = GatekeeperAgent(max_history=10)
        agent.screen_url("https://site1.com")
        agent.screen_file("file1.pdf")
        agent.screen_url("http://192.168.1.1/login")

        history = agent.get_recent_results()
        assert len(history) == 3
        assert history[0].target == "https://site1.com"
        assert history[1].target == "file1.pdf"
        assert history[2].target == "http://192.168.1.1/login"

        # Test limit argument
        recent_2 = agent.get_recent_results(limit=2)
        assert len(recent_2) == 2
        assert recent_2[0].target == "file1.pdf"
        assert recent_2[1].target == "http://192.168.1.1/login"

    def test_agent_max_history_enforcement(self):
        agent = GatekeeperAgent(max_history=5)
        for i in range(12):
            agent.screen_file(f"doc_{i}.pdf")

        history = agent.get_recent_results()
        assert len(history) == 5
        # The oldest 7 were evicted; 7 through 11 remain
        assert history[0].target == "doc_7.pdf"
        assert history[-1].target == "doc_11.pdf"

    def test_agent_status_and_statistics(self):
        agent = GatekeeperAgent()
        agent.screen_url("https://safe.org")                  # ALLOW
        agent.screen_file("report.docx")                     # ALLOW
        agent.screen_url("http://paypal-security-verify.example") # SUSPICIOUS
        agent.screen_file("invoice.pdf.exe")                 # BLOCK

        status = agent.get_status()
        assert status["total_screenings"] == 4
        assert status["history_size"] == 4
        assert status["verdict_counts"]["ALLOW"] == 2
        assert status["verdict_counts"]["SUSPICIOUS"] == 1
        assert status["verdict_counts"]["BLOCK"] == 1

        agent.clear_history()
        status_after = agent.get_status()
        assert status_after["total_screenings"] == 0
        assert status_after["history_size"] == 0
        assert status_after["verdict_counts"]["ALLOW"] == 0

    def test_agent_thread_safety(self):
        agent = GatekeeperAgent(max_history=500)
        errors = []

        def worker(worker_id: int):
            try:
                for i in range(20):
                    agent.screen_url(f"https://worker{worker_id}-site-{i}.org")
                    agent.screen_file(f"worker{worker_id}_file_{i}.pdf")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        status = agent.get_status()
        assert status["total_screenings"] == 200
        assert status["history_size"] == 200
