import pytest
from pathlib import Path

from gatekeeper.gatekeeper import GatekeeperAgent
from gatekeeper.models import ScreeningVerdict
from simulator.ransomware_simulator import SafeRansomwareSimulator
from simulator.gatekeeper_adapter import SimulatorGatekeeperAdapter

def test_benign_input(tmp_path):
    # Setup
    simulator = SafeRansomwareSimulator(tmp_path / "sandbox")
    gatekeeper = GatekeeperAgent()
    adapter = SimulatorGatekeeperAdapter(simulator, gatekeeper)
    
    # Action
    test_file = simulator.create_dummy_workload(count=1)[0]
    original_content = test_file.read_bytes()
    results = adapter.evaluate_attack([test_file])
    result = results[0][1]
    
    # Assert
    assert result.verdict == ScreeningVerdict.ALLOW
    assert result.target == str(test_file)
    assert result.target_type == "file"
    assert result.risk_score <= 0.29
    
    # File should be modified by the simulator because it was allowed
    assert test_file.read_bytes() != original_content
    assert b"SIMULATED RANSOMWARE" in test_file.read_bytes()

def test_suspicious_input(tmp_path):
    # Setup
    simulator = SafeRansomwareSimulator(tmp_path / "sandbox")
    gatekeeper = GatekeeperAgent()
    adapter = SimulatorGatekeeperAdapter(simulator, gatekeeper)
    
    # Action
    # Create a filename that hits multiple heuristics to push score into SUSPICIOUS (0.60-0.79)
    test_file = tmp_path / "sandbox" / "urgent_invoice_payment....pdf   .pdf"
    test_file.write_text("Dummy content", encoding="utf-8")
    original_content = test_file.read_bytes()
    
    results = adapter.evaluate_attack([test_file])
    result = results[0][1]
    
    # Assert
    assert result.verdict == ScreeningVerdict.SUSPICIOUS
    assert result.risk_score > 0.59
    assert result.risk_score <= 0.79
    
    # File should be modified by the simulator because SUSPICIOUS does not block
    assert test_file.read_bytes() != original_content
    assert b"SIMULATED RANSOMWARE" in test_file.read_bytes()

def test_blocked_input(tmp_path):
    # Setup
    simulator = SafeRansomwareSimulator(tmp_path / "sandbox")
    gatekeeper = GatekeeperAgent()
    adapter = SimulatorGatekeeperAdapter(simulator, gatekeeper)
    
    # Action
    test_file = tmp_path / "sandbox" / "ransomware.exe"
    test_file.write_text("Dummy content", encoding="utf-8")
    original_content = test_file.read_bytes()
    
    results = adapter.evaluate_attack([test_file])
    result = results[0][1]
    
    # Assert
    assert result.verdict == ScreeningVerdict.BLOCK
    assert result.risk_score >= 0.80
    assert "Dangerous executable" in result.reasons[0]
    
    # File should NOT be modified because Gatekeeper blocked it
    assert test_file.read_bytes() == original_content
    assert b"SIMULATED RANSOMWARE" not in test_file.read_bytes()

def test_result_contains_required_fields(tmp_path):
    # Setup
    simulator = SafeRansomwareSimulator(tmp_path / "sandbox")
    gatekeeper = GatekeeperAgent()
    adapter = SimulatorGatekeeperAdapter(simulator, gatekeeper)
    
    # Action
    test_file = tmp_path / "sandbox" / "test.txt"
    test_file.write_text("Dummy content", encoding="utf-8")
    results = adapter.evaluate_attack([test_file])
    result = results[0][1]
    
    # Assert
    assert hasattr(result, "timestamp")
    assert hasattr(result, "target")
    assert hasattr(result, "target_type")
    assert hasattr(result, "verdict")
    assert hasattr(result, "risk_score")
    assert hasattr(result, "reasons")
    assert isinstance(result.reasons, list)
    
    event_dict = result.to_dict()
    assert "timestamp" in event_dict
    assert "target" in event_dict
    assert "target_type" in event_dict
    assert "verdict" in event_dict
    assert "risk_score" in event_dict
    assert "reasons" in event_dict
