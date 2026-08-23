"""
End-to-End Tests for RiskAnalyser Integration.

Validates the Simulator -> Gatekeeper -> Watchdog -> Telemetry Collector -> RiskAnalyser pipeline.
"""

import os
import time
import pytest
from pathlib import Path
import json
import sys

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from simulator.ransomware_simulator import SafeRansomwareSimulator
from gatekeeper.gatekeeper import GatekeeperAgent
from simulator.gatekeeper_adapter import SimulatorGatekeeperAdapter
from watcher.watcher import WatchdogAgent
from watcher.hardware_telemetry import global_telemetry_collector
from RiskAnalyser.service import RiskAnalyserService
from RiskAnalyser.models import RiskResult

@pytest.fixture
def sandbox_dir(tmp_path):
    d = tmp_path / "sandbox_test"
    d.mkdir()
    return d

def test_feature_ordering():
    """Verify that the generated feature vector has exactly 27 features in the correct order."""
    # Simulate a single write event
    global_telemetry_collector.events.clear()
    
    sim = SafeRansomwareSimulator(sandbox_dir=Path("./disposable_pytest_sandbox"))
    sim._emit_telemetry(b"A" * 8192, ["ata_write", "mem_write"])
    
    features = global_telemetry_collector.get_feature_vector(window_duration=10.0)
    assert len(features) == 27
    
    # 8192 bytes = 2 ops
    # total ops should be 2 ata_write + 2 mem_write = 4
    assert features[0] == 4.0 # total_ops
    assert features[1] == 8192.0 # total_bytes
    assert features[5] == 2.0 # ata_write_ops
    assert features[7] == 8192.0 # ata_write_bytes

def test_model_loading():
    """Verify that the model can be loaded by RiskAnalyserService."""
    service = RiskAnalyserService()
    # The model might not be present in CI, but if it is, self.model should not be None
    if service.model_path.exists():
        assert service.model is not None
        assert hasattr(service.model, "predict_proba")

def test_riskanalyser_pipeline(sandbox_dir):
    """End-to-end test of the entire runtime pipeline."""
    # Reset collector
    global_telemetry_collector.events.clear()
    
    # Initialize agents
    gatekeeper = GatekeeperAgent()
    
    # Setup Watchdog
    received_results = []
    
    def on_risk_result(result: RiskResult):
        received_results.append(result)
        
    riskanalyser = RiskAnalyserService()
    riskanalyser.add_callback(on_risk_result)
    
    watchdog = WatchdogAgent(watch_dir=sandbox_dir, enable_heartbeat=False, enable_canary=False, correlate_processes=False)
    # Connect Watchdog -> RiskAnalyser
    watchdog.add_callback(riskanalyser.evaluate_event)
    
    # Setup Adapter and Simulator
    simulator = SafeRansomwareSimulator(sandbox_dir=sandbox_dir)
    adapter = SimulatorGatekeeperAdapter(simulator=simulator, gatekeeper=gatekeeper, watchdog=watchdog)
    
    watchdog.start()
    try:
        # 1. Benign Scenario
        # Create dummy workload
        files = simulator.create_dummy_workload(count=2)
        
        # Screen access using adapter
        adapter.evaluate_attack(files)
        
        # Wait for watchdog to process events
        time.sleep(1.0)
        
        # Should have results
        assert len(received_results) > 0
        latest_result = received_results[-1]
        
        # Model should predict some probability (benign usually < threshold)
        assert isinstance(latest_result.ransomware_probability, float)
        assert isinstance(latest_result.risk_score, float)
        
        # Gatekeeper context should be preserved
        assert isinstance(latest_result.gatekeeper_context, dict)
        
    finally:
        watchdog.stop()
