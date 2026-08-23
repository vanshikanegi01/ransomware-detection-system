"""
End-to-End Tests for Policy Engine to Enforcer Integration (Step 5).

Validates the complete pipeline:
Simulator -> Gatekeeper -> Watchdog -> Telemetry -> RiskAnalyser -> PolicyEngine -> Enforcer

Ensures that the Enforcer receives the correct CONTAIN commands only on high-risk events,
and that all containment actions are strictly confined to the sandbox.
"""
import os
import sys
import time
import pytest
from pathlib import Path

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
from policy_enforcer.policy_engine import PolicyEngine
from policy_enforcer.adapter import RiskToPolicyAdapter
from policy_enforcer.enforcer import Enforcer

@pytest.fixture
def sandbox_dir(tmp_path):
    d = tmp_path / "sandbox_test_enforcer"
    d.mkdir()
    return d

def test_enforcer_integration(sandbox_dir):
    """End-to-end test verifying Enforcer triggering upon high-risk policy decisions."""
    global_telemetry_collector.events.clear()
    
    # 1. Initialize Gatekeeper
    gatekeeper = GatekeeperAgent()
    
    # 2. Initialize Watchdog
    watchdog = WatchdogAgent(watch_dir=sandbox_dir, enable_heartbeat=False, enable_canary=False, correlate_processes=False)
    
    # 3. Initialize RiskAnalyser
    riskanalyser = RiskAnalyserService()
    
    # 4. Initialize Enforcer (strictly sandboxed)
    enforcer = Enforcer(
        allowed_lock_roots=[str(sandbox_dir)],
        log_path=str(sandbox_dir / "enforcer_actions.jsonl")
    )
    
    # 5. Initialize PolicyEngine with the Enforcer attached
    policy_events = []
    def on_policy_event(event: dict):
        policy_events.append(event)
    
    policy_engine = PolicyEngine(event_sink=on_policy_event, enforcer=enforcer)
    
    # Enable dry_run for extra safety in tests, though allowed_roots also protects us
    policy_engine.config["enforcer"]["dry_run"] = True
    policy_engine.config["enforcer"]["enabled"] = True
    
    # 6. Initialize Adapter
    adapter = RiskToPolicyAdapter(policy_engine=policy_engine)
    
    # 7. Wiring callbacks
    watchdog.add_callback(riskanalyser.evaluate_event)
    riskanalyser.add_callback(adapter.handle_risk_result)
    
    # Track final decisions from the adapter
    decisions = []
    adapter.add_callback(lambda d: decisions.append(d))
    
    # 8. Setup Simulator
    simulator = SafeRansomwareSimulator(sandbox_dir=sandbox_dir)
    sim_adapter = SimulatorGatekeeperAdapter(simulator=simulator, gatekeeper=gatekeeper, watchdog=watchdog)
    
    watchdog.start()
    try:
        # ---------------------------------------------------------
        # Scenario 1: Benign Operations (Enforcer should NOT trigger)
        # ---------------------------------------------------------
        policy_events.clear()
        files = simulator.create_dummy_workload(count=20)
        sim_adapter.evaluate_attack(files) # creates new files
        time.sleep(1.0)
        
        assert len(decisions) > 0
        benign_decision = decisions[-1]
        
        # Risk should be SAFE or SUSPICIOUS or HIGH_RISK, but NOT THREAT_CONFIRMED.
        # Wait, if it is THREAT_CONFIRMED (which it shouldn't be for benign creates), enforcer would fire.
        # But we verified in step 4 it doesn't trigger ENFORCE action for benign.
        assert benign_decision.action in ["MONITOR", "LOG", "RESTRICT"]
        
        # Verify Enforcer was NOT triggered
        enforcer_activations = [e for e in policy_events if e.get("event") == "ENFORCER_ACTIVATED"]
        assert len(enforcer_activations) == 0, "Enforcer should not activate on low-risk events."

        # ---------------------------------------------------------
        # Scenario 2: Attack Operations (Enforcer MUST trigger)
        # ---------------------------------------------------------
        policy_events.clear()
        decisions.clear()
        
        # Temporarily lower the threshold in the test instance to ensure the dummy payload triggers ENFORCE
        # This avoids having to run a massive 10GB simulation in a unit test.
        policy_engine.config["thresholds"]["ransomware_threshold"] = 30
        policy_engine.config["thresholds"]["high_risk_max"] = 29
        policy_engine.config["thresholds"]["suspicious_max"] = 15
        
        # Add a suspicious file so Gatekeeper flags it, which grants the 3rd indicator needed to escalate HIGH_RISK to THREAT_CONFIRMED
        suspicious_file = sandbox_dir / "readme_decrypt.txt"
        suspicious_file.write_text("You have been hacked.")
        files.append(suspicious_file)
        
        # evaluate_attack automatically calls simulate_attack_damage on all these files
        sim_adapter.evaluate_attack(files)
        time.sleep(1.0)
        
        assert len(decisions) > 0
        attack_decision = decisions[-1]
        
        # Verify Policy Engine made the right decision
        assert attack_decision.decision == "THREAT_CONFIRMED" or (attack_decision.decision == "HIGH_RISK" and attack_decision.action == "ENFORCE")
        assert attack_decision.action == "ENFORCE"
        
        # Verify the Enforcer actually returned a result
        assert attack_decision.enforcement_result is not None
        assert "process_termination" in attack_decision.enforcement_result
        assert "file_protection" in attack_decision.enforcement_result
        
        # Verify Enforcer actions were logged safely
        enforcer_activations = [e for e in policy_events if e.get("event") == "ENFORCER_ACTIVATED"]
        assert len(enforcer_activations) > 0
        
        process_terminated_events = [e for e in policy_events if e.get("event") in ("PROCESS_TERMINATED", "PROCESS_TERMINATION_SKIPPED")]
        assert len(process_terminated_events) > 0
        
        # Verify all affected paths were strictly confined to sandbox_dir
        for path_str in attack_decision.enforcement_result["file_protection"].get("paths_locked", []):
            assert str(sandbox_dir) in str(path_str), f"Enforcer locked a path outside sandbox! {path_str}"
            
    finally:
        watchdog.stop()
        enforcer.unlock_all_files()
