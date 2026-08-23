import json
import time
from pathlib import Path

import pytest
from policy_enforcer.policy_engine import PolicyEngine
from policy_enforcer.adapter import RiskToPolicyAdapter
from policy_enforcer.enforcer import Enforcer
from policy_enforcer.vault_adapter import PolicyToVaultkeeperAdapter
from RiskAnalyser.service import RiskAnalyserService
from simulator.gatekeeper_adapter import SimulatorGatekeeperAdapter
from simulator.ransomware_simulator import SafeRansomwareSimulator
from vaultkeeper.manager import VaultkeeperManager
from gatekeeper.gatekeeper import GatekeeperAgent
from watcher.watcher import WatchdogAgent


@pytest.fixture
def sandbox_dir(tmp_path):
    """Fixture providing a temporary, safe directory for integration testing."""
    test_dir = tmp_path / "sandbox_test_vaultkeeper"
    test_dir.mkdir(parents=True, exist_ok=True)
    return test_dir


def test_vaultkeeper_integration(sandbox_dir):
    """End-to-end test verifying VaultKeeper triggers on containment."""
    
    # Vault configuration
    vault_dir = sandbox_dir / "vault"
    db_path = None
    
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
    
    # 5. Initialize VaultKeeper Manager & Adapter
    vault_manager = VaultkeeperManager(
        vault_dir=vault_dir,
        db_path=db_path
    )
    vault_adapter = PolicyToVaultkeeperAdapter(manager=vault_manager)

    # 6. Initialize PolicyEngine with Enforcer and Vaultkeeper attached
    policy_events = []
    def on_policy_event(event: dict):
        policy_events.append(event)

    policy_engine = PolicyEngine(
        event_sink=on_policy_event,
        enforcer=enforcer,
        vaultkeeper=vault_adapter
    )

    # Enable enforcer for test
    policy_engine.config["enforcer"]["dry_run"] = True
    policy_engine.config["enforcer"]["enabled"] = True

    # 7. Initialize Risk Adapter
    adapter = RiskToPolicyAdapter(policy_engine=policy_engine)

    # 8. Wiring callbacks
    watchdog.add_callback(riskanalyser.evaluate_event)
    riskanalyser.add_callback(adapter.handle_risk_result)

    # Track final decisions from the adapter
    decisions = []
    adapter.add_callback(lambda d: decisions.append(d))

    # 9. Setup Simulator
    simulator = SafeRansomwareSimulator(sandbox_dir=sandbox_dir)
    sim_adapter = SimulatorGatekeeperAdapter(simulator=simulator, gatekeeper=gatekeeper, watchdog=watchdog)

    watchdog.start()
    try:
        # ---------------------------------------------------------
        # Scenario 1: Benign Operations (Vaultkeeper should NOT trigger)
        # ---------------------------------------------------------
        policy_events.clear()
        files = simulator.create_dummy_workload(count=5)
        sim_adapter.evaluate_attack(files)
        time.sleep(1.0)

        assert len(decisions) > 0
        benign_decision = decisions[-1]
        assert benign_decision.action in ["MONITOR", "LOG", "RESTRICT"]

        # Verify VaultKeeper was NOT triggered
        vk_activations = [e for e in policy_events if e.get("event") == "VAULTKEEPER_NOTIFIED"]
        assert len(vk_activations) == 0, "VaultKeeper should not activate on low-risk events."

        # ---------------------------------------------------------
        # Scenario 2: Attack Operations (Vaultkeeper MUST trigger)
        # ---------------------------------------------------------
        policy_events.clear()
        decisions.clear()

        # Lower threshold for attack scenario
        policy_engine.config["thresholds"]["ransomware_threshold"] = 30
        policy_engine.config["thresholds"]["high_risk_max"] = 29
        policy_engine.config["thresholds"]["suspicious_max"] = 15

        # Add a suspicious file so Gatekeeper flags it, bumping score and indicators
        suspicious_file = sandbox_dir / "readme_decrypt.txt"
        suspicious_file.write_text("You have been hacked.")
        files.append(suspicious_file)

        sim_adapter.evaluate_attack(files)
        time.sleep(1.0)

        assert len(decisions) > 0
        attack_decision = decisions[-1]
        
        # Expecting THREAT_CONFIRMED based on our lowered threshold (30)
        assert attack_decision.decision == "THREAT_CONFIRMED"

        # Verify VaultKeeper was triggered
        vk_activations = [e for e in policy_events if e.get("event") == "VAULTKEEPER_NOTIFIED"]
        assert len(vk_activations) > 0, "Vaultkeeper was not notified during THREAT_CONFIRMED."

        vk_completed = [e for e in policy_events if e.get("event") == "VAULTKEEPER_RECOVERY_COMPLETED"]
        assert len(vk_completed) > 0, "Vaultkeeper did not complete recovery."
        
        # Verify the supplementary forensic JSON is present in vault_dir
        json_files = list(vault_dir.glob("incident_context_*.json"))
        assert len(json_files) >= 1, "Forensic context JSON file not created."
        
        with open(json_files[0], "r") as f:
            context = json.load(f)
            
        assert "incident_id" in context
        assert "timestamp" in context
        assert "risk_score" in context
        assert "gatekeeper_context" in context
        assert "watchdog_context" in context
        
        # Ensure Watchdog/Gatekeeper metadata is populated
        assert context["risk_score"] >= 30.0

        # Verify SQLite Incident Report exists in VaultkeeperManager
        all_reports = vault_manager.metadata_store.get_all_backups()
        
        # We might not have created backups beforehand (the attack hit unbacked files)
        # But the recovery engine generates a RecoveryReport. Let's query it.
        incident_id = context["incident_id"]
        report = vault_manager.get_incident_report(incident_id)
        assert report is not None
        assert report.incident_id == incident_id
        assert report.recovery_status in ["COMPLETE", "PARTIAL", "FAILED"]

    finally:
        watchdog.stop()
