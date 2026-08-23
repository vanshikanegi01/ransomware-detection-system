import json
import logging
import tempfile
import time
from pathlib import Path

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

logging.basicConfig(level=logging.ERROR)

def run_validation():
    # ---------------------------------------------------------
    # Setup Sandbox
    # ---------------------------------------------------------
    sandbox = tempfile.mkdtemp(prefix="trinetra_sandbox_")
    sandbox_dir = Path(sandbox)
    vault_dir = sandbox_dir / "vault"
    print(f"==================================================")
    print(f"SANDBOX PATH: {sandbox_dir}")
    print(f"==================================================")

    # 1. Gatekeeper
    gatekeeper = GatekeeperAgent()

    # 2. Watchdog
    watchdog = WatchdogAgent(watch_dir=sandbox_dir, enable_heartbeat=False, enable_canary=False, correlate_processes=False)

    # 3. RiskAnalyser
    riskanalyser = RiskAnalyserService()

    # 4. Enforcer
    enforcer = Enforcer(
        allowed_lock_roots=[str(sandbox_dir)],
        log_path=str(sandbox_dir / "enforcer_actions.jsonl")
    )
    
    # 5. VaultKeeper
    vault_manager = VaultkeeperManager(
        vault_dir=vault_dir,
        db_path=None # Defaults to vault_dir / "vault_metadata.db"
    )
    vault_adapter = PolicyToVaultkeeperAdapter(manager=vault_manager)

    # 6. Policy Engine
    policy_events = []
    def on_policy_event(event: dict):
        policy_events.append(event)

    policy_engine = PolicyEngine(
        event_sink=on_policy_event,
        enforcer=enforcer,
        vaultkeeper=vault_adapter
    )

    # Enable enforcer for validation.
    # Note: We do NOT lower the threshold. We use the production threshold of 44.
    policy_engine.config["enforcer"]["dry_run"] = True
    policy_engine.config["enforcer"]["enabled"] = True

    # 7. Risk Adapter
    adapter = RiskToPolicyAdapter(policy_engine=policy_engine)

    # 8. Wiring callbacks
    watchdog.add_callback(riskanalyser.evaluate_event)
    riskanalyser.add_callback(adapter.handle_risk_result)

    decisions = []
    adapter.add_callback(lambda d: decisions.append(d))

    # 9. Simulator
    simulator = SafeRansomwareSimulator(sandbox_dir=sandbox_dir)
    sim_adapter = SimulatorGatekeeperAdapter(simulator=simulator, gatekeeper=gatekeeper, watchdog=watchdog)

    watchdog.start()
    try:
        # =========================================================
        # 1. SAFE SCENARIO
        # =========================================================
        print("\n--- SAFE SCENARIO ---")
        start_time = time.time()
        policy_events.clear()
        
        files = simulator.create_dummy_workload(count=5)
        sim_adapter.evaluate_attack(files)
        time.sleep(1.0)
        
        benign_decision = decisions[-1] if decisions else None
        
        print("Result:")
        if benign_decision:
            print(f"- Gatekeeper Verdict: {benign_decision.score_breakdown.get('rule_based_score', 0)}")
            print(f"- ML Ransomware Probability: {benign_decision.score_breakdown.get('ml_analyzer_score', 0)}")
            print(f"- Final Risk Score: {benign_decision.risk_score}")
            print(f"- Policy Decision: {benign_decision.decision}")
            print(f"- Policy Action: {benign_decision.action}")
            print(f"- Enforcer Triggered: {benign_decision.action == 'ENFORCE'}")
            
            vk_events = [e for e in policy_events if e.get("event") == "VAULTKEEPER_NOTIFIED"]
            print(f"- VaultKeeper Triggered: {len(vk_events) > 0}")
        else:
            print("- No decision generated.")
        
        print(f"- Execution Time: {time.time() - start_time:.2f}s")


        # =========================================================
        # 2. RANSOMWARE SCENARIO
        # =========================================================
        print("\n--- RANSOMWARE SCENARIO ---")
        policy_events.clear()
        decisions.clear()
        
        # We need a large enough payload to naturally trigger the Random Forest model 
        # and rule-based components above the 44 threshold.
        # We will generate a burst of highly suspicious files.
        attack_files = simulator.create_dummy_workload(count=15)
        # Give them suspicious names and content
        for i, path in enumerate(attack_files):
            new_path = path.with_suffix(".locked_test")
            path.rename(new_path)
            new_path.write_bytes(b"\\x00" * 4096)
            attack_files[i] = new_path
            
        suspicious_file = sandbox_dir / "readme_decrypt.txt"
        suspicious_file.write_text("You have been hacked.")
        attack_files.append(suspicious_file)
        
        start_time = time.time()
        sim_adapter.evaluate_attack(attack_files)
        time.sleep(2.0)
        
        attack_decision = decisions[-1] if decisions else None
        
        print("Result:")
        if attack_decision:
            print(f"- Gatekeeper Verdict Score: {attack_decision.score_breakdown.get('rule_based_score', 0)}")
            print(f"- ML Ransomware Score: {attack_decision.score_breakdown.get('ml_analyzer_score', 0)}")
            print(f"- Final Risk Score: {attack_decision.risk_score}")
            print(f"- Policy Decision: {attack_decision.decision}")
            print(f"- Policy Action: {attack_decision.action}")
            print(f"- Enforcer Result: {attack_decision.enforcement_result.get('contained') if attack_decision.enforcement_result else 'None'}")
            
            vk_completed = [e for e in policy_events if e.get("event") == "VAULTKEEPER_RECOVERY_COMPLETED"]
            if vk_completed:
                print(f"- VaultKeeper Status: {vk_completed[-1].get('status')}")
            else:
                print(f"- VaultKeeper Status: NOT COMPLETED")
                
            json_files = list(vault_dir.glob("incident_context_*.json"))
            print(f"- Forensic JSON Created: {len(json_files) > 0}")
            if json_files:
                print(f"- Forensic Path: {json_files[-1]}")
        else:
            print("- No decision generated.")

        print(f"- Execution Time: {time.time() - start_time:.2f}s")
        print(f"- Affected Sandbox Files: {len(attack_files)}")

        # =========================================================
        # 3. TEST-ONLY: DOWNSTREAM PIPELINE VALIDATION
        # =========================================================
        print("\n--- TEST-ONLY: DOWNSTREAM PIPELINE VALIDATION (Threshold=30) ---")
        policy_events.clear()
        decisions.clear()
        
        # We explicitly lower the threshold here ONLY to prove Enforcer + VaultKeeper 
        # integration actually works when a threat crosses the threshold.
        policy_engine.config["thresholds"]["ransomware_threshold"] = 30
        policy_engine.config["thresholds"]["high_risk_max"] = 29
        policy_engine.config["thresholds"]["suspicious_max"] = 15
        
        test_attack_files = simulator.create_dummy_workload(count=5)
        for i, path in enumerate(test_attack_files):
            new_path = path.with_suffix(".locked_test_only")
            path.rename(new_path)
            new_path.write_bytes(b"\\x00" * 4096)
            test_attack_files[i] = new_path
            
        start_time = time.time()
        sim_adapter.evaluate_attack(test_attack_files)
        time.sleep(1.0)
        
        test_decision = decisions[-1] if decisions else None
        
        print("Result:")
        if test_decision:
            print(f"- Gatekeeper Verdict Score: {test_decision.score_breakdown.get('rule_based_score', 0)}")
            print(f"- ML Ransomware Score: {test_decision.score_breakdown.get('ml_analyzer_score', 0)}")
            print(f"- Final Risk Score: {test_decision.risk_score}")
            print(f"- Policy Decision: {test_decision.decision}")
            print(f"- Policy Action: {test_decision.action}")
            print(f"- Enforcer Result: {test_decision.enforcement_result.get('contained') if test_decision.enforcement_result else 'None'}")
            
            vk_completed = [e for e in policy_events if e.get("event") == "VAULTKEEPER_RECOVERY_COMPLETED"]
            if vk_completed:
                print(f"- VaultKeeper Status: {vk_completed[-1].get('status')}")
            else:
                print(f"- VaultKeeper Status: NOT COMPLETED")
                
            json_files = list(vault_dir.glob("incident_context_*.json"))
            print(f"- Forensic JSON Created: {len(json_files)}")
            if json_files:
                print(f"- Forensic Path: {json_files[-1]}")
        else:
            print("- No decision generated.")

        print(f"- Execution Time: {time.time() - start_time:.2f}s")
        print(f"- Affected Sandbox Files: {len(test_attack_files)}")

    finally:
        watchdog.stop()


if __name__ == "__main__":
    run_validation()
