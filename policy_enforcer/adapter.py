"""
Adapter connecting RiskAnalyser (RiskResult) to Policy Engine (BehavioralSignal).
"""
import logging
from RiskAnalyser.models import RiskResult
from policy_enforcer.models import BehavioralSignal, PolicyDecisionResponse

logger = logging.getLogger("policy_enforcer.adapter")

class RiskToPolicyAdapter:
    """
    Translates RiskAnalyser output into Policy Engine BehavioralSignal.
    """
    def __init__(self, policy_engine):
        self.policy_engine = policy_engine
        self.callbacks = []

    def add_callback(self, cb):
        self.callbacks.append(cb)

    def handle_risk_result(self, result: RiskResult) -> PolicyDecisionResponse:
        try:
            signal = self._map_to_signal(result)
            decision = self.policy_engine.evaluate(signal)
            logger.info("Policy Engine evaluation complete: %s (Severity: %s)", decision.decision, decision.severity)
            
            for cb in self.callbacks:
                try:
                    cb(decision)
                except Exception as e:
                    logger.error("Error in PolicyDecision callback: %s", e)
            
            return decision
        except Exception as e:
            logger.error("Failed to map or evaluate RiskResult in Policy Engine: %s", e)
            raise e

    def _map_to_signal(self, result: RiskResult) -> BehavioralSignal:
        wd = result.watchdog_context or {}
        proc = wd.get("process_telemetry") or {}
        
        process_name = proc.get("name", "unknown")
        process_id = proc.get("pid", 0)
        process_location = proc.get("exe", "")
        
        affected_paths = []
        if wd.get("file_path"):
            affected_paths.append(wd.get("file_path"))
        if wd.get("dest_path"):
            affected_paths.append(wd.get("dest_path"))
            
        file_extensions = []
        if wd.get("file_extension"):
            file_extensions.append(wd.get("file_extension"))
            
        # Map features from 27-feature array to behavioral signal if available
        # Index 2 = total_operation_velocity (file_modification_rate proxy)
        # Index 20 = ata_write_entropy_max (entropy proxy)
        file_mod_rate = 0.0
        entropy = 0.0
        if result.features and len(result.features) >= 27:
            file_mod_rate = float(result.features[2])
            entropy = float(result.features[20])
            
        gatekeeper_ctx = result.gatekeeper_context or {}
        suspicious = gatekeeper_ctx.get("verdict") in ("SUSPICIOUS", "BLOCK")
        
        return BehavioralSignal(
            risk_score=int(result.risk_score),
            process_name=process_name,
            process_id=process_id,
            entropy=entropy,
            file_modification_rate=file_mod_rate,
            files_modified=1,
            file_extensions=file_extensions,
            process_location=process_location,
            network_activity=False,
            suspicious_behavior=suspicious,
            affected_paths=affected_paths,
            event_id=result.event_id,
            timestamp=result.timestamp,
            threshold_met=result.threshold_met,
            ransomware_probability=result.ransomware_probability,
            gatekeeper_context=gatekeeper_ctx,
            watchdog_context=wd,
            features=result.features
        )
