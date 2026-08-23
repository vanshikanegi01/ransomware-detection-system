"""Adapter connecting the Policy Engine to the VaultKeeper subsystem.

Preserves the full forensic context in a supplementary JSON file, while
bridging the interface to the existing VaultkeeperManager.handle_incident().
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional

from policy_enforcer.models import BehavioralSignal
from vaultkeeper.manager import VaultkeeperManager
from vaultkeeper.models import IncidentEvent

logger = logging.getLogger(__name__)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class PolicyToVaultkeeperAdapter:
    """Adapts PolicyEngine's vaultkeeper.recover() call to VaultkeeperManager."""

    def __init__(self, manager: VaultkeeperManager):
        self.manager = manager
        self.vault_dir = Path(manager.vault_dir)

    def recover(
        self, sig: BehavioralSignal, affected_paths: List[str], event_sink: Callable
    ) -> dict:
        """Called automatically by the Policy Engine after a successful ENFORCE action.

        Args:
            sig: The full BehavioralSignal containing ML context.
            affected_paths: List of file paths to recover.
            event_sink: Event emission callback.

        Returns:
            Dict containing the RecoveryReport result.
        """
        # Generate a unique incident ID based on the process ID and timestamp
        incident_id = f"inc_{sig.process_id}_{int(datetime.now().timestamp())}"
        timestamp = _utc_now()

        # 1. Create the forensic JSON payload
        context_data = {
            "incident_id": incident_id,
            "timestamp": timestamp,
            "process_name": sig.process_name,
            "process_id": sig.process_id,
            "original_paths": affected_paths,
            "gatekeeper_context": sig.gatekeeper_context,
            "watchdog_context": sig.watchdog_context,
            "risk_score": sig.risk_score,
            "ransomware_probability": sig.ransomware_probability,
        }

        # 2. Write the supplementary forensic JSON into the Vault directory
        context_file = self.vault_dir / f"incident_context_{incident_id}.json"
        try:
            with open(context_file, "w") as f:
                json.dump(context_data, f, indent=2)
            logger.info(f"Preserved forensic context at {context_file}")
            event_sink({
                "event": "FORENSIC_CONTEXT_SAVED",
                "incident_id": incident_id,
                "file": str(context_file)
            })
        except Exception as e:
            logger.error(f"Failed to write forensic context: {e}")

        # 3. Create the standard IncidentEvent for the VaultkeeperManager
        incident_event = IncidentEvent(
            incident_id=incident_id,
            timestamp=timestamp,
            risk_score=sig.risk_score,
            affected_files=affected_paths,
            event="RANSOMWARE_CONFIRMED"
        )

        # 4. Handoff to Vaultkeeper Manager
        event_sink({"event": "VAULTKEEPER_RECOVERY_STARTED", "incident_id": incident_id})
        
        # We define a tiny progress callback to pump VaultKeeper progress into the event sink
        def on_progress(evt):
            event_sink(evt.to_dict())

        try:
            recovery_report = self.manager.handle_incident(
                incident=incident_event,
                progress_callback=on_progress
            )
            
            event_sink({
                "event": "VAULTKEEPER_RECOVERY_COMPLETED",
                "incident_id": incident_id,
                "status": recovery_report.recovery_status
            })
            
            return recovery_report.to_dict()

        except Exception as e:
            logger.exception("VaultKeeper recovery failed")
            event_sink({
                "event": "VAULTKEEPER_RECOVERY_ERROR",
                "incident_id": incident_id,
                "error": str(e)
            })
            return {"error": str(e), "status": "FAILED"}
