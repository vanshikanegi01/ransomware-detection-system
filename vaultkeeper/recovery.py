"""Automated incident recovery workflow coordinator and recovery state machine.

Member 3: Recovery Engineer
TRINETRA: Bharat's Next-Generation Cyber Resilience Platform
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional, Union

from vaultkeeper.metadata import MetadataStore, normalize_path
from vaultkeeper.models import (
    FileRecoveryResult,
    FileRecoveryStatus,
    IncidentEvent,
    RecoveryProgressEvent,
    RecoveryReport,
    RecoveryState,
)
from vaultkeeper.restore import RestoreEngine
from vaultkeeper.versioning import VersioningEngine

logger = logging.getLogger(__name__)


class RecoveryEngine:
    """Orchestrates multi-file recovery across attack boundaries with fallback selection."""

    def __init__(
        self,
        versioning_engine: VersioningEngine,
        restore_engine: RestoreEngine,
        metadata_store: MetadataStore,
    ) -> None:
        """Initialize RecoveryEngine.

        Args:
            versioning_engine: Engine for querying candidate versions before attack time.
            restore_engine: Engine for verified candidate restoration.
            metadata_store: Catalog store for persisting recovery reports and status.
        """
        self.versioning_engine = versioning_engine
        self.restore_engine = restore_engine
        self.metadata_store = metadata_store
        self._current_state = RecoveryState.IDLE

    @property
    def current_state(self) -> RecoveryState:
        """Get the current lifecycle state of the recovery engine."""
        return self._current_state

    def _transition_to(self, new_state: RecoveryState) -> None:
        """Log and transition the recovery engine state."""
        logger.info(f"[RecoveryEngine] State transition: {self._current_state.value} -> {new_state.value}")
        self._current_state = new_state

    def execute_recovery(
        self,
        incident: IncidentEvent,
        progress_callback: Optional[Callable[[RecoveryProgressEvent], None]] = None,
        destination_override: Optional[Union[str, Path]] = None,
    ) -> RecoveryReport:
        """Execute the full automated rollback workflow for a confirmed ransomware incident.

        Algorithm Flow:
        1. Receive confirmed incident & attack timestamp boundary.
        2. For each affected file:
           a. Query versions strictly created before attack timestamp.
           b. Sort candidate versions from newest to oldest.
           c. Check candidate pre-restore integrity.
           d. If candidate fails integrity, try NEXT older candidate.
           e. Restore valid candidate.
           f. Verify post-restore SHA-256 of the restored file on disk.
           g. Mark RECOVERED or FAILED per file.
        3. Calculate aggregate totals and overall status (COMPLETE / PARTIAL / FAILED).
        4. Store RecoveryReport and notify listeners.

        Args:
            incident: Structured IncidentEvent from Policy Engine.
            progress_callback: Optional callable to receive real-time RecoveryProgressEvent.
            destination_override: Optional alternate directory to restore files to (used in tests).

        Returns:
            RecoveryReport summarizing per-file outcomes and aggregate statistics.
        """
        recovery_start_time = datetime.now(timezone.utc).isoformat()
        self._transition_to(RecoveryState.RECEIVED)

        def emit_progress(event_type: str, path: Optional[str] = None, completed: int = 0, total: int = 0, msg: Optional[str] = None):
            if progress_callback:
                progress_ev = RecoveryProgressEvent(
                    incident_id=incident.incident_id,
                    event=event_type,
                    path=path,
                    completed=completed,
                    total=total,
                    message=msg,
                )
                progress_callback(progress_ev)

        affected_files = incident.affected_files
        total_files = len(affected_files)

        emit_progress("recovery_started", total=total_files, msg=f"Starting recovery for {total_files} affected files.")
        self._transition_to(RecoveryState.ANALYZING)

        file_results: List[FileRecoveryResult] = []
        integrity_failures_count = 0

        for idx, file_path_str in enumerate(affected_files, start=1):
            file_path = Path(file_path_str)
            target_dest = (
                Path(destination_override) / file_path.name
                if destination_override
                else file_path
            )

            emit_progress("candidate_search_started", path=str(file_path), completed=idx - 1, total=total_files)

            # Step A: Filter versions before the attack timestamp
            candidates = self.versioning_engine.get_candidate_versions_before_boundary(
                source_path=file_path,
                attack_timestamp=incident.timestamp,
            )

            if not candidates:
                logger.warning(f"No clean backup candidates found before {incident.timestamp} for {file_path}")
                file_results.append(
                    FileRecoveryResult(
                        path=normalize_path(file_path),
                        status=FileRecoveryStatus.FAILED.value,
                        error_message="No clean candidate versions exist prior to attack timestamp boundary.",
                    )
                )
                emit_progress("file_failed", path=str(file_path), completed=idx, total=total_files, msg="No candidate before attack boundary.")
                continue

            # Step B: Iterate candidates newest -> oldest until a valid clean candidate is restored
            recovered_success = False
            last_err = None

            for candidate in candidates:
                self._transition_to(RecoveryState.VERIFYING)
                emit_progress("candidate_found", path=str(file_path), completed=idx - 1, total=total_files, msg=f"Testing candidate version {candidate.version_id} ({candidate.timestamp})")

                # Check pre-restore integrity
                is_valid, _, pre_err = self.restore_engine.verify_candidate_integrity(candidate)
                if not is_valid:
                    integrity_failures_count += 1
                    logger.warning(
                        f"Candidate {candidate.version_id} for {file_path} failed pre-restore integrity: {pre_err}. Trying older candidate."
                    )
                    emit_progress("integrity_failure", path=str(file_path), completed=idx - 1, total=total_files, msg=f"Candidate {candidate.version_id} failed integrity: {pre_err}")
                    last_err = pre_err
                    continue  # Try next older candidate!

                # Step C: Pre-restore check passed -> Restore candidate
                self._transition_to(RecoveryState.RESTORING)
                emit_progress("file_restore_started", path=str(file_path), completed=idx - 1, total=total_files, msg=f"Restoring from {candidate.version_id}")

                success, restored_hash, restore_err = self.restore_engine.restore_candidate(
                    candidate=candidate,
                    destination_path=target_dest,
                )

                if success:
                    # Step D: Post-restore verified
                    self._transition_to(RecoveryState.POST_VERIFY)
                    recovered_success = True
                    file_results.append(
                        FileRecoveryResult(
                            path=normalize_path(file_path),
                            status=FileRecoveryStatus.RECOVERED.value,
                            version_used=candidate.version_id,
                            original_sha256=candidate.sha256_hash,
                            restored_sha256=restored_hash,
                        )
                    )
                    emit_progress("file_recovered", path=str(file_path), completed=idx, total=total_files, msg=f"Successfully recovered from version {candidate.version_id}")
                    break
                else:
                    integrity_failures_count += 1
                    last_err = restore_err
                    logger.warning(
                        f"Post-restore verification failed for {file_path} using version {candidate.version_id}: {restore_err}. Trying older candidate."
                    )
                    emit_progress("integrity_failure", path=str(file_path), completed=idx - 1, total=total_files, msg=f"Post-restore verification failed: {restore_err}")
                    continue

            if not recovered_success:
                file_results.append(
                    FileRecoveryResult(
                        path=normalize_path(file_path),
                        status=FileRecoveryStatus.FAILED.value,
                        error_message=f"All candidate versions failed verification or restoration. Last error: {last_err}",
                    )
                )
                emit_progress("file_failed", path=str(file_path), completed=idx, total=total_files, msg=f"Recovery failed for file: {last_err}")

        # Step E: Aggregate calculation
        recovered_count = sum(1 for f in file_results if f.status == FileRecoveryStatus.RECOVERED.value)
        failed_count = sum(1 for f in file_results if f.status == FileRecoveryStatus.FAILED.value)

        if total_files == 0:
            overall_status = RecoveryState.COMPLETE.value
        elif recovered_count == total_files:
            overall_status = RecoveryState.COMPLETE.value
        elif recovered_count > 0:
            overall_status = RecoveryState.PARTIAL.value
        else:
            overall_status = RecoveryState.FAILED.value

        self._transition_to(RecoveryState(overall_status))
        recovery_end_time = datetime.now(timezone.utc).isoformat()

        report = RecoveryReport(
            incident_id=incident.incident_id,
            recovery_started=recovery_start_time,
            recovery_completed=recovery_end_time,
            files_at_risk=total_files,
            files_encrypted=total_files,
            files_recovered=recovered_count,
            files_lost=failed_count,
            integrity_failures=integrity_failures_count,
            recovery_status=overall_status,
            files=file_results,
        )

        # Step F: Persist report
        self.metadata_store.save_incident_report(report)
        emit_progress("recovery_complete", completed=total_files, total=total_files, msg=f"Recovery complete with status: {overall_status}")

        return report
