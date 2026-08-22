"""
Canary / Honeypot File Monitor for Windows Watchdog Agent (Member 1).

Monitors sacrificial decoy canary files placed strategically in directories.
Early detection of tampering (creation, modification, renaming, or deletion)
with a canary file provides high-confidence early warning telemetry for
ransomware traversal, flagging events with high severity.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# Ensure project root is in sys.path when executed directly or imported in isolation
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from watcher.models import EventData, EventType

logger = logging.getLogger("watcher.canary_monitor")

# Default decoy filenames. Using prefixes like '!' and '000_' ensures they
# sort first alphabetically in directory scans typically conducted by ransomware.
DEFAULT_CANARY_FILENAMES = [
    "!_canary_01.docx",
    "!_canary_02.xlsx",
    "!_canary_03.pdf",
    "000_canary.txt",
    "!_aa_canary.log",
]

DEFAULT_CANARY_PATTERNS = [
    "canary",
    "honeypot",
    "!_canary_",
]


class CanaryMonitor:
    """
    Ransomware Canary Decoy Monitor.
    
    Deploys, registers, and monitors inert honeypot files.
    When a file system event touches a canary file, enriches the telemetry event
    with `is_canary = True` and `severity = 'high'`.
    """

    def __init__(
        self,
        canary_dir: Optional[str | Path] = None,
        canary_filenames: Optional[List[str]] = None,
        canary_patterns: Optional[List[str]] = None,
    ) -> None:
        """
        Initialize the CanaryMonitor.

        Args:
            canary_dir: Base directory where canary files reside or will be deployed.
            canary_filenames: Specific list of filenames to treat as canaries.
            canary_patterns: Substrings/patterns used to identify canary filenames.
        """
        self.canary_dir = Path(canary_dir).resolve() if canary_dir else None
        self.canary_filenames: List[str] = list(canary_filenames or DEFAULT_CANARY_FILENAMES)
        self.canary_patterns: List[str] = list(canary_patterns or DEFAULT_CANARY_PATTERNS)
        self._canary_paths: Set[str] = set()

        if self.canary_dir:
            for fname in self.canary_filenames:
                self._canary_paths.add(str((self.canary_dir / fname).resolve()).lower())

    def register_canary_file(self, file_path: str | Path) -> None:
        """
        Register an existing path as a monitored canary file.

        Args:
            file_path: Path to the canary file.
        """
        resolved = str(Path(file_path).resolve()).lower()
        self._canary_paths.add(resolved)
        logger.debug("Registered canary file: %s", resolved)

    def unregister_canary_file(self, file_path: str | Path) -> None:
        """
        Unregister a canary file from monitoring.

        Args:
            file_path: Path to the canary file.
        """
        resolved = str(Path(file_path).resolve()).lower()
        self._canary_paths.discard(resolved)

    def is_canary_path(self, file_path: str | Path) -> bool:
        """
        Check if a file path belongs to a canary decoy file.

        Args:
            file_path: Absolute or relative file path to check.

        Returns:
            True if path matches a registered canary or canary naming pattern.
        """
        if not file_path:
            return False

        path_obj = Path(file_path)
        resolved_str = str(path_obj.resolve()).lower()
        file_name = path_obj.name.lower()

        # 1. Exact match against registered canary paths
        if resolved_str in self._canary_paths:
            return True

        # 2. Match against configured canary filenames
        if file_name in [f.lower() for f in self.canary_filenames]:
            return True

        # 3. Match against canary pattern keywords
        for pattern in self.canary_patterns:
            if pattern.lower() in file_name:
                return True

        return False

    def deploy_canaries(
        self,
        target_dir: Optional[str | Path] = None,
        filenames: Optional[List[str]] = None,
        content_template: Optional[str] = None,
    ) -> List[Path]:
        """
        Safely deploy inert, harmless dummy canary files strictly in target test directory.

        Args:
            target_dir: Directory where canaries should be created.
            filenames: List of filenames to create (defaults to configured filenames).
            content_template: Harmless text content written into the canary files.

        Returns:
            List of Path objects for successfully created canary files.
        """
        deploy_dir = Path(target_dir).resolve() if target_dir else self.canary_dir
        if not deploy_dir:
            raise ValueError("Target directory for canary deployment must be provided.")

        deploy_dir.mkdir(parents=True, exist_ok=True)
        to_create = filenames or self.canary_filenames
        created_paths: List[Path] = []

        template = (
            content_template
            or "TRINETRA CANARY DECOY FILE — DO NOT MODIFY OR DELETE.\n"
            "This file is a passive integrity tripwire for ransomware anomaly detection.\n"
        )

        for fname in to_create:
            file_path = deploy_dir / fname
            try:
                if not file_path.exists():
                    file_path.write_text(template, encoding="utf-8")
                    logger.info("Deployed canary decoy file: %s", file_path)
                
                self.register_canary_file(file_path)
                created_paths.append(file_path)
            except Exception as e:
                logger.error("Failed to deploy canary file %s: %s", file_path, e)

        return created_paths

    def inspect_and_tag_event(self, event: EventData) -> EventData:
        """
        Inspect an incoming file system event and tag it if it involves a canary.

        Args:
            event: The incoming EventData object.

        Returns:
            The event object (enriched in-place with is_canary and severity).
        """
        target_is_canary = self.is_canary_path(event.file_path)
        dest_is_canary = self.is_canary_path(event.dest_path) if event.dest_path else False

        if target_is_canary or dest_is_canary:
            event.is_canary = True
            event.severity = "high"
            event.metadata["canary_alert"] = True
            event.metadata["canary_trigger_event"] = event.event_type
            event.metadata["canary_target"] = event.file_path
            if event.dest_path:
                event.metadata["canary_dest"] = event.dest_path
            
            logger.warning(
                "CANARY TRIPWIRE TRIGGERED [%s] on %s (Severity: HIGH)",
                event.event_type.upper(),
                event.file_path,
            )

        return event

    def cleanup_canaries(self, target_dir: Optional[str | Path] = None) -> int:
        """
        Safely remove deployed synthetic canary files from the test directory.

        Args:
            target_dir: Directory to clean up (defaults to configured canary directory).

        Returns:
            Count of successfully removed canary files.
        """
        clean_dir = Path(target_dir).resolve() if target_dir else self.canary_dir
        if not clean_dir or not clean_dir.exists():
            return 0

        removed_count = 0
        for fname in self.canary_filenames:
            file_path = clean_dir / fname
            try:
                if file_path.exists() and file_path.is_file():
                    file_path.unlink()
                    self.unregister_canary_file(file_path)
                    removed_count += 1
                    logger.debug("Removed canary file during cleanup: %s", file_path)
            except Exception as e:
                logger.debug("Non-fatal error removing canary %s: %s", file_path, e)

        return removed_count

    def get_canary_files(self) -> List[Path]:
        """Return a list of registered canary file Path objects."""
        return [Path(p) for p in self._canary_paths]
