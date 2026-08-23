"""
TRINETRA Enforcer

Public entry point used by the Policy Engine. Wraps process
termination, file/folder protection, and network isolation behind a
single `contain()` call, with safety controls:

    - dry_run mode (simulate everything, touch nothing)
    - kill_switch / enabled flags are resolved upstream by the Policy
      Engine before this is even called
    - protected-process allowlist enforced inside ProcessManager
    - all filesystem locking constrained to allowed sandbox roots
    - every action logged via EnforcerLogger
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable, Optional

from .process_manager import ProcessManager
from .file_locker import FileLocker
from .network_isolator import NetworkIsolator
from .logger import EnforcerLogger
from .actions import ContainmentActions

BASE_DIR = Path(__file__).parent.parent


class Enforcer:
    def __init__(self, allowed_lock_roots=None, log_path: str = None):
        allowed_lock_roots = allowed_lock_roots or [
            str(BASE_DIR / "sandbox_data")
        ]
        log_path = log_path or str(BASE_DIR / "logs" / "enforcer_actions.jsonl")

        self.process_manager = ProcessManager()
        self.file_locker = FileLocker(
            allowed_roots=allowed_lock_roots,
            lock_state_path=str(BASE_DIR / "logs" / "file_lock_state.json"),
        )
        self.network_isolator = NetworkIsolator()
        self.logger = EnforcerLogger(log_path)
        self.actions = ContainmentActions(
            self.process_manager, self.file_locker,
            self.network_isolator, self.logger,
        )

    def contain(self, command: dict, event_sink: Optional[Callable[[dict], None]] = None) -> dict:
        """
        command = {
            "action": "CONTAIN",
            "process_id": int,
            "process_name": str,
            "affected_paths": [str, ...],
            "dry_run": bool,
        }
        """
        return self.actions.run(command, event_sink=event_sink)

    def unlock_all_files(self) -> dict:
        return self.file_locker.unlock_all()

    def recent_log(self, limit: int = 100) -> list:
        return self.logger.read_recent(limit)
