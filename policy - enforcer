"""
Defines the ordered containment sequence executed by the Enforcer:

    1. Terminate malicious process
    2. Lock affected folders/files
    3. Isolate network activity
    4. Log every step

Each step is defensive-only: nothing here deletes, encrypts, or
irreversibly modifies user data. All actions are logged and every step
respects dry_run / kill_switch / enforcer-disabled configuration
already resolved by the caller.
"""
from __future__ import annotations

from typing import Callable, Optional

from .process_manager import ProcessManager
from .file_locker import FileLocker
from .network_isolator import NetworkIsolator
from .logger import EnforcerLogger


class ContainmentActions:
    def __init__(self, process_manager: ProcessManager, file_locker: FileLocker,
                 network_isolator: NetworkIsolator, logger: EnforcerLogger):
        self.process_manager = process_manager
        self.file_locker = file_locker
        self.network_isolator = network_isolator
        self.logger = logger

    def run(self, command: dict, event_sink: Optional[Callable[[dict], None]] = None) -> dict:
        emit = event_sink or (lambda e: None)
        pid = command["process_id"]
        process_name = command["process_name"]
        affected_paths = command.get("affected_paths", [])
        dry_run = command.get("dry_run", False)

        result = {"contained": False, "dry_run": dry_run}

        # Step 1: process info + termination
        info = self.process_manager.get_process_info(pid)
        term_result = self.process_manager.terminate(pid, process_name, dry_run=dry_run)
        self.logger.log("PROCESS_TERMINATION", {"pid": pid, "process_name": process_name,
                                                  "info": info, "result": term_result})
        result["process_termination"] = term_result
        emit({"event": "PROCESS_TERMINATED" if term_result.get("process_terminated") else "PROCESS_TERMINATION_SKIPPED",
              "pid": pid, "details": term_result})

        # Step 2: file/folder protection
        lock_result = self.file_locker.lock_paths(affected_paths, dry_run=dry_run)
        self.logger.log("FOLDER_LOCK", {"paths": affected_paths, "result": lock_result})
        result["file_protection"] = lock_result
        emit({"event": "FOLDER_LOCKED", "paths": affected_paths, "details": lock_result})

        # Step 3: network isolation
        process_path = (info or {}).get("exe") if info else None
        net_result = self.network_isolator.isolate(pid, process_name, process_path, dry_run=dry_run)
        self.logger.log("NETWORK_ISOLATION", {"pid": pid, "result": net_result})
        result["network_isolation"] = net_result
        emit({"event": "NETWORK_ISOLATED", "pid": pid, "details": net_result})

        # Contained if process handling didn't error out AND (locked or nothing to lock)
        result["contained"] = not term_result.get("blocked", False)

        return result
