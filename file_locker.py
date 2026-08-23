"""
File/folder protection: restricts further modification of affected
resources WITHOUT deleting, moving, or encrypting anything.

Prototype mechanism: flips affected files to read-only (chmod on
POSIX, read-only attribute via os.chmod which maps to FILE_ATTRIBUTE_READONLY
on Windows) and records exactly what was changed so it can be reversed
(unlock) once recovery/investigation is complete.

Hard safety rule: only ever operates inside an allowed root
(sandbox/test directory by default) unless explicitly configured
otherwise - this prevents an over-eager containment action from
locking arbitrary parts of the filesystem in the prototype.
"""
from __future__ import annotations

import os
import stat
import json
from pathlib import Path
from typing import List


class FileLocker:
    def __init__(self, allowed_roots: List[str], lock_state_path: str):
        self.allowed_roots = [Path(r).resolve() for r in allowed_roots]
        self.lock_state_path = Path(lock_state_path)
        self.lock_state_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.lock_state_path.exists():
            self.lock_state_path.write_text("{}")

    def _within_allowed_root(self, path: Path) -> bool:
        try:
            resolved = path.resolve()
        except Exception:
            return False
        return any(
            resolved == root or root in resolved.parents
            for root in self.allowed_roots
        )

    def _load_state(self) -> dict:
        try:
            return json.loads(self.lock_state_path.read_text())
        except Exception:
            return {}

    def _save_state(self, state: dict) -> None:
        self.lock_state_path.write_text(json.dumps(state, indent=2))

    def lock_paths(self, paths: List[str], dry_run: bool = False) -> dict:
        locked = []
        skipped = []
        state = self._load_state()

        for raw_path in paths:
            p = Path(raw_path)
            if not p.exists():
                skipped.append({"path": raw_path, "reason": "does not exist"})
                continue

            if not self._within_allowed_root(p):
                skipped.append({
                    "path": raw_path,
                    "reason": "outside allowed sandbox root - refusing to lock for safety",
                })
                continue

            targets = [p] if p.is_file() else list(p.rglob("*"))
            targets = [t for t in targets if t.is_file()]

            for f in targets:
                try:
                    original_mode = stat.S_IMODE(os.stat(f).st_mode)
                    if not dry_run:
                        os.chmod(f, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
                    state[str(f)] = original_mode
                    locked.append(str(f))
                except Exception as e:
                    skipped.append({"path": str(f), "reason": str(e)})

        if not dry_run:
            self._save_state(state)

        return {
            "folder_locked": len(locked) > 0 or dry_run,
            "files_locked": locked,
            "skipped": skipped,
            "dry_run": dry_run,
        }

    def unlock_all(self) -> dict:
        """Reverse all locks recorded in the lock state (used once
        Vaultkeeper recovery / investigation completes)."""
        state = self._load_state()
        restored = []
        failed = []

        for path_str, mode in state.items():
            try:
                if os.path.exists(path_str):
                    os.chmod(path_str, mode)
                restored.append(path_str)
            except Exception as e:
                failed.append({"path": path_str, "reason": str(e)})

        self._save_state({})
        return {"restored": restored, "failed": failed}
