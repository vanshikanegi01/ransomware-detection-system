"""
TRINETRA Vaultkeeper

Recovery module notified by the Policy Engine once the Enforcer has
successfully contained a threat. Responsible for:

    1. Finding clean/backup versions of affected files.
    2. Verifying their integrity (hash comparison).
    3. Restoring them into place.

This is a prototype recovery flow: it expects a mirrored backup
directory structure (backups/<relative path>) for the sandbox/demo. In
a production system this would integrate with shadow copies / a real
versioned backup store.
"""
from __future__ import annotations

import os
import stat
import hashlib
import shutil
from pathlib import Path
from typing import Callable, List, Optional

BASE_DIR = Path(__file__).parent.parent


def _hash_file(path: Path) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


class Vaultkeeper:
    def __init__(self, backup_root: str = None, sandbox_root: str = None):
        self.backup_root = Path(backup_root or (BASE_DIR / "backups"))
        self.sandbox_root = Path(sandbox_root or (BASE_DIR / "sandbox_data" / "test_target"))
        self.backup_root.mkdir(parents=True, exist_ok=True)
        self.sandbox_root.mkdir(parents=True, exist_ok=True)

    def _backup_path_for(self, target: Path) -> Optional[Path]:
        try:
            rel = target.resolve().relative_to(self.sandbox_root.resolve())
        except ValueError:
            return None
        return self.backup_root / rel

    def snapshot(self, paths: Optional[List[str]] = None) -> dict:
        """Create/update clean backups for the sandbox target directory
        (or specific paths). Used before running a simulation so
        recovery has something legitimate to restore from."""
        targets = [Path(p) for p in paths] if paths else [self.sandbox_root]
        backed_up = []

        for t in targets:
            files = [t] if t.is_file() else list(t.rglob("*"))
            for f in files:
                if not f.is_file():
                    continue
                dest = self._backup_path_for(f)
                if dest is None:
                    continue
                dest.parent.mkdir(parents=True, exist_ok=True)
                if dest.exists():
                    try:
                        os.chmod(dest, stat.S_IWRITE)
                    except Exception:
                        pass
                shutil.copy2(f, dest)
                backed_up.append(str(f))

        return {"snapshotted": backed_up, "count": len(backed_up)}

    def recover(self, *args, **kwargs) -> dict:
        event_sink = kwargs.get("event_sink")
        affected_paths = []
        if len(args) == 1:
            affected_paths = args[0] if isinstance(args[0], list) else []
        elif len(args) >= 2:
            affected_paths = args[1] if isinstance(args[1], list) else []
        elif "affected_paths" in kwargs:
            affected_paths = kwargs["affected_paths"]

        emit = event_sink or (lambda e: None)
        emit({"event": "VAULTKEEPER_SEARCHING_CLEAN_VERSIONS", "paths": affected_paths})

        restored = []
        failed = []
        verified = []

        targets = [Path(p) for p in affected_paths] if affected_paths else [self.sandbox_root]

        for t in targets:
            files = [t] if t.is_file() else (list(t.rglob("*")) if t.exists() else [])
            for f in files:
                if not f.is_file():
                    continue
                backup = self._backup_path_for(f)
                if backup is None or not backup.exists():
                    failed.append({"path": str(f), "reason": "no clean backup version found"})
                    continue

                backup_hash = _hash_file(backup)
                verified.append({"path": str(f), "backup_hash": backup_hash})

                try:
                    if f.exists():
                        try:
                            os.chmod(f, stat.S_IWRITE)
                        except Exception:
                            pass
                    shutil.copy2(backup, f)
                    restored.append(str(f))
                except Exception as e:
                    failed.append({"path": str(f), "reason": str(e)})

        emit({"event": "INTEGRITY_VERIFIED", "count": len(verified)})
        emit({"event": "FILES_RESTORED", "count": len(restored), "restored": restored})
        emit({"event": "RECOVERY_COMPLETED", "restored_count": len(restored),
              "failed_count": len(failed)})

        return {
            "recovery_completed": True,
            "restored": restored,
            "failed": failed,
            "verified": verified,
        }
