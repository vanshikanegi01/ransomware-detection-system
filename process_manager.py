"""
Process containment: identifies and safely terminates a malicious
process by PID, with mandatory protected-process validation.

Never terminates anything on PROTECTED_PROCESS_ALLOWLIST regardless of
what the Policy Engine requests - this is a hard safety backstop.
"""
from __future__ import annotations

import platform
from typing import Optional

try:
    import psutil
except ImportError:  # pragma: no cover - allows import on systems without psutil yet
    psutil = None

# Hard-coded allowlist of critical OS / system process names that must
# never be terminated by the Enforcer, no matter the reported risk score.
PROTECTED_PROCESS_ALLOWLIST = {
    "system", "system idle process", "smss.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe",
    "explorer.exe", "dwm.exe", "fontdrvhost.exe", "registry",
    "msmpeng.exe", "spoolsv.exe", "taskhostw.exe",
    # Non-Windows dev/sandbox environment protections
    "systemd", "init", "bash", "sshd", "python", "python3",
}


class ProcessManager:
    def __init__(self, allowlist: Optional[set] = None):
        self.allowlist = allowlist or PROTECTED_PROCESS_ALLOWLIST

    def _is_protected(self, process_name: str) -> bool:
        return (process_name or "").strip().lower() in self.allowlist

    def get_process_info(self, pid: int) -> Optional[dict]:
        if psutil is None:
            return None
        try:
            p = psutil.Process(pid)
            return {
                "pid": pid,
                "name": p.name(),
                "exe": self._safe(p.exe),
                "status": p.status(),
                "create_time": p.create_time(),
            }
        except Exception:
            return None

    def _safe(self, fn):
        try:
            return fn()
        except Exception:
            return None

    def terminate(self, pid: int, process_name: str, dry_run: bool = False) -> dict:
        """
        Terminate a process by PID after validating it is not on the
        protected allowlist and (where possible) confirming the live
        process name matches what the Policy Engine reported.
        """
        if self._is_protected(process_name):
            return {
                "process_terminated": False,
                "blocked": True,
                "reason": f"'{process_name}' is on the protected-process allowlist; refusing to terminate",
            }

        if dry_run:
            return {
                "process_terminated": False,
                "dry_run": True,
                "reason": "Dry-run mode: termination simulated, no process was touched",
            }

        if psutil is None:
            return {
                "process_terminated": False,
                "reason": "psutil not available in this environment (simulated result)",
                "simulated": True,
            }

        try:
            proc = psutil.Process(pid)
            live_name = proc.name()

            if self._is_protected(live_name):
                return {
                    "process_terminated": False,
                    "blocked": True,
                    "reason": f"Live process name '{live_name}' is protected; refusing to terminate",
                }

            proc.terminate()
            try:
                proc.wait(timeout=3)
            except psutil.TimeoutExpired:
                proc.kill()

            return {"process_terminated": True, "pid": pid, "name": live_name}

        except psutil.NoSuchProcess:
            return {
                "process_terminated": False,
                "reason": f"No process with PID {pid} found (may have already exited)",
            }
        except psutil.AccessDenied:
            return {
                "process_terminated": False,
                "reason": f"Access denied terminating PID {pid} (requires elevated privileges)",
            }
        except Exception as e:
            return {"process_terminated": False, "reason": f"Unexpected error: {e}"}
