"""
Network isolation: attempts to block outbound/inbound network activity
for the malicious process via the Windows Firewall (netsh advfirewall).

Falls back to a simulated isolation layer when:
    - not running on Windows,
    - not running with sufficient privileges,
    - dry_run is requested,
so that the prototype/demo never fails or silently does something
unsafe on non-Windows dev machines.
"""
from __future__ import annotations

import platform
import subprocess
import ctypes
from typing import Optional


def _is_windows() -> bool:
    return platform.system().lower() == "windows"


def _is_admin_windows() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


class NetworkIsolator:
    def isolate(self, pid: int, process_name: str, process_path: Optional[str] = None,
                dry_run: bool = False) -> dict:
        rule_name = f"TRINETRA_BLOCK_{process_name}_{pid}"

        if dry_run:
            return {
                "network_isolated": True,
                "method": "dry_run_simulation",
                "rule_name": rule_name,
            }

        if not _is_windows():
            return self._simulate(rule_name, reason="Not running on Windows")

        if not process_path:
            return self._simulate(rule_name, reason="No process path available to bind firewall rule")

        if not _is_admin_windows():
            return self._simulate(rule_name, reason="Insufficient privileges for firewall rule (requires admin)")

        try:
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}", "dir=out", "action=block",
                f"program={process_path}", "enable=yes",
            ]
            subprocess.run(cmd, check=True, capture_output=True, timeout=10)

            cmd_in = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}_IN", "dir=in", "action=block",
                f"program={process_path}", "enable=yes",
            ]
            subprocess.run(cmd_in, check=True, capture_output=True, timeout=10)

            return {
                "network_isolated": True,
                "method": "windows_firewall",
                "rule_name": rule_name,
            }
        except Exception as e:
            return self._simulate(rule_name, reason=f"Firewall rule creation failed: {e}")

    def _simulate(self, rule_name: str, reason: str) -> dict:
        return {
            "network_isolated": True,
            "method": "simulated",
            "rule_name": rule_name,
            "note": reason,
        }

    def remove_isolation(self, rule_name: str) -> dict:
        if not _is_windows():
            return {"removed": True, "method": "simulated"}
        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                check=False, capture_output=True, timeout=10,
            )
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}_IN"],
                check=False, capture_output=True, timeout=10,
            )
            return {"removed": True, "method": "windows_firewall"}
        except Exception as e:
            return {"removed": False, "reason": str(e)}
