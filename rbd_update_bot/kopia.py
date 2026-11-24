"""Kopia snapshot trigger over SSH."""
from __future__ import annotations

import subprocess


def _ssh_run(host: str, user: str, command: str, *, identity_file: str = "",
             timeout: float = 3600.0) -> tuple[bool, str]:
    ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new"]
    if identity_file:
        ssh_cmd += ["-i", identity_file]
    ssh_cmd += [f"{user}@{host}", command]
    proc = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout)
    return proc.returncode == 0, (proc.stdout + proc.stderr)


def run_kopia_snapshot(
    ssh_host: str,
    ssh_user: str,
    systemd_service: str,
    *,
    identity_file: str = "",
    timeout: float = 3600.0,
) -> tuple[bool, str]:
    ok, _ = _ssh_run(
        ssh_host, ssh_user, f"sudo systemctl start {systemd_service}",
        identity_file=identity_file, timeout=timeout,
    )
    if ok:
        return True, f"{systemd_service} completed successfully"

    _, log_tail = _ssh_run(
        ssh_host, ssh_user, f"journalctl -u {systemd_service} -n 20 --no-pager",
        identity_file=identity_file, timeout=30,
    )
    return False, f"{systemd_service} failed:\n{log_tail}"
