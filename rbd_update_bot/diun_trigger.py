"""Starts an on-demand Diun image check."""
from __future__ import annotations

import subprocess


def trigger_check(host: str, user: str, *, identity_file: str = "", timeout: float = 30.0) -> tuple[bool, str]:
    ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes"]
    if identity_file:
        ssh_cmd += ["-i", identity_file]
    ssh_cmd += [f"{user}@{host}", "cd /home/rbdroot/monitor && docker compose restart diun"]
    proc = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout)
    return proc.returncode == 0, (proc.stdout + proc.stderr)
