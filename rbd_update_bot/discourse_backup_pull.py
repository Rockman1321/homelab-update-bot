"""Pulls Discourse's own backups down to the management host."""
from __future__ import annotations

import json
import subprocess


def trigger_discourse_backup_pull(
    host: str,
    user: str,
    *,
    retention_days: int = 90,
    identity_file: str = "",
    timeout: float = 900.0,
) -> tuple[bool, dict, list[str]]:
    payload = json.dumps({
        "mode": "discourse_backup_pull",
        "retention_days": retention_days,
    })

    ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes"]
    if identity_file:
        ssh_cmd += ["-i", identity_file]
    ssh_cmd += [f"{user}@{host}", "true"]
    proc = subprocess.run(ssh_cmd, input=payload, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        return False, {}, [f"SSH/collection failed: {proc.stderr.strip() or proc.stdout.strip()}"]

    try:
        body = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return False, {}, [f"bad JSON from collector: {proc.stdout.strip()[:500]}"]

    return True, {
        "pulled": body.get("pulled", []),
        "pruned": body.get("pruned", []),
        "newest_remote_file": body.get("newest_remote_file"),
        "newest_remote_age_hours": body.get("newest_remote_age_hours"),
    }, body.get("errors", [])
