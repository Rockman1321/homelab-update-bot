"""Triggers the daily deployed-config archive on the management host and reports unexplained changes."""
from __future__ import annotations

import json
import subprocess


def trigger_config_archive_collect(
    host: str,
    user: str,
    *,
    immich_stack_content: str = "",
    identity_file: str = "",
    timeout: float = 60.0,
) -> tuple[bool, dict, list[str]]:
    payload = json.dumps({
        "mode": "config_archive_collect",
        "immich_stack_content": immich_stack_content,
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
        "committed": body.get("committed", False),
        "commit_hash": body.get("commit_hash"),
        "changed_files": body.get("changed_files", []),
        "diffs": body.get("diffs", {}),
    }, body.get("errors", [])
