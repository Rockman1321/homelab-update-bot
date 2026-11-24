"""Relays a rotated Matrix registration token to the management host, which updates the KB page."""
from __future__ import annotations

import json
import subprocess


def trigger_update_registration_token_page(
    host: str, user: str, new_token: str, *, identity_file: str = "", timeout: float = 30.0,
) -> tuple[bool, str]:
    ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes"]
    if identity_file:
        ssh_cmd += ["-i", identity_file]
    ssh_cmd += [f"{user}@{host}", "true"]
    payload = {"mode": "kb_registration_token_update", "new_token": new_token}
    try:
        proc = subprocess.run(
            ssh_cmd, input=json.dumps(payload), capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, f"SSH to {host} timed out after {timeout}s"
    if proc.returncode != 0:
        return False, f"SSH failed: {proc.stderr.strip() or proc.stdout.strip()}"
    try:
        body = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return False, f"bad JSON from mgmt1: {proc.stdout.strip()[:500]}"
    return bool(body.get("ok")), body.get("detail", "")
