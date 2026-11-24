"""Human-approved changes to a FortiGate address-group blocklist."""
from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone

FORTIGATE_BACKUP_DIR = "fortigate-backups"


def save_config_backup(raw_config: bytes, *, serial: str) -> str:
    os.makedirs(FORTIGATE_BACKUP_DIR, exist_ok=True)
    os.chmod(FORTIGATE_BACKUP_DIR, 0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    path = os.path.join(FORTIGATE_BACKUP_DIR, f"{serial}-{stamp}.conf")
    with open(path, "wb") as f:
        f.write(raw_config)
    os.chmod(path, 0o600)
    return path


def _trigger(
    host: str, user: str, payload: dict, *, identity_file: str = "", timeout: float = 30.0,
) -> tuple[bool, dict, str]:
    ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes"]
    if identity_file:
        ssh_cmd += ["-i", identity_file]
    ssh_cmd += [f"{user}@{host}", "true"]
    proc = subprocess.run(
        ssh_cmd, input=json.dumps(payload), capture_output=True, text=True, timeout=timeout,
    )
    if proc.returncode != 0:
        return False, {}, f"SSH failed: {proc.stderr.strip() or proc.stdout.strip()}"
    try:
        return True, json.loads(proc.stdout), ""
    except json.JSONDecodeError:
        return False, {}, f"bad JSON from mgmt1: {proc.stdout.strip()[:500]}"


def trigger_block_ip(
    host: str, user: str, ip: str, comment: str, *,
    fortigate_api_host: str, fortigate_write_token_file: str,
    identity_file: str = "", timeout: float = 30.0,
) -> tuple[bool, str]:
    ok, body, err = _trigger(
        host, user,
        {
            "mode": "fortigate_blocklist_action", "action": "block", "ip": ip, "comment": comment,
            "fortigate": {"api_host": fortigate_api_host, "write_token_file": fortigate_write_token_file},
        },
        identity_file=identity_file, timeout=timeout,
    )
    if not ok:
        return False, err
    return bool(body.get("ok")), body.get("detail", "")


def trigger_unblock_ip(
    host: str, user: str, ip: str, *,
    fortigate_api_host: str, fortigate_write_token_file: str,
    identity_file: str = "", timeout: float = 30.0,
) -> tuple[bool, str]:
    ok, body, err = _trigger(
        host, user,
        {
            "mode": "fortigate_blocklist_action", "action": "unblock", "ip": ip,
            "fortigate": {"api_host": fortigate_api_host, "write_token_file": fortigate_write_token_file},
        },
        identity_file=identity_file, timeout=timeout,
    )
    if not ok:
        return False, err
    return bool(body.get("ok")), body.get("detail", "")


def trigger_list_blocked_ips(
    host: str, user: str, *,
    fortigate_api_host: str, fortigate_write_token_file: str,
    identity_file: str = "", timeout: float = 30.0,
) -> tuple[bool, list[str], str]:
    ok, body, err = _trigger(
        host, user,
        {
            "mode": "fortigate_blocklist_action", "action": "list",
            "fortigate": {"api_host": fortigate_api_host, "write_token_file": fortigate_write_token_file},
        },
        identity_file=identity_file, timeout=timeout,
    )
    if not ok:
        return False, [], err
    return bool(body.get("ok")), body.get("blocked_ips", []), body.get("detail", "")


def trigger_get_wan_ip(
    host: str, user: str, *,
    fortigate_api_host: str, fortigate_token_file: str,
    identity_file: str = "", timeout: float = 30.0,
) -> tuple[str | None, str]:
    ok, body, err = _trigger(
        host, user,
        {
            "mode": "fortigate_wan_ip",
            "fortigate": {"api_host": fortigate_api_host, "token_file": fortigate_token_file},
        },
        identity_file=identity_file, timeout=timeout,
    )
    if not ok:
        return None, err
    return body.get("wan_ip"), body.get("error") or ""


def trigger_get_status(
    host: str, user: str, *,
    fortigate_api_host: str, fortigate_token_file: str,
    identity_file: str = "", timeout: float = 30.0,
) -> tuple[dict | None, str]:
    ok, body, err = _trigger(
        host, user,
        {
            "mode": "fortigate_status",
            "fortigate": {"api_host": fortigate_api_host, "token_file": fortigate_token_file},
        },
        identity_file=identity_file, timeout=timeout,
    )
    if not ok:
        return None, err
    return body, body.get("error") or ""


def trigger_config_backup(
    host: str, user: str, *,
    fortigate_api_host: str, fortigate_token_file: str,
    identity_file: str = "", timeout: float = 45.0,
) -> tuple[bytes | None, str]:
    import base64
    ok, body, err = _trigger(
        host, user,
        {
            "mode": "fortigate_config_backup",
            "fortigate": {"api_host": fortigate_api_host, "token_file": fortigate_token_file},
        },
        identity_file=identity_file, timeout=timeout,
    )
    if not ok:
        return None, err
    b64 = body.get("config_b64")
    if not b64:
        return None, body.get("error") or "no config returned"
    return base64.b64decode(b64), ""
