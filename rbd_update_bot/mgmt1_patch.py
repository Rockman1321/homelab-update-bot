"""OS patch and reboot-required status for the management host itself."""
from __future__ import annotations

import json
import subprocess


def _trigger(
    host: str, user: str, payload: dict, *, identity_file: str = "", timeout: float = 30.0,
) -> tuple[bool, dict, str]:
    ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes"]
    if identity_file:
        ssh_cmd += ["-i", identity_file]
    ssh_cmd += [f"{user}@{host}", "true"]
    try:
        proc = subprocess.run(
            ssh_cmd, input=json.dumps(payload), capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, {}, f"SSH timed out after {timeout}s"
    if proc.returncode != 0:
        return False, {}, f"SSH failed: {proc.stderr.strip() or proc.stdout.strip()}"
    try:
        return True, json.loads(proc.stdout), ""
    except json.JSONDecodeError:
        return False, {}, f"bad JSON from mgmt1: {proc.stdout.strip()[:500]}"


def trigger_collect(mgmt_host: str, mgmt_ssh_user: str, *, identity_file: str = "") -> dict | None:
    ok, resp, _ = _trigger(
        mgmt_host, mgmt_ssh_user, {"mode": "mgmt1_patch_collect"},
        identity_file=identity_file, timeout=60,
    )
    if not ok or not resp.get("ok"):
        return None
    return resp


def trigger_apply(mgmt_host: str, mgmt_ssh_user: str, *, identity_file: str = "") -> tuple[bool, str]:
    ok, resp, detail = _trigger(
        mgmt_host, mgmt_ssh_user, {"mode": "mgmt1_patch_apply"},
        identity_file=identity_file, timeout=1850,
    )
    if not ok:
        return False, detail
    if not resp.get("ok"):
        return False, resp.get("detail", "unknown error")
    return True, resp.get("detail", "")


def build_reboot_check(status: dict) -> dict:
    reboot_required = bool(status.get("reboot_required"))
    pkgs = status.get("reboot_required_pkgs") or []
    detail = (
        (f"reboot required for: {', '.join(pkgs)}" if pkgs else "reboot required")
        if reboot_required else "no reboot required"
    )
    return {
        "check_id": "mgmt1_patch:reboot_required", "source": "mgmt1_patch",
        "status": detail, "detail": detail, "is_bad": reboot_required,
    }
