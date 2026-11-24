"""Human-confirmed Discourse restore from one of its own backups."""
from __future__ import annotations

import json
import re
import subprocess
import time

import requests

from .config import ServiceConfig

_FILENAME_RE = re.compile(r"^[A-Za-z0-9._-]+\.tar\.gz$")

_DISCOURSE_PUBLIC_URL = "https://hub.example.org/"


def is_valid_backup_filename(filename: str) -> bool:
    return bool(_FILENAME_RE.match(filename)) and ".." not in filename


def _ssh_run(host: str, user: str, command: str, *, identity_file: str = "",
             timeout: float = 1800.0) -> tuple[bool, str]:
    ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes"]
    if identity_file:
        ssh_cmd += ["-i", identity_file]
    ssh_cmd += [f"{user}@{host}", command]
    try:
        proc = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, f"ssh timed out after {timeout:.0f}s"
    return proc.returncode == 0, (proc.stdout + proc.stderr)


def _trigger_mgmt1(host: str, user: str, mode: str, extra: dict, *,
                    identity_file: str = "", timeout: float = 300.0) -> tuple[bool, dict]:
    payload = json.dumps({"mode": mode, **extra})
    ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes"]
    if identity_file:
        ssh_cmd += ["-i", identity_file]
    ssh_cmd += [f"{user}@{host}", "true"]
    try:
        proc = subprocess.run(ssh_cmd, input=payload, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, {"error": f"ssh to mgmt1 timed out after {timeout:.0f}s"}
    if proc.returncode != 0:
        return False, {"error": f"SSH to mgmt1 failed: {proc.stderr.strip() or proc.stdout.strip()}"}
    try:
        return True, json.loads(proc.stdout)
    except json.JSONDecodeError:
        return False, {"error": f"bad JSON from mgmt1: {proc.stdout.strip()[:500]}"}


def list_backups(mgmt_host: str, mgmt_ssh_user: str, *,
                  identity_file: str = "") -> tuple[bool, list[dict], str]:
    ok, body = _trigger_mgmt1(
        mgmt_host, mgmt_ssh_user, "discourse_backup_list", {}, identity_file=identity_file,
    )
    if not ok:
        return False, [], body.get("error", "unknown error")
    return True, body.get("backups", []), ""


def push_backup_to_host(filename: str, mgmt_host: str, mgmt_ssh_user: str, *,
                         identity_file: str = "") -> tuple[bool, str]:
    if not is_valid_backup_filename(filename):
        return False, f"refusing: invalid filename {filename!r}"
    ok, body = _trigger_mgmt1(
        mgmt_host, mgmt_ssh_user, "discourse_backup_push", {"filename": filename},
        identity_file=identity_file, timeout=600.0,
    )
    if not ok:
        return False, body.get("error", "unknown error")
    if not body.get("ok"):
        return False, body.get("error") or "push failed for an unknown reason"
    return True, "already on host" if body.get("already_present") else "pushed to host"


def create_safety_backup(service: ServiceConfig, *, identity_file: str = "",
                          timeout: float = 1800.0) -> tuple[bool, str]:
    return _ssh_run(
        service.ssh_host, service.ssh_user,
        'docker exec app bash -c "discourse backup"',
        identity_file=identity_file, timeout=timeout,
    )


def enable_restore(service: ServiceConfig, *, identity_file: str = "") -> tuple[bool, str]:
    return _ssh_run(
        service.ssh_host, service.ssh_user,
        'docker exec app bash -c "discourse enable_restore"',
        identity_file=identity_file, timeout=60,
    )


def disable_restore(service: ServiceConfig, *, identity_file: str = "") -> tuple[bool, str]:
    return _ssh_run(
        service.ssh_host, service.ssh_user,
        'docker exec app bash -c "discourse disable_restore"',
        identity_file=identity_file, timeout=60,
    )


def run_restore(service: ServiceConfig, filename: str, *,
                 identity_file: str = "", timeout: float = 1800.0) -> tuple[bool, str]:
    if not is_valid_backup_filename(filename):
        return False, f"refusing to run restore: invalid filename {filename!r}"
    inner = f"discourse restore '{filename}'"
    return _ssh_run(
        service.ssh_host, service.ssh_user,
        f'docker exec app bash -c "{inner}"',
        identity_file=identity_file, timeout=timeout,
    )


def check_health(*, settle_seconds: float = 90.0, poll_interval: float = 5.0) -> tuple[bool, str]:
    deadline = time.monotonic() + settle_seconds
    detail = ""
    while True:
        try:
            resp = requests.get(_DISCOURSE_PUBLIC_URL, timeout=15)
        except requests.RequestException as exc:
            detail = f"{_DISCOURSE_PUBLIC_URL} did not respond: {exc}"
        else:
            if resp.status_code < 500:
                return True, f"{_DISCOURSE_PUBLIC_URL} returned {resp.status_code}"
            detail = f"{_DISCOURSE_PUBLIC_URL} returned {resp.status_code}"
        if time.monotonic() >= deadline:
            return False, detail
        time.sleep(poll_interval)
