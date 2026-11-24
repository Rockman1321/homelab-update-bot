"""Ollama version tracking and update."""
from __future__ import annotations

import json
import subprocess

import requests

_GITHUB_RELEASES_URL = "https://api.github.com/repos/ollama/ollama/releases"


def get_latest_version() -> str | None:
    try:
        resp = requests.get(_GITHUB_RELEASES_URL, params={"per_page": 10}, timeout=15)
        resp.raise_for_status()
        for release in resp.json():
            if not release.get("prerelease") and not release.get("draft"):
                return release["tag_name"].lstrip("v")
    except Exception:
        return None
    return None


def _mgmt_relay(mgmt_host: str, mgmt_user: str, payload: dict, *,
                 identity_file: str = "", timeout: float = 60.0) -> dict:
    ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes"]
    if identity_file:
        ssh_cmd += ["-i", identity_file]
    ssh_cmd += [f"{mgmt_user}@{mgmt_host}", "true"]
    proc = subprocess.run(ssh_cmd, input=json.dumps(payload), capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        return {"errors": [f"SSH/relay failed: {proc.stderr.strip() or proc.stdout.strip()}"]}
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"errors": [f"bad JSON from relay: {proc.stdout.strip()[:500]}"]}


def get_installed_version(mgmt_host: str, mgmt_user: str, *, ollama_ssh_host: str,
                           ollama_ssh_user: str, identity_file: str = "") -> str | None:
    result = _mgmt_relay(
        mgmt_host, mgmt_user,
        {"mode": "ollama_version_check", "ollama": {"ssh_host": ollama_ssh_host, "ssh_user": ollama_ssh_user}},
        identity_file=identity_file,
    )
    return result.get("installed_version")


def relay_ssh_run(mgmt_host: str, mgmt_user: str, *, target_ssh_host: str, target_ssh_user: str,
                   command: str, identity_file: str = "", timeout: float = 30.0) -> tuple[bool, str]:
    result = _mgmt_relay(
        mgmt_host, mgmt_user,
        {"mode": "ssh_exec", "ssh_host": target_ssh_host, "ssh_user": target_ssh_user,
         "command": command, "timeout": timeout},
        identity_file=identity_file, timeout=timeout + 15.0,
    )
    if "errors" in result and "output" not in result:
        return False, "; ".join(result["errors"])
    return bool(result.get("ok")), result.get("output") or ""


def apply_update(mgmt_host: str, mgmt_user: str, *, ollama_ssh_host: str, ollama_ssh_user: str,
                  identity_file: str = "") -> tuple[bool, str, str]:
    result = _mgmt_relay(
        mgmt_host, mgmt_user,
        {"mode": "ollama_apply_update", "ollama": {"ssh_host": ollama_ssh_host, "ssh_user": ollama_ssh_user}},
        identity_file=identity_file, timeout=300.0,
    )
    output = result.get("output") or "\n".join(result.get("errors", []))
    return bool(result.get("ok")), result.get("installed_version") or "", output
