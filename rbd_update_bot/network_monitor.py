"""Triggers the device/DHCP collection and flags new devices."""
from __future__ import annotations

import json
import subprocess


def trigger_network_collect(
    host: str,
    user: str,
    *,
    omada_config_file: str = "",
    fortigate_api_host: str = "",
    fortigate_token_file: str = "",
    identity_file: str = "",
    timeout: float = 60.0,
) -> tuple[bool, list[dict], list[str]]:
    payload_dict = {"mode": "network_collect"}
    if omada_config_file:
        payload_dict["omada"] = {"config_file": omada_config_file}
    if fortigate_api_host and fortigate_token_file:
        payload_dict["fortigate"] = {
            "api_host": fortigate_api_host,
            "token_file": fortigate_token_file,
        }
    payload = json.dumps(payload_dict)

    ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes"]
    if identity_file:
        ssh_cmd += ["-i", identity_file]
    ssh_cmd += [f"{user}@{host}", "true"]
    try:
        proc = subprocess.run(ssh_cmd, input=payload, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, [], [f"SSH/collection timed out after {timeout:.0f}s"]
    if proc.returncode != 0:
        return False, [], [f"SSH/collection failed: {proc.stderr.strip() or proc.stdout.strip()}"]

    try:
        body = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return False, [], [f"bad JSON from collector: {proc.stdout.strip()[:500]}"]

    return True, body.get("devices", []), body.get("errors", [])


def trigger_wifi_rf_collect(
    host: str,
    user: str,
    *,
    omada_config_file: str,
    watched_macs: list[str] | None = None,
    identity_file: str = "",
    timeout: float = 60.0,
) -> tuple[bool, dict, list[str]]:
    payload = json.dumps({
        "mode": "wifi_rf_collect",
        "omada": {"config_file": omada_config_file},
        "watched_macs": watched_macs or [],
    })

    ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes"]
    if identity_file:
        ssh_cmd += ["-i", identity_file]
    ssh_cmd += [f"{user}@{host}", "true"]
    try:
        proc = subprocess.run(ssh_cmd, input=payload, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, {}, [f"SSH/collection timed out after {timeout:.0f}s"]
    if proc.returncode != 0:
        return False, {}, [f"SSH/collection failed: {proc.stderr.strip() or proc.stdout.strip()}"]

    try:
        body = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return False, {}, [f"bad JSON from collector: {proc.stdout.strip()[:500]}"]

    return True, {
        "radios": body.get("radios", []),
        "neighbors": body.get("neighbors", []),
        "watched_clients": body.get("watched_clients", []),
    }, body.get("errors", [])


def trigger_wg_collect(
    host: str,
    user: str,
    *,
    wg_ssh_host: str,
    wg_ssh_user: str,
    identity_file: str = "",
    timeout: float = 30.0,
) -> tuple[bool, list[dict], list[str]]:
    payload = json.dumps({
        "mode": "wg_collect",
        "wireguard": {"ssh_host": wg_ssh_host, "ssh_user": wg_ssh_user},
    })

    ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes"]
    if identity_file:
        ssh_cmd += ["-i", identity_file]
    ssh_cmd += [f"{user}@{host}", "true"]
    try:
        proc = subprocess.run(ssh_cmd, input=payload, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, [], [f"SSH/collection timed out after {timeout:.0f}s"]
    if proc.returncode != 0:
        return False, [], [f"SSH/collection failed: {proc.stderr.strip() or proc.stdout.strip()}"]

    try:
        body = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return False, [], [f"bad JSON from collector: {proc.stdout.strip()[:500]}"]

    return True, body.get("peers", []), body.get("errors", [])
