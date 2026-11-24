"""Starts a read-only Claude Code investigation on the management host."""
from __future__ import annotations

import json
import subprocess


def trigger_investigation(
    host: str,
    user: str,
    *,
    service_name: str,
    current_version: str,
    new_version: str,
    error: str,
    self_ssh_host: str = "",
    self_ssh_user: str = "",
    self_install_dir: str = "",
    supports_repair: bool = False,
    supports_rollback: bool = False,
    supports_mass_digest_rollback: bool = False,
    supports_immich_digest_rollback: bool = False,
    supports_nextcloud_recovery: bool = False,
    identity_file: str = "",
    timeout: float = 900.0,
) -> tuple[bool, str]:
    payload = json.dumps({
        "service": service_name,
        "current_version": current_version,
        "new_version": new_version,
        "error": error,
        "self_ssh_host": self_ssh_host,
        "self_ssh_user": self_ssh_user,
        "self_install_dir": self_install_dir,
        "supports_repair": supports_repair,
        "supports_rollback": supports_rollback,
        "supports_mass_digest_rollback": supports_mass_digest_rollback,
        "supports_immich_digest_rollback": supports_immich_digest_rollback,
        "supports_nextcloud_recovery": supports_nextcloud_recovery,
    })
    ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes"]
    if identity_file:
        ssh_cmd += ["-i", identity_file]
    ssh_cmd += [f"{user}@{host}", "true"]
    proc = subprocess.run(ssh_cmd, input=payload, capture_output=True, text=True, timeout=timeout)
    return proc.returncode == 0, (proc.stdout + proc.stderr)


def trigger_finding_investigation(
    host: str,
    user: str,
    *,
    finding: dict,
    omada_config_file: str = "",
    fortigate_api_host: str = "",
    fortigate_token_file: str = "",
    synology_config_file: str = "",
    recent_roams: list[dict] | None = None,
    hosts: list[dict] | None = None,
    proxmox_backup_context: dict | None = None,
    identity_file: str = "",
    timeout: float = 900.0,
) -> tuple[bool, str]:
    payload = json.dumps({
        "mode": "investigate_finding",
        "finding": finding,
        "omada": {"config_file": omada_config_file} if omada_config_file else None,
        "fortigate": (
            {"api_host": fortigate_api_host, "token_file": fortigate_token_file}
            if fortigate_api_host and fortigate_token_file else None
        ),
        "synology": {"config_file": synology_config_file} if synology_config_file else None,
        "recent_roams": recent_roams or [],
        "proxmox_backup_context": proxmox_backup_context,
        "hosts": hosts or [],
    })
    ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes"]
    if identity_file:
        ssh_cmd += ["-i", identity_file]
    ssh_cmd += [f"{user}@{host}", "true"]
    proc = subprocess.run(ssh_cmd, input=payload, capture_output=True, text=True, timeout=timeout)
    return proc.returncode == 0, (proc.stdout + proc.stderr)


def trigger_network_issue_investigation(
    host: str,
    user: str,
    *,
    description: str,
    recent_roams: list[dict],
    omada_config_file: str = "",
    fortigate_api_host: str = "",
    fortigate_token_file: str = "",
    hosts: list[dict] | None = None,
    identity_file: str = "",
    timeout: float = 900.0,
) -> tuple[bool, str]:
    payload = json.dumps({
        "mode": "investigate_network_issue",
        "description": description,
        "recent_roams": recent_roams,
        "hosts": hosts or [],
        "omada": {"config_file": omada_config_file} if omada_config_file else None,
        "fortigate": (
            {"api_host": fortigate_api_host, "token_file": fortigate_token_file}
            if fortigate_api_host and fortigate_token_file else None
        ),
    })
    ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes"]
    if identity_file:
        ssh_cmd += ["-i", identity_file]
    ssh_cmd += [f"{user}@{host}", "true"]
    proc = subprocess.run(ssh_cmd, input=payload, capture_output=True, text=True, timeout=timeout)
    return proc.returncode == 0, (proc.stdout + proc.stderr)


def trigger_cluster_investigation(
    host: str,
    user: str,
    *,
    description: str,
    node_resources: list[dict],
    vm_resources: list[dict],
    hosts: list[dict] | None = None,
    identity_file: str = "",
    timeout: float = 900.0,
) -> tuple[bool, str]:
    payload = json.dumps({
        "mode": "investigate_cluster_resources",
        "description": description,
        "node_resources": node_resources,
        "vm_resources": vm_resources,
        "hosts": hosts or [],
    })
    ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes"]
    if identity_file:
        ssh_cmd += ["-i", identity_file]
    ssh_cmd += [f"{user}@{host}", "true"]
    proc = subprocess.run(ssh_cmd, input=payload, capture_output=True, text=True, timeout=timeout)
    return proc.returncode == 0, (proc.stdout + proc.stderr)
