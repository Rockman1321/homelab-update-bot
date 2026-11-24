"""Disk and storage health monitor (SMART, wearout, pool state)."""
from __future__ import annotations

import json
import re
import subprocess

from .proxmox import PBSClient, ProxmoxClient

_NVME_FIELD_PATTERNS = {
    "critical_warning": re.compile(r"Critical Warning:\s*0x([0-9a-fA-F]+)"),
    "available_spare": re.compile(r"Available Spare:\s*(\d+)%"),
    "available_spare_threshold": re.compile(r"Available Spare Threshold:\s*(\d+)%"),
    "percentage_used": re.compile(r"Percentage Used:\s*(\d+)%"),
    "media_errors": re.compile(r"Media and Data Integrity Errors:\s*([\d,]+)"),
    "error_log_entries": re.compile(r"Error Information Log Entries:\s*([\d,]+)"),
}


def _parse_nvme_smart_text(text: str) -> dict:
    parsed: dict = {}
    for field, pattern in _NVME_FIELD_PATTERNS.items():
        match = pattern.search(text)
        if not match:
            parsed[field] = None
            continue
        raw = match.group(1).replace(",", "")
        parsed[field] = int(raw, 16) if field == "critical_warning" else int(raw)
    return parsed


def _is_nvme_smart_bad(smart: dict) -> bool:
    if smart.get("critical_warning"):
        return True
    if smart.get("media_errors"):
        return True
    spare, threshold = smart.get("available_spare"), smart.get("available_spare_threshold")
    if spare is not None and threshold is not None and spare <= threshold:
        return True
    return False


def collect_proxmox_pbs(proxmox: ProxmoxClient, pbs: PBSClient | None) -> tuple[list[dict], list[str]]:
    checks: list[dict] = []
    errors: list[str] = []

    try:
        nodes = proxmox.list_nodes()
    except Exception as exc:
        return checks, [f"proxmox: couldn't list cluster nodes: {exc}"]

    for node in nodes:
        try:
            for d in proxmox.list_disks(node):
                devpath = d.get("devpath")
                check = {
                    "disk_id": f"{node}:{devpath}",
                    "source": "proxmox",
                    "model": d.get("model"),
                    "health": d.get("health"),
                    "wearout": d.get("wearout"),
                }
                try:
                    smart = proxmox.get_disk_smart(node, devpath)
                    if smart.get("type") == "text":
                        check.update(_parse_nvme_smart_text(smart.get("text", "")))
                        check["smart_bad"] = _is_nvme_smart_bad(check)
                except Exception as exc:
                    errors.append(f"proxmox ({node} {devpath} smart): {exc}")
                checks.append(check)
        except Exception as exc:
            errors.append(f"proxmox ({node}): {exc}")

    if pbs is not None:
        try:
            for d in pbs.list_disks():
                checks.append({
                    "disk_id": f"pbs:{d.get('devpath')}",
                    "source": "pbs",
                    "model": d.get("model"),
                    "health": d.get("status"),
                    "wearout": d.get("wearout"),
                })
        except Exception as exc:
            errors.append(f"pbs: {exc}")

    return checks, errors


def trigger_synology_collect(
    host: str,
    user: str,
    *,
    synology_config_file: str,
    identity_file: str = "",
    timeout: float = 60.0,
) -> tuple[bool, list[dict], list[str]]:
    payload = json.dumps({
        "mode": "disk_health_collect",
        "synology": {"config_file": synology_config_file},
    })

    ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes"]
    if identity_file:
        ssh_cmd += ["-i", identity_file]
    ssh_cmd += [f"{user}@{host}", "true"]
    proc = subprocess.run(ssh_cmd, input=payload, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        return False, [], [f"SSH/collection failed: {proc.stderr.strip() or proc.stdout.strip()}"]

    try:
        body = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return False, [], [f"bad JSON from collector: {proc.stdout.strip()[:500]}"]

    return True, body.get("disks", []), body.get("errors", [])
