"""Shuts down and later restores every VM/CT around a manual Proxmox host maintenance window."""
from __future__ import annotations

import random
import socket
import struct
import subprocess
import time

from .proxmox import PBSClient, ProxmoxClient

ALWAYS_EXCLUDED_VMIDS = {211, 212, 900, 214}

NS_HOSTS = {"rbd-ns1": "192.168.50.101", "rbd-ns2": "192.168.50.102"}

DEFAULT_POWER_TIMEOUT_SECONDS = 180.0
DEFAULT_POWER_POLL_INTERVAL_SECONDS = 10.0


def compute_in_scope_vms(proxmox: ProxmoxClient) -> list[dict]:
    out = []
    for r in proxmox.cluster_vm_resources():
        if r.get("status") != "running":
            continue
        vmid = r.get("vmid")
        if vmid in ALWAYS_EXCLUDED_VMIDS:
            continue
        out.append({
            "vmid": vmid, "name": r.get("name"),
            "type": r.get("type"), "node": r.get("node"),
        })
    return out


def _wait_for_status(proxmox: ProxmoxClient, vm: dict, target: str, *,
                      timeout_seconds: float, poll_interval_seconds: float) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            status = proxmox.vm_power_status(vm["node"], vm["vmid"], vm["type"])
        except Exception:
            status = None
        if status == target:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(poll_interval_seconds)


def shutdown_all(proxmox: ProxmoxClient, vms: list[dict], *,
                  timeout_seconds: float = DEFAULT_POWER_TIMEOUT_SECONDS,
                  poll_interval_seconds: float = DEFAULT_POWER_POLL_INTERVAL_SECONDS) -> dict:
    stopped, still_running, errors = [], [], []
    issued = []
    for vm in vms:
        try:
            proxmox.shutdown_vm(vm["node"], vm["vmid"], vm["type"])
            issued.append(vm)
        except Exception as exc:
            errors.append(f"{vm['name']} (VMID {vm['vmid']}): shutdown request failed -- {exc}")

    for vm in issued:
        if _wait_for_status(proxmox, vm, "stopped",
                             timeout_seconds=timeout_seconds,
                             poll_interval_seconds=poll_interval_seconds):
            stopped.append(vm)
        else:
            still_running.append(vm)

    return {"stopped": stopped, "still_running": still_running, "errors": errors}


def start_all(proxmox: ProxmoxClient, vms: list[dict], *,
              timeout_seconds: float = DEFAULT_POWER_TIMEOUT_SECONDS,
              poll_interval_seconds: float = DEFAULT_POWER_POLL_INTERVAL_SECONDS) -> dict:
    started, failed, errors = [], [], []
    issued = []
    for vm in vms:
        try:
            status = proxmox.vm_power_status(vm["node"], vm["vmid"], vm["type"])
        except Exception:
            status = None
        if status == "running":
            started.append(vm)
            continue
        try:
            proxmox.start_vm(vm["node"], vm["vmid"], vm["type"])
            issued.append(vm)
        except Exception as exc:
            errors.append(f"{vm['name']} (VMID {vm['vmid']}): start request failed -- {exc}")

    for vm in issued:
        if _wait_for_status(proxmox, vm, "running",
                             timeout_seconds=timeout_seconds,
                             poll_interval_seconds=poll_interval_seconds):
            started.append(vm)
        else:
            failed.append(vm)

    return {"started": started, "failed": failed, "errors": errors}


def check_backup_freshness(pbs: PBSClient, pbs_datastore: str, vms: list[dict], *,
                            stale_after_hours: float = 24.0) -> list[str]:
    warnings = []
    for vm in vms:
        backup_type = "ct" if vm["type"] == "lxc" else "vm"
        try:
            last = pbs.last_vm_snapshot(pbs_datastore, vm["vmid"], backup_type)
        except Exception as exc:
            warnings.append(f"{vm['name']} (VMID {vm['vmid']}): couldn't check backup age -- {exc}")
            continue
        if last is None:
            warnings.append(f"{vm['name']} (VMID {vm['vmid']}): no PBS backup on record at all.")
            continue
        age_hours = (time.time() - last["backup-time"]) / 3600
        if age_hours >= stale_after_hours:
            warnings.append(f"{vm['name']} (VMID {vm['vmid']}): last backup {age_hours:.1f}h ago.")
    return warnings


def _dns_server_responding(server_ip: str, *, query_name: str = "example.com",
                            timeout: float = 3.0) -> bool:
    transaction_id = random.randint(0, 65535)
    header = struct.pack(">HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)
    question = b"".join(
        struct.pack("B", len(label)) + label.encode() for label in query_name.split(".")
    ) + b"\x00" + struct.pack(">HH", 1, 1)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(header + question, (server_ip, 53))
            resp, _ = sock.recvfrom(512)
    except OSError:
        return False
    if len(resp) < 4:
        return False
    resp_id, resp_flags = struct.unpack(">HH", resp[:4])
    return resp_id == transaction_id and bool(resp_flags & 0x8000)


def check_ns_healthy(*, timeout: float = 3.0) -> tuple[bool, str]:
    down = [name for name, ip in NS_HOSTS.items() if not _dns_server_responding(ip, timeout=timeout)]
    if down:
        return False, f"not answering DNS queries: {', '.join(down)}"
    return True, "rbd-ns1 and rbd-ns2 both answering DNS queries"


def check_mgmt1_reachable(mgmt_host: str, mgmt_ssh_user: str, *, identity_file: str = "") -> bool:
    ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=5",
               "-o", "BatchMode=yes"]
    if identity_file:
        ssh_cmd += ["-i", identity_file]
    ssh_cmd += [f"{mgmt_ssh_user}@{mgmt_host}", "true"]
    try:
        proc = subprocess.run(ssh_cmd, input="", capture_output=True, text=True, timeout=10)
    except Exception:
        return False
    return "bad JSON payload on stdin" in proc.stderr
