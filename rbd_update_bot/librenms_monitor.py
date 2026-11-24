"""Watches LibreNMS polling health and port state."""
from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone

import requests


PORT_TRACKED_HOSTNAMES = {"192.168.40.10", "192.168.40.11", "192.168.50.1"}

_PORT_COLUMNS = (
    "port_id,ifName,ifAlias,ifOperStatus,ifAdminStatus,ifSpeed,"
    "ifInOctets_rate,ifOutOctets_rate,ifInErrors_rate,ifOutErrors_rate"
)

_UTILIZATION_INFO_PCT = 80.0

_ALERT_WORTHY_PORT_ALIAS_KEYWORDS = ("PMX", "PBS", "NAS", "UPLINK", "WIFI", "FG-")

_UNUSED_FORTIGATE_PORT_ALIASES = frozenset({
    "wan2", "dmz", "internal", "internal3", "internal4", "internal5", "fortilink",
})


def _is_alert_worthy_port_alias(alias: str) -> bool:
    alias_upper = (alias or "").upper()
    return any(keyword in alias_upper for keyword in _ALERT_WORTHY_PORT_ALIAS_KEYWORDS)


def _headers(token: str) -> dict:
    return {"X-Auth-Token": token}


def collect_devices(api_host: str, token: str) -> tuple[list[dict], str | None]:
    try:
        resp = requests.get(
            f"{api_host}/api/v0/devices", headers=_headers(token), timeout=20,
        )
        resp.raise_for_status()
        raw = resp.json().get("devices", [])
    except requests.RequestException as exc:
        return [], f"LibreNMS devices request failed: {exc}"
    except (KeyError, ValueError) as exc:
        return [], f"unexpected LibreNMS devices response shape: {exc}"

    devices = [
        {
            "device_id": d.get("device_id"),
            "hostname": d.get("hostname"),
            "sysName": d.get("sysName"),
            "status": d.get("status"),
            "status_reason": d.get("status_reason"),
        }
        for d in raw
    ]
    return devices, None


def collect_ports(api_host: str, token: str, device_id: int) -> tuple[list[dict], str | None]:
    try:
        resp = requests.get(
            f"{api_host}/api/v0/devices/{device_id}/ports",
            headers=_headers(token), params={"columns": _PORT_COLUMNS}, timeout=20,
        )
        resp.raise_for_status()
        raw = resp.json().get("ports", [])
    except requests.RequestException as exc:
        return [], f"LibreNMS ports request failed for device {device_id}: {exc}"
    except (KeyError, ValueError) as exc:
        return [], f"unexpected LibreNMS ports response shape for device {device_id}: {exc}"

    ports = [
        {
            "port_id": p.get("port_id"),
            "ifName": p.get("ifName"),
            "ifAlias": p.get("ifAlias"),
            "ifOperStatus": p.get("ifOperStatus"),
            "ifAdminStatus": p.get("ifAdminStatus"),
            "ifSpeed": p.get("ifSpeed"),
            "ifInOctets_rate": p.get("ifInOctets_rate"),
            "ifOutOctets_rate": p.get("ifOutOctets_rate"),
            "ifInErrors_rate": p.get("ifInErrors_rate"),
            "ifOutErrors_rate": p.get("ifOutErrors_rate"),
        }
        for p in raw
    ]
    return ports, None


_BANDWIDTH_SNAPSHOT_TARGETS: dict[str, str] = {
    "192.168.20.11": "bond0",
    "192.168.20.12": "bond0",
    "192.168.20.13": "bond0",
    "192.168.20.14": "bond0",
    "192.168.20.5": "nic1",
    "192.168.20.40": "bond0",
}


def collect_bandwidth_snapshot(api_host: str, token: str) -> tuple[list[dict], str | None]:
    devices, err = collect_devices(api_host, token)
    if err:
        return [], err

    snapshot = []
    for d in devices:
        if_name = _BANDWIDTH_SNAPSHOT_TARGETS.get(d.get("hostname"))
        if if_name is None:
            continue
        ports, perr = collect_ports(api_host, token, d["device_id"])
        if perr:
            continue
        port = next((p for p in ports if p["ifName"] == if_name), None)
        if port is None or port["ifInOctets_rate"] is None:
            continue
        in_mbps = port["ifInOctets_rate"] * 8 / 1e6
        out_mbps = port["ifOutOctets_rate"] * 8 / 1e6
        speed_mbps = (port["ifSpeed"] or 0) / 1e6
        snapshot.append({
            "label": d.get("sysName") or d.get("hostname"),
            "in_mbps": in_mbps,
            "out_mbps": out_mbps,
            "speed_mbps": speed_mbps,
            "utilization_pct": (max(in_mbps, out_mbps) / speed_mbps * 100) if speed_mbps else None,
        })
    return snapshot, None


def trigger_bandwidth_trend(
    mgmt_host: str, mgmt_ssh_user: str, backup_checks: list[dict], *,
    days: int = 7, identity_file: str = "", timeout: float = 60.0,
) -> tuple[bool, dict, str]:
    payload = json.dumps({
        "mode": "librenms_bandwidth_trend", "days": days, "backup_checks": backup_checks,
    })
    ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes"]
    if identity_file:
        ssh_cmd += ["-i", identity_file]
    ssh_cmd += [f"{mgmt_ssh_user}@{mgmt_host}", "true"]
    try:
        proc = subprocess.run(ssh_cmd, input=payload, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, {}, f"ssh to mgmt1 timed out after {timeout:.0f}s"
    if proc.returncode != 0:
        return False, {}, f"SSH to mgmt1 failed: {proc.stderr.strip() or proc.stdout.strip()}"
    try:
        body = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return False, {}, f"bad JSON from mgmt1: {proc.stdout.strip()[:500]}"
    return True, drop_incomplete_today(body.get("trend", {})), ""


_TODAY_COMPLETE_AFTER_UTC_HOUR = 12


def drop_incomplete_today(trend: dict, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    if now.hour >= _TODAY_COMPLETE_AFTER_UTC_HOUR:
        return trend
    today = now.date().isoformat()
    out = {}
    for label, data in trend.items():
        if isinstance(data, dict) and data.get("nights"):
            data = {**data, "nights": [n for n in data["nights"] if n.get("date") != today]}
        out[label] = data
    return out


def build_checks(devices: list[dict], ports_by_device: dict[int, list[dict]]) -> list[dict]:
    checks: list[dict] = []
    switch_device_ids = {
        d["device_id"] for d in devices if d.get("hostname") in {"192.168.40.10", "192.168.40.11"}
    }
    fortigate_device_ids = {d["device_id"] for d in devices if d.get("hostname") == "192.168.50.1"}

    for d in devices:
        device_id = d["device_id"]
        label = d.get("sysName") or d.get("hostname") or str(device_id)
        is_down = d.get("status") != 1
        checks.append({
            "check_id": f"librenms_device:{device_id}",
            "source": "librenms_monitor",
            "status": "down" if is_down else "up",
            "detail": (
                f"{label}: DOWN -- {d.get('status_reason') or 'no reason given'}" if is_down
                else f"{label}: reachable"
            ),
            "raw_detail": d,
            "is_bad": is_down,
        })

    for device_id, ports in ports_by_device.items():
        for p in ports:
            port_label = p.get("ifAlias") or p.get("ifName") or str(p.get("port_id"))
            port_down = p.get("ifAdminStatus") == "up" and p.get("ifOperStatus") == "down"
            if device_id in switch_device_ids:
                alert_worthy = _is_alert_worthy_port_alias(port_label)
            elif device_id in fortigate_device_ids:
                alert_worthy = (port_label or "").strip().lower() not in _UNUSED_FORTIGATE_PORT_ALIASES
            else:
                alert_worthy = True
            checks.append({
                "check_id": f"librenms_port:{device_id}:{p.get('port_id')}",
                "source": "librenms_monitor",
                "status": p.get("ifOperStatus") or "unknown",
                "detail": (
                    f"device {device_id} port {port_label}: "
                    f"oper={p.get('ifOperStatus')} admin={p.get('ifAdminStatus')}"
                ),
                "raw_detail": {"device_id": device_id, **p},
                "is_bad": port_down and alert_worthy,
            })

            if p.get("ifSpeed") and p.get("ifInOctets_rate") is not None and p.get("ifOutOctets_rate") is not None:
                in_pct = (p["ifInOctets_rate"] * 8 / p["ifSpeed"]) * 100
                out_pct = (p["ifOutOctets_rate"] * 8 / p["ifSpeed"]) * 100
                checks.append({
                    "check_id": f"librenms_util:{device_id}:{p.get('port_id')}",
                    "source": "librenms_monitor",
                    "status": f"in={in_pct:.1f}% out={out_pct:.1f}% of link speed",
                    "detail": (
                        f"device {device_id} port {port_label}: in={in_pct:.1f}% out={out_pct:.1f}% "
                        f"of {p['ifSpeed'] / 1e9:.2f}Gbps"
                    ),
                    "raw_detail": {
                        "device_id": device_id, "port_id": p.get("port_id"),
                        "in_pct": in_pct, "out_pct": out_pct, "ifSpeed": p["ifSpeed"],
                    },
                    "is_bad": False,
                })

    return checks
