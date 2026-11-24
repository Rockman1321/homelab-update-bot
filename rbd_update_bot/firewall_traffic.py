"""Triggers the FortiGate traffic collection and flags spikes or unusual sources."""
from __future__ import annotations

import json
import subprocess

_BLOCKLIST_PACKET_SPIKE_THRESHOLD = 200

_EXPOSED_DISTINCT_IP_THRESHOLD = 15

_EXPOSED_DISTINCT_IP_THRESHOLD_OVERRIDES = {
    22: 40,
}


def _exposed_distinct_ip_threshold(policyid: int) -> int:
    return _EXPOSED_DISTINCT_IP_THRESHOLD_OVERRIDES.get(policyid, _EXPOSED_DISTINCT_IP_THRESHOLD)


_QUERY_PING_MAX_TOTAL_BYTES = {
    22: 2000,
}


_IOT_EGRESS_DISTINCT_DEST_THRESHOLD = 60


def trigger_firewall_traffic_collect(
    host: str,
    user: str,
    *,
    fortigate_api_host: str = "",
    fortigate_token_file: str = "",
    identity_file: str = "",
    timeout: float = 60.0,
) -> tuple[bool, dict, list[str]]:
    payload = json.dumps({
        "mode": "firewall_traffic_collect",
        "fortigate": {"api_host": fortigate_api_host, "token_file": fortigate_token_file},
    })

    ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes"]
    if identity_file:
        ssh_cmd += ["-i", identity_file]
    ssh_cmd += [f"{user}@{host}", "true"]
    proc = subprocess.run(ssh_cmd, input=payload, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        return False, {}, [f"SSH/collection failed: {proc.stderr.strip() or proc.stdout.strip()}"]

    try:
        body = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return False, {}, [f"bad JSON from collector: {proc.stdout.strip()[:500]}"]

    return True, {
        "exposed": body.get("exposed", []), "blocklist": body.get("blocklist", []),
        "iot_egress": body.get("iot_egress", []),
    }, body.get("errors", [])


def real_sessions_for_policy(exposed: list[dict], policyid: int) -> list[dict] | None:
    byte_threshold = _QUERY_PING_MAX_TOTAL_BYTES.get(policyid)
    if byte_threshold is None:
        return None
    for e in exposed:
        if e.get("policyid") != policyid:
            continue
        session_details = e.get("session_details") or []
        return [
            s for s in session_details
            if (s.get("sentbyte") or 0) + (s.get("rcvdbyte") or 0) > byte_threshold
        ]
    return []


def _policy_label(policyid: int, dest_names: list[str] | None) -> str:
    if dest_names:
        return f"{policyid} ({', '.join(dest_names)})"
    return str(policyid)


def build_checks(data: dict, store) -> list[dict]:
    checks: list[dict] = []

    for b in data.get("blocklist", []):
        policyid = b["policyid"]
        label = _policy_label(policyid, b.get("dest_names"))
        packets = b.get("packets") or 0
        meta_key = f"fw_blocklist_packets:{policyid}"
        last_raw = store.get_meta(meta_key)
        last = int(last_raw) if last_raw is not None else packets
        delta = max(packets - last, 0)
        store.set_meta(meta_key, str(packets))
        checks.append({
            "check_id": f"fw_blocklist_spike:{policyid}",
            "source": "firewall_traffic",
            "status": f"{delta} new blocked packets this interval",
            "detail": f"policy {label}: {delta} new blocked packets ({b.get('bytes')} cumulative bytes)",
            "raw_detail": {
                "policyid": policyid, "dest_names": b.get("dest_names"), "delta_packets": delta,
                "total_packets": packets, "total_bytes": b.get("bytes"),
            },
            "is_bad": delta > _BLOCKLIST_PACKET_SPIKE_THRESHOLD,
        })

    for e in data.get("exposed", []):
        policyid = e["policyid"]
        label = _policy_label(policyid, e.get("dest_names"))
        if e.get("open_to_all"):
            non_us = e.get("non_us_sessions") or []
            checks.append({
                "check_id": f"fw_exposure_geo:{policyid}",
                "source": "firewall_traffic",
                "status": f"{len(non_us)} non-US session(s)" if non_us else "all sessions US-sourced",
                "detail": f"policy {label}: {len(non_us)} non-US session(s)",
                "raw_detail": {"policyid": policyid, "dest_names": e.get("dest_names"), "sessions": non_us},
                "is_bad": bool(non_us),
            })

        distinct = e.get("distinct_ip_count") or 0
        real_sessions = real_sessions_for_policy(data.get("exposed", []), policyid)
        distinct_for_alert = (
            len({s.get("saddr") for s in real_sessions if s.get("saddr")})
            if real_sessions is not None else distinct
        )
        checks.append({
            "check_id": f"fw_exposure_volume:{policyid}",
            "source": "firewall_traffic",
            "status": (
                f"{distinct} distinct source IP(s) this interval"
                + (f" ({distinct_for_alert} after filtering known query-ping noise)"
                   if real_sessions is not None else "")
            ),
            "detail": (
                f"policy {label}: {distinct} distinct source IP(s)"
                + (f" ({distinct_for_alert} real)" if real_sessions is not None else "")
            ),
            "raw_detail": {
                "policyid": policyid, "dest_names": e.get("dest_names"),
                "distinct_ip_count": distinct, "distinct_ip_count_filtered": distinct_for_alert,
                "sample_ips": e.get("sample_ips"),
            },
            "is_bad": distinct_for_alert > _exposed_distinct_ip_threshold(policyid),
        })

        if real_sessions is not None:
            byte_threshold = _QUERY_PING_MAX_TOTAL_BYTES[policyid]
            session_details = e.get("session_details") or []
            checks.append({
                "check_id": f"fw_real_connections:{policyid}",
                "source": "firewall_traffic",
                "status": f"{len(real_sessions)} real (high-volume) session(s) this interval",
                "detail": (
                    f"policy {label}: {len(real_sessions)} session(s) over "
                    f"{byte_threshold} total bytes -- the real signal of actual use, "
                    f"since play traffic and query pings share the same port here "
                    f"(see _QUERY_PING_MAX_TOTAL_BYTES's own comment -- this threshold "
                    f"is still unvalidated against a real play session)"
                ),
                "raw_detail": {
                    "policyid": policyid, "byte_threshold": byte_threshold,
                    "real_sessions": real_sessions, "all_sessions": session_details,
                },
                "is_bad": False,
            })

    for i in data.get("iot_egress", []):
        policyid = i["policyid"]
        label = _policy_label(policyid, i.get("dest_names"))
        distinct = i.get("distinct_dest_count") or 0
        checks.append({
            "check_id": f"fw_iot_egress_volume:{policyid}",
            "source": "firewall_traffic",
            "status": f"{distinct} distinct destination(s) this interval",
            "detail": (
                f"policy {label}: {distinct} distinct destination(s) across "
                f"{i.get('distinct_device_count') or 0} IoT device(s)"
            ),
            "raw_detail": {
                "policyid": policyid, "distinct_dest_count": distinct,
                "distinct_device_count": i.get("distinct_device_count"),
                "sample_dests": i.get("sample_dests"),
            },
            "is_bad": distinct > _IOT_EGRESS_DISTINCT_DEST_THRESHOLD,
        })

    return checks
