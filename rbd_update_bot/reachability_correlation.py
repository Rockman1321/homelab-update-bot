"""Compares Uptime Kuma's inside view with UptimeRobot's outside view of each service."""
from __future__ import annotations

from .cloudflare_traffic import _HOSTNAME_TO_SERVICE
from .kuma_crash_monitor import KUMA_MONITOR_TO_SERVICE


def correlate(ops_health_rows: list[dict]) -> list[dict]:
    internal_by_service: dict[str, str] = {}
    external_by_service: dict[str, str] = {}

    for row in ops_health_rows:
        check_id = row.get("check_id") or ""
        if row.get("source") == "kuma_monitor":
            name = (row.get("detail") or "").split(":", 1)[0].strip().lower()
            service = KUMA_MONITOR_TO_SERVICE.get(name)
            if service:
                internal_by_service[service] = row.get("status") or "unknown"
        elif row.get("source") == "external_reachability":
            hostname = check_id.split(":", 1)[1] if ":" in check_id else ""
            service = _HOSTNAME_TO_SERVICE.get(hostname)
            if service:
                external_by_service[service] = row.get("status") or "unknown"

    results = []
    for service in sorted(set(internal_by_service) & set(external_by_service)):
        internal_status = internal_by_service[service]
        external_status = external_by_service[service]
        internal_up = internal_status == "up"
        external_up = external_status == "up"
        if internal_up and external_up:
            classification = "healthy"
        elif internal_up and not external_up:
            classification = "external_only_down"
        elif not internal_up and external_up:
            classification = "internal_only_down"
        else:
            classification = "fully_down"
        results.append({
            "service": service,
            "internal_status": internal_status,
            "external_status": external_status,
            "classification": classification,
        })
    return results
