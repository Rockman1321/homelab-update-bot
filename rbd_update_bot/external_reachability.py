"""Polls UptimeRobot for the outside view of each public service."""
from __future__ import annotations

from urllib.parse import urlparse

import requests

_API_BASE = "https://api.uptimerobot.com/v3"

_DOWN_STATUSES = {"DOWN"}
_SEEMS_DOWN_STATUSES = {"LOOKS_DOWN", "LOOKSDOWN", "SEEMS_DOWN", "SEEMSDOWN"}
_SETUP_GAP_STATUSES = {"PAUSED", "STARTED", "PENDING", "NOT_CHECKED_YET"}


def collect_uptimerobot_status(api_key: str) -> tuple[list[dict], str | None]:
    try:
        resp = requests.get(
            f"{_API_BASE}/monitors",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        return [], f"request failed: {exc}"
    except ValueError as exc:
        return [], f"response wasn't valid JSON: {exc}"

    monitors = data.get("data") if isinstance(data, dict) else data
    if not isinstance(monitors, list):
        return [], f"unexpected response shape (no 'data' list): {data!r:.200}"
    return monitors, None


def _monitor_matches_hostname(monitor_url: str, hostname: str) -> bool:
    return urlparse(monitor_url).netloc == hostname


def monitor_ids_for(monitors: list[dict], hostname: str) -> list[int]:
    return [m["id"] for m in monitors
            if m.get("id") is not None and _monitor_matches_hostname(m.get("url") or "", hostname)]


def set_monitor_paused(api_key: str, monitor_id: int, paused: bool) -> tuple[bool, str]:
    action = "pause" if paused else "start"
    try:
        resp = requests.post(
            f"{_API_BASE}/monitors/{monitor_id}/{action}",
            headers={"Authorization": f"Bearer {api_key}"}, json={}, timeout=20,
        )
    except requests.RequestException as exc:
        return False, f"{action} request failed: {exc}"
    if resp.status_code not in (200, 201):
        return False, f"{action} returned HTTP {resp.status_code}: {resp.text[:200]}"
    return True, action


def create_http_monitor(api_key: str, friendly_name: str, url: str, interval_seconds: int = 300) -> tuple[int | None, str]:
    try:
        resp = requests.post(
            f"{_API_BASE}/monitors",
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "type": "HTTP",
                "friendlyName": friendly_name,
                "url": url,
                "interval": interval_seconds,
                "timeout": 30,
                "httpMethodType": "GET",
            },
            timeout=20,
        )
    except requests.RequestException as exc:
        return None, f"request failed: {exc}"
    if resp.status_code != 201:
        return None, f"create returned HTTP {resp.status_code}: {resp.text[:200]}"
    try:
        monitor_id = resp.json().get("id")
    except ValueError as exc:
        return None, f"response wasn't valid JSON: {exc}"
    if monitor_id is None:
        return None, f"201 response had no 'id': {resp.text[:200]}"
    return monitor_id, "created"


def build_checks(monitors: list[dict], hostnames: list[str]) -> list[dict]:
    checks: list[dict] = []
    for hostname in hostnames:
        match = next((m for m in monitors if _monitor_matches_hostname(m.get("url") or "", hostname)), None)
        check_id = f"external_reachability:{hostname}"

        if match is None:
            checks.append({
                "check_id": check_id, "source": "external_reachability", "status": "no_monitor",
                "is_bad": True,
                "detail": f"No UptimeRobot monitor found for {hostname} -- create one on the dashboard.",
            })
            continue

        status = str(match.get("status", "")).strip().upper()
        if status in _DOWN_STATUSES:
            detail = f"{hostname} is DOWN per UptimeRobot -- can't be confirmed reachable from outside."
            checks.append({"check_id": check_id, "source": "external_reachability", "status": "down",
                            "is_bad": True, "detail": detail})
        elif status in _SEEMS_DOWN_STATUSES:
            detail = f"{hostname} looks down per UptimeRobot (not yet confirmed by their own retry logic)."
            checks.append({"check_id": check_id, "source": "external_reachability", "status": "seems_down",
                            "is_bad": True, "detail": detail})
        elif status in _SETUP_GAP_STATUSES:
            detail = f"UptimeRobot monitor for {hostname} is paused or has never completed a check."
            checks.append({"check_id": check_id, "source": "external_reachability", "status": "not_monitoring",
                            "is_bad": True, "detail": detail})
        else:
            checks.append({"check_id": check_id, "source": "external_reachability", "status": "up",
                            "is_bad": False, "detail": f"{hostname} is reachable per UptimeRobot."})
    return checks
