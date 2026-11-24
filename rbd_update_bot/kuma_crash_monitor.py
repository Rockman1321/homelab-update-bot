"""Restarts a service automatically when Uptime Kuma reports it down, then pages if that fails."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta

from uptime_kuma_api import MonitorStatus

from .uptime_kuma import connect_and_login

logger = logging.getLogger(__name__)

KUMA_MONITOR_TO_SERVICE = {
    "immich": "immich", "joplin": "joplin", "matrix": "matrix",
    "nextcloud": "nextcloud", "discourse": "discourse", "teamspeak": "teamspeak",
    "enshrouded": "enshrouded", "mass": "mass", "ollama": "ollama",
    "password pusher": "pwpush",
}


SELF_UPDATING = {
    "enshrouded": ("enshrouded", ("enshrouded-updater", "enshrouded-bootstrap",
                                  "enshrouded-force-update", "enshrouded-restart")),
}
SELF_UPDATE_MAX_WAIT_MINUTES = 90


SCHEDULED_SELF_UPDATE = {
    "librenms": (0, 19, 20),
}


def in_scheduled_self_update_window(monitor_name: str, now_local: datetime) -> bool:
    spec = SCHEDULED_SELF_UPDATE.get(monitor_name.lower())
    if spec is None:
        return False
    hour, minute, duration_minutes = spec
    window_start = now_local.replace(hour=hour, minute=minute, second=0, microsecond=0)
    return window_start <= now_local < window_start + timedelta(minutes=duration_minutes)


def running_programs(supervisorctl_status: str, programs: tuple[str, ...]) -> list[str] | None:
    states = {}
    for line in supervisorctl_status.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].isupper():
            states[parts[0]] = parts[1]
    if not states:
        return None
    return [p for p in programs if states.get(p) in ("RUNNING", "STARTING")]


def latest_status(beats: list) -> MonitorStatus | None:
    flat = []
    for item in beats or []:
        flat.extend(item if isinstance(item, list) else [item])
    flat = [b for b in flat if isinstance(b, dict) and b.get("status") is not None]
    if not flat:
        return None
    newest = max(flat, key=lambda b: (str(b.get("time") or ""), b.get("id") or 0))
    return MonitorStatus(newest["status"])


def collect_monitor_statuses(base_url: str, username: str, password: str) -> tuple[dict[int, dict], str | None]:
    api = None
    try:
        api = connect_and_login(base_url, username, password)
        heartbeats = api.get_heartbeats()
        result: dict[int, dict] = {}
        for m in api.get_monitors():
            if not m.get("active"):
                continue
            monitor_id = m["id"]
            status = latest_status(heartbeats.get(monitor_id) if isinstance(heartbeats, dict) else None)
            if status is None:
                continue
            result[monitor_id] = {"name": m.get("name") or str(monitor_id), "status": status}
        return result, None
    except Exception as exc:
        detail = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
        logger.warning("kuma crash monitor poll failed: %s", detail,
                       exc_info=type(exc).__name__ not in ("TimeoutError", "Timeout"))
        return {}, detail
    finally:
        if api is not None:
            try:
                api.disconnect()
            except Exception:
                pass


def build_checks(statuses: dict[int, dict]) -> list[dict]:
    checks = []
    for monitor_id, info in statuses.items():
        is_down = info["status"] == MonitorStatus.DOWN
        checks.append({
            "check_id": f"kuma_monitor:{monitor_id}",
            "source": "kuma_monitor",
            "status": "down" if is_down else "up",
            "detail": f"{info['name']}: {'DOWN' if is_down else 'up'}",
            "raw_detail": {"monitor_id": monitor_id, "name": info["name"], "status": info["status"].name},
            "is_bad": is_down,
        })
    return checks
