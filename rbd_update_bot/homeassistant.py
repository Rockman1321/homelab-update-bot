"""Home Assistant OS update detection and apply."""
from __future__ import annotations

from dataclasses import dataclass

import requests


@dataclass
class UpdateEntity:
    entity_id: str
    title: str
    installed_version: str
    latest_version: str
    supports_backup: bool


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


_HA_SOFTWARE_ENTITY_IDS = {
    "update.home_assistant_core_update",
    "update.home_assistant_supervisor_update",
    "update.home_assistant_operating_system_update",
}


def _is_ha_software_update(entity_id: str, attrs: dict) -> bool:
    if entity_id in _HA_SOFTWARE_ENTITY_IDS:
        return True
    return (attrs.get("entity_picture") or "").startswith("/api/hassio/addons/")


_UPDATE_FEATURE_BACKUP = 8


def list_available_updates(api_host: str, token: str) -> list[UpdateEntity] | None:
    try:
        resp = requests.get(f"{api_host}/api/states", headers=_headers(token), timeout=15)
        resp.raise_for_status()
    except requests.RequestException:
        return None
    updates = []
    for entity in resp.json():
        entity_id = entity.get("entity_id", "")
        if not entity_id.startswith("update.") or entity.get("state") != "on":
            continue
        attrs = entity.get("attributes", {})
        if not _is_ha_software_update(entity_id, attrs):
            continue
        supported_features = attrs.get("supported_features") or 0
        updates.append(UpdateEntity(
            entity_id=entity_id,
            title=attrs.get("title") or entity_id,
            installed_version=attrs.get("installed_version") or "",
            latest_version=attrs.get("latest_version") or "",
            supports_backup=bool(supported_features & _UPDATE_FEATURE_BACKUP),
        ))
    return updates


def install_update(api_host: str, token: str, entity_id: str, *, backup: bool = False) -> tuple[bool, str]:
    payload = {"entity_id": entity_id}
    if backup:
        payload["backup"] = True
    try:
        resp = requests.post(
            f"{api_host}/api/services/update/install",
            headers=_headers(token), json=payload, timeout=30,
        )
        resp.raise_for_status()
    except requests.exceptions.ReadTimeout:
        return True, "install likely triggered -- read timeout waiting for the blocking call to finish"
    except requests.RequestException as exc:
        return False, str(exc)
    return True, "install triggered"


def get_entity_state(api_host: str, token: str, entity_id: str) -> dict | None:
    try:
        resp = requests.get(f"{api_host}/api/states/{entity_id}", headers=_headers(token), timeout=15)
        resp.raise_for_status()
    except requests.RequestException:
        return None
    return resp.json()


def wait_for_install(
    api_host: str, token: str, entity_id: str, timeout_seconds: float = 300, poll_interval: float = 5.0,
    target_version: str | None = None,
) -> None:
    import time
    deadline = time.monotonic() + timeout_seconds
    seen_in_progress = False
    while time.monotonic() < deadline:
        state = get_entity_state(api_host, token, entity_id)
        if state is not None:
            attrs = state.get("attributes") or {}
            if attrs.get("in_progress"):
                seen_in_progress = True
            elif state.get("state") not in ("unavailable", "unknown") and attrs.get("installed_version"):
                if seen_in_progress or (target_version and attrs["installed_version"] == target_version):
                    return
        time.sleep(poll_interval)


def wait_for_api(api_host: str, token: str, timeout_seconds: float = 300, poll_interval: float = 10.0) -> bool:
    import time
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            resp = requests.get(f"{api_host}/api/", headers=_headers(token), timeout=10)
            if resp.status_code == 200:
                return True
        except requests.RequestException:
            pass
        time.sleep(poll_interval)
    return False
