"""Watches sign-ups and access on the KB site's restricted pages for abuse."""
from __future__ import annotations

import requests

from . import continuwuity_admin

_API_BASE = "https://api.cloudflare.com/client/v4"


def _cf_headers(api_token: str) -> dict:
    return {"Authorization": f"Bearer {api_token}"}


def collect_access_logins(
    api_token: str, account_id: str, app_uid: str, since_iso: str, until_iso: str, *, timeout: float = 20.0,
) -> tuple[list[dict], str]:
    events: list[dict] = []
    try:
        resp = requests.get(
            f"{_API_BASE}/accounts/{account_id}/access/logs/access_requests",
            headers=_cf_headers(api_token), timeout=timeout,
            params={"since": since_iso, "until": until_iso, "limit": 1000},
        )
        resp.raise_for_status()
        body = resp.json()
        if not body.get("success"):
            return [], f"Cloudflare error: {body.get('errors')}"
        for item in body.get("result", []):
            if item.get("app_uid") == app_uid:
                events.append(item)
        return events, ""
    except requests.RequestException as exc:
        return [], f"Cloudflare Access log request failed: {exc}"
    except (KeyError, TypeError, ValueError) as exc:
        return [], f"unexpected Cloudflare Access log response shape: {exc}"


def collect_all_matrix_usernames(
    homeserver: str, admin_access_token: str, admin_room_id: str, admin_bot_user_id: str, *,
    reply_timeout: float = 30.0,
) -> tuple[list[str] | None, str]:
    reply, err = continuwuity_admin.run_admin_command(
        homeserver, admin_access_token, admin_room_id, "!admin users list", admin_bot_user_id,
        reply_timeout=reply_timeout,
    )
    if reply is None:
        return None, err
    return continuwuity_admin.parse_user_list(reply), ""


def collect_active_token_uses_remaining(
    homeserver: str, admin_access_token: str, admin_room_id: str, admin_bot_user_id: str, token: str, *,
    reply_timeout: float = 30.0,
) -> tuple[int | None, str]:
    reply, err = continuwuity_admin.run_admin_command(
        homeserver, admin_access_token, admin_room_id, "!admin token list", admin_bot_user_id,
        reply_timeout=reply_timeout,
    )
    if reply is None:
        return None, err
    return continuwuity_admin.parse_token_uses_remaining(reply, token), ""
