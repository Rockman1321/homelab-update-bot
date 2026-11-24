"""Human-triggered lockdown actions for the KB site's restricted pages."""
from __future__ import annotations

import requests

from . import continuwuity_admin

_API_BASE = "https://api.cloudflare.com/client/v4"


def rotate_registration_token(
    homeserver: str, admin_access_token: str, admin_room_id: str, admin_bot_user_id: str, old_token: str, *,
    issue_flag: str = "--immortal", reply_timeout: float = 30.0,
) -> tuple[str | None, str]:
    issue_reply, err = continuwuity_admin.run_admin_command(
        homeserver, admin_access_token, admin_room_id, f"!admin token issue {issue_flag}", admin_bot_user_id,
        reply_timeout=reply_timeout,
    )
    if issue_reply is None:
        return None, f"issuing new registration token failed: {err}"
    new_token = continuwuity_admin.parse_issued_token(issue_reply)
    if not new_token:
        return None, f"couldn't parse a token out of the issue reply: {issue_reply!r}"

    revoke_reply, err = continuwuity_admin.run_admin_command(
        homeserver, admin_access_token, admin_room_id, f"!admin token revoke {old_token}", admin_bot_user_id,
        reply_timeout=reply_timeout,
    )
    if revoke_reply is None:
        return new_token, f"new token issued ({new_token}) but revoking the old one failed: {err}"

    return new_token, ""


def set_application_policies(
    api_token: str, account_id: str, app_id: str, policy_ids: list[str], *, timeout: float = 15.0,
) -> tuple[bool, str]:
    try:
        resp = requests.put(
            f"{_API_BASE}/accounts/{account_id}/access/apps/{app_id}",
            headers={"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"},
            timeout=timeout, json={"policies": policy_ids},
        )
        resp.raise_for_status()
        body = resp.json()
        if not body.get("success"):
            return False, f"Cloudflare error: {body.get('errors')}"
    except requests.RequestException as exc:
        return False, f"Cloudflare Access application update failed: {exc}"
    return True, ""
