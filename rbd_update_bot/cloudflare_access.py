"""Adds and removes individual emails on a Cloudflare Access policy."""
from __future__ import annotations

import requests

_API_BASE = "https://api.cloudflare.com/client/v4"


def _get_policy(api_token: str, account_id: str, app_id: str, policy_id: str, *, timeout: float) -> dict:
    resp = requests.get(
        f"{_API_BASE}/accounts/{account_id}/access/apps/{app_id}/policies/{policy_id}",
        headers={"Authorization": f"Bearer {api_token}"},
        timeout=timeout,
    )
    resp.raise_for_status()
    body = resp.json()
    if not body.get("success"):
        raise RuntimeError(f"Cloudflare error fetching policy: {body.get('errors')}")
    return body["result"]


def _put_policy(
    api_token: str, account_id: str, app_id: str, policy_id: str, policy: dict, *, timeout: float,
) -> tuple[bool, str]:
    try:
        resp = requests.put(
            f"{_API_BASE}/accounts/{account_id}/access/apps/{app_id}/policies/{policy_id}",
            headers={"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"},
            timeout=timeout,
            json={
                "name": policy["name"],
                "decision": policy["decision"],
                "include": policy["include"],
                "exclude": policy.get("exclude", []),
                "require": policy.get("require", []),
            },
        )
        resp.raise_for_status()
        body = resp.json()
        if not body.get("success"):
            return False, f"Cloudflare error: {body.get('errors')}"
    except requests.RequestException as exc:
        return False, f"Cloudflare Access policy update failed: {exc}"
    return True, ""


def add_policy_include_email(
    api_token: str, account_id: str, app_id: str, policy_id: str, email: str, *, timeout: float = 15.0,
) -> tuple[bool, str]:
    try:
        policy = _get_policy(api_token, account_id, app_id, policy_id, timeout=timeout)
    except (requests.RequestException, RuntimeError) as exc:
        return False, f"couldn't fetch current policy: {exc}"

    email = email.lower()
    already_present = any(
        entry.get("email", {}).get("email", "").lower() == email for entry in policy["include"]
    )
    if already_present:
        return True, "already present"

    policy["include"].append({"email": {"email": email}})
    return _put_policy(api_token, account_id, app_id, policy_id, policy, timeout=timeout)


def remove_policy_include_email(
    api_token: str, account_id: str, app_id: str, policy_id: str, email: str, *, timeout: float = 15.0,
) -> tuple[bool, str]:
    try:
        policy = _get_policy(api_token, account_id, app_id, policy_id, timeout=timeout)
    except (requests.RequestException, RuntimeError) as exc:
        return False, f"couldn't fetch current policy: {exc}"

    email = email.lower()
    remaining = [
        entry for entry in policy["include"]
        if entry.get("email", {}).get("email", "").lower() != email
    ]
    if len(remaining) == len(policy["include"]):
        return True, "already absent"

    policy["include"] = remaining
    return _put_policy(api_token, account_id, app_id, policy_id, policy, timeout=timeout)
