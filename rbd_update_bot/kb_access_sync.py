"""Keeps a Cloudflare Access rule group in sync with Immich's user list."""
from __future__ import annotations

import requests

_API_BASE = "https://api.cloudflare.com/client/v4"

_IMMICH_USERS_PATH = "/api/admin/users"


def _cf_headers(api_token: str) -> dict:
    return {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}


def collect_immich_emails(base_url: str, api_key: str, *, timeout: float = 15.0) -> tuple[list[str] | None, str]:
    try:
        resp = requests.get(
            f"{base_url}{_IMMICH_USERS_PATH}", headers={"x-api-key": api_key}, timeout=timeout,
        )
        resp.raise_for_status()
        users = resp.json()
    except requests.RequestException as exc:
        return None, f"Immich user-list request failed: {exc}"
    except ValueError as exc:
        return None, f"Immich user-list response wasn't JSON: {exc}"

    emails: list[str] = []
    for user in users:
        if user.get("deletedAt"):
            continue
        email = (user.get("email") or "").strip().lower()
        if email:
            emails.append(email)
    return emails, ""


def get_group_emails(api_token: str, account_id: str, group_id: str, *, timeout: float = 15.0) -> tuple[list[str] | None, str]:
    try:
        resp = requests.get(
            f"{_API_BASE}/accounts/{account_id}/access/groups/{group_id}",
            headers=_cf_headers(api_token), timeout=timeout,
        )
        resp.raise_for_status()
        body = resp.json()
        if not body.get("success"):
            return None, f"Cloudflare error: {body.get('errors')}"
        include = body["result"].get("include", [])
    except requests.RequestException as exc:
        return None, f"Cloudflare Access group fetch failed: {exc}"
    except (KeyError, TypeError, ValueError) as exc:
        return None, f"unexpected Cloudflare Access group response shape: {exc}"

    emails: list[str] = []
    for rule in include:
        email = (rule.get("email") or {}).get("email")
        if email:
            emails.append(email.strip().lower())
    return emails, ""


def set_group_emails(api_token: str, account_id: str, group_id: str, emails: list[str], *, timeout: float = 15.0) -> tuple[bool, str]:
    include = [{"email": {"email": email}} for email in emails]
    try:
        resp = requests.put(
            f"{_API_BASE}/accounts/{account_id}/access/groups/{group_id}",
            headers=_cf_headers(api_token), timeout=timeout,
            json={"include": include},
        )
        resp.raise_for_status()
        body = resp.json()
        if not body.get("success"):
            return False, f"Cloudflare error: {body.get('errors')}"
    except requests.RequestException as exc:
        return False, f"Cloudflare Access group update failed: {exc}"
    return True, ""


def diff_emails(current: list[str], desired: list[str]) -> tuple[list[str], list[str]]:
    current_set, desired_set = set(current), set(desired)
    return sorted(desired_set - current_set), sorted(current_set - desired_set)
