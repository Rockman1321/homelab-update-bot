"""Microsoft Graph monitor for mailbox rules and sign-ins."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import requests

_TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
_GRAPH_BASE = "https://graph.microsoft.com/v1.0"

_LEGACY_AUTH_CLIENT_APPS = {
    "Exchange ActiveSync", "IMAP4", "IMAP", "POP3", "POP", "SMTP",
    "Authenticated SMTP", "Other clients",
}
_FAILED_BURST_THRESHOLD = 5
_FAILED_BURST_WINDOW_SECONDS = 600
_MAX_SIGNIN_PAGES = 20


def _get_token(client_id: str, client_secret: str, tenant_id: str) -> tuple[str | None, str | None]:
    try:
        resp = requests.post(
            _TOKEN_URL.format(tenant_id=tenant_id),
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
            },
            timeout=15,
        )
        body = resp.json()
        if resp.status_code != 200 or "access_token" not in body:
            return None, f"token request failed ({resp.status_code}): {body.get('error_description') or body}"
        return body["access_token"], None
    except requests.RequestException as exc:
        return None, f"token request failed: {exc}"
    except ValueError as exc:
        return None, f"token response wasn't JSON: {exc}"


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def collect_inbox_rules(token: str, user_ids: list[str]) -> tuple[dict[str, list[dict]], list[str]]:
    rules_by_user: dict[str, list[dict]] = {}
    errors: list[str] = []
    for user_id in user_ids:
        try:
            resp = requests.get(
                f"{_GRAPH_BASE}/users/{user_id}/mailFolders/inbox/messageRules",
                headers=_headers(token), timeout=20,
            )
            resp.raise_for_status()
            rules_by_user[user_id] = resp.json().get("value", [])
        except requests.RequestException as exc:
            errors.append(f"{user_id}: {exc}")
    return rules_by_user, errors


def collect_signin_events(token: str, since_iso: str) -> tuple[list[dict], str | None]:
    events: list[dict] = []
    url = f"{_GRAPH_BASE}/auditLogs/signIns"
    params = {
        "$filter": f"createdDateTime ge {since_iso}",
        "$orderby": "createdDateTime asc",
    }
    try:
        for _ in range(_MAX_SIGNIN_PAGES):
            resp = requests.get(url, headers=_headers(token), params=params, timeout=20)
            if resp.status_code != 200:
                body = resp.text[:500]
                return events, f"signIns request failed ({resp.status_code}): {body}"
            body = resp.json()
            events.extend(body.get("value", []))
            next_link = body.get("@odata.nextLink")
            if not next_link:
                break
            url, params = next_link, None
        return events, None
    except requests.RequestException as exc:
        return events, f"signIns request failed: {exc}"


def flag_signin_events(events: list[dict]) -> list[dict]:
    flagged: list[dict] = []

    for event in events:
        client_app = event.get("clientAppUsed") or ""
        status = event.get("status") or {}
        error_code = status.get("errorCode")
        user = event.get("userPrincipalName") or "unknown"
        when = event.get("createdDateTime") or ""

        if client_app in _LEGACY_AUTH_CLIENT_APPS:
            flagged.append({
                "category": "legacy_auth", "severity": "warning", "event": event,
                "summary": f"{user}: legacy/basic auth ({client_app}) at {when}",
            })

        risk_level = event.get("riskLevelAggregated")
        risk_state = event.get("riskState")
        if risk_level and risk_level not in ("none", "hidden"):
            flagged.append({
                "category": "entra_risk", "severity": "warning", "event": event,
                "summary": f"{user}: Entra risk level {risk_level!r} (state {risk_state!r}) at {when}",
            })

        country = (event.get("location") or {}).get("countryOrRegion")
        if country and country != "US":
            flagged.append({
                "category": "non_us_country", "severity": "info", "event": event,
                "summary": f"{user}: sign-in from {country} at {when}",
            })

    failures_by_user: dict[str, list[datetime]] = {}
    for event in events:
        status = event.get("status") or {}
        if not status.get("errorCode"):
            continue
        when_raw = event.get("createdDateTime")
        if not when_raw:
            continue
        user = event.get("userPrincipalName") or "unknown"
        when = datetime.fromisoformat(when_raw.replace("Z", "+00:00"))
        failures_by_user.setdefault(user, []).append(when)

    for user, timestamps in failures_by_user.items():
        timestamps.sort()
        for i, start in enumerate(timestamps):
            window_end = start + timedelta(seconds=_FAILED_BURST_WINDOW_SECONDS)
            count_in_window = sum(1 for t in timestamps[i:] if t <= window_end)
            if count_in_window >= _FAILED_BURST_THRESHOLD:
                flagged.append({
                    "category": "failed_signin_burst", "severity": "warning", "event": {"user": user},
                    "summary": (
                        f"{user}: {count_in_window} failed sign-ins within "
                        f"{_FAILED_BURST_WINDOW_SECONDS // 60} minutes starting {start.isoformat()}"
                    ),
                })
                break

    return flagged


def flag_admin_signin_events(events: list[dict], admin_upn: str, home_ip: str | None) -> list[dict]:
    if not admin_upn or not home_ip:
        return []

    flagged: list[dict] = []
    for event in events:
        if (event.get("userPrincipalName") or "") != admin_upn:
            continue
        source_ip = event.get("ipAddress")
        when = event.get("createdDateTime") or ""
        if source_ip and source_ip != home_ip:
            flagged.append({
                "category": "admin_signin_untrusted_ip", "severity": "critical", "event": event,
                "summary": (
                    f"Global Admin sign-in from {source_ip} (home is currently {home_ip}) at {when}"
                ),
            })
    return flagged
