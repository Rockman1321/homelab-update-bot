"""Talks to the Continuwuity (Matrix homeserver) admin room."""
from __future__ import annotations

import re
import time
import uuid

import requests


def _headers(access_token: str) -> dict:
    return {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}


def send_admin_command(
    homeserver: str, access_token: str, admin_room_id: str, command: str, *, timeout: float = 15.0,
) -> tuple[str | None, str]:
    txn_id = uuid.uuid4().hex
    try:
        resp = requests.put(
            f"{homeserver}/_matrix/client/v3/rooms/{admin_room_id}/send/m.room.message/{txn_id}",
            headers=_headers(access_token), timeout=timeout,
            json={"msgtype": "m.text", "body": command},
        )
        resp.raise_for_status()
        event_id = resp.json().get("event_id")
        if not event_id:
            return None, f"no event_id in send response: {resp.text[:300]}"
        return event_id, ""
    except requests.RequestException as exc:
        return None, f"sending admin command failed: {exc}"


def await_admin_reply(
    homeserver: str, access_token: str, admin_room_id: str, admin_bot_user_id: str, *,
    poll_interval: float = 2.0, timeout: float = 30.0,
) -> tuple[str | None, str]:
    deadline = time.time() + timeout
    started = time.time()
    while time.time() < deadline:
        try:
            resp = requests.get(
                f"{homeserver}/_matrix/client/v3/rooms/{admin_room_id}/messages",
                headers=_headers(access_token), timeout=15.0,
                params={"dir": "b", "limit": 20},
            )
            resp.raise_for_status()
            for event in resp.json().get("chunk", []):
                if (event.get("sender") == admin_bot_user_id
                        and event.get("type") == "m.room.message"
                        and (event.get("origin_server_ts", 0) / 1000.0) >= started):
                    body = (event.get("content") or {}).get("body")
                    if body:
                        return body, ""
        except requests.RequestException as exc:
            return None, f"polling for admin reply failed: {exc}"
        time.sleep(poll_interval)
    return None, f"no reply from {admin_bot_user_id} within {timeout}s"


def run_admin_command(
    homeserver: str, access_token: str, admin_room_id: str, command: str, admin_bot_user_id: str, *,
    reply_timeout: float = 30.0,
) -> tuple[str | None, str]:
    event_id, err = send_admin_command(homeserver, access_token, admin_room_id, command)
    if not event_id:
        return None, err
    return await_admin_reply(homeserver, access_token, admin_room_id, admin_bot_user_id, timeout=reply_timeout)


def parse_user_list(reply_text: str) -> list[str]:
    users: list[str] = []
    for line in reply_text.splitlines():
        token = line.strip().strip("`").strip().lstrip("-*• ").strip()
        if token.startswith("@") and ":" in token:
            users.append(token.split()[0])
    return users


_ISSUED_TOKEN_RE = re.compile(r"token issued:\s*([A-Za-z0-9]+)")


def parse_issued_token(reply_text: str) -> str | None:
    m = _ISSUED_TOKEN_RE.search(reply_text)
    return m.group(1) if m else None


_TOKEN_USAGE_RE = re.compile(r"and used (\d+) times\.\s*Expires after (\d+) uses")


def parse_token_uses_remaining(reply_text: str, token: str) -> int | None:
    for line in reply_text.splitlines():
        if token not in line:
            continue
        m = _TOKEN_USAGE_RE.search(line)
        if not m:
            return None
        used, max_uses = int(m.group(1)), int(m.group(2))
        return max_uses - used
    return None
