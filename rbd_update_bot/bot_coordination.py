"""Bot-to-bot messages with pass-bot over a shared Matrix room (mail rules, heartbeats, maintenance, status)."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

CONTENT_KEY = "com.example.bot"
MAX_TTL = timedelta(hours=2)
MAX_CLOCK_SKEW = timedelta(minutes=5)
RULE_PREFIX = "pass-bot: "
_ALLOWED_ACTIONS = {"moveToFolder", "stopProcessingRules"}
MAINTENANCE_MAX = timedelta(hours=3)


def normalize_rule(rule: dict) -> dict:
    def part(d: dict | None) -> dict:
        out = {}
        for k, v in (d or {}).items():
            if v in (None, False, "", [], {}):
                continue
            out[k] = sorted(str(x).lower() for x in v) if isinstance(v, list) else v
        return out
    return {"displayName": rule.get("displayName", ""), "isEnabled": bool(rule.get("isEnabled", True)),
            "conditions": part(rule.get("conditions")), "exceptions": part(rule.get("exceptions")),
            "actions": part(rule.get("actions"))}


def parse_declaration(content: dict, sender: str, trusted_sender: str, now: datetime) -> dict | None:
    if not trusted_sender or sender != trusted_sender:
        return None
    d = content.get(CONTENT_KEY)
    if not isinstance(d, dict) or d.get("v") != 1 or d.get("type") != "mail_rule":
        return None
    if d.get("action") not in ("create", "update", "delete") or not isinstance(d.get("rule"), dict):
        return None
    if not d.get("id") or not d.get("mailbox"):
        return None
    try:
        at = datetime.fromisoformat(d["at"])
    except (KeyError, TypeError, ValueError):
        return None
    if at.tzinfo is None or at > now + MAX_CLOCK_SKEW:
        return None
    ttl = min(timedelta(seconds=float(d.get("ttl_s") or 0)), MAX_TTL)
    return {"id": str(d["id"]), "mailbox": str(d["mailbox"]).lower(), "action": d["action"],
            "rule_id": str(d.get("rule_id") or ""), "rule": normalize_rule(d["rule"]),
            "folder_name": str(d.get("folder_name") or ""), "reason": str(d.get("reason") or ""),
            "declared_at": at.astimezone(timezone.utc).isoformat(),
            "expires_at": (at + ttl).astimezone(timezone.utc).isoformat()}


def guardrail_issues(rule: dict, mailbox: str, allowed_mailboxes: list[str]) -> list[str]:
    n = normalize_rule(rule)
    issues = []
    extra = sorted(set(n["actions"]) - _ALLOWED_ACTIONS)
    if extra:
        issues.append(f"actions beyond moving mail: {', '.join(extra)}")
    if not n["displayName"].startswith(RULE_PREFIX):
        issues.append(f"name doesn't start with {RULE_PREFIX.strip()!r}")
    if mailbox.lower() not in [m.lower() for m in allowed_mailboxes]:
        issues.append(f"{mailbox} isn't one of pass-bot's mailboxes")
    return issues


def _strip_order(rule: dict) -> dict:
    return {k: v for k, v in rule.items() if k != "sequence"}


def classify_rule_change(kind: str, mailbox: str, rule: dict, previous: dict | None,
                         declarations: list[dict], allowed_mailboxes: list[str],
                         now: datetime) -> tuple[str, str]:
    mailbox = mailbox.lower()
    if kind == "modified" and previous is not None and _strip_order(previous) == _strip_order(rule):
        return "order", f"position changed only ({previous.get('sequence')} → {rule.get('sequence')})"
    if kind != "deleted":
        issues = guardrail_issues(rule, mailbox, allowed_mailboxes)
        if issues:
            return "warn", "; ".join(issues)
    want = {"new": ("create", "update"), "modified": ("update",), "deleted": ("delete",)}[kind]
    seen = normalize_rule(rule)
    for d in declarations:
        if d["mailbox"] != mailbox or d["action"] not in want:
            continue
        if not (datetime.fromisoformat(d["declared_at"]) <= now + MAX_CLOCK_SKEW
                and now <= datetime.fromisoformat(d["expires_at"])):
            continue
        if kind == "deleted":
            if d["rule_id"] and d["rule_id"] == rule.get("id"):
                return "expected", d["reason"] or "declared delete"
            continue
        if d["rule_id"] and d["rule_id"] != rule.get("id"):
            continue
        if d["rule"] == seen:
            return "expected", d["reason"] or "declared"
    return "warn", "no matching pass-bot declaration"


def maintenance_notice(service: str, state: str, kind: str, now: datetime) -> dict:
    when = now.astimezone().strftime("%-I:%M %p")
    body = (f"[update bot] {service}: {kind or 'maintenance'} started {when}" if state == "begin"
            else f"[update bot] {service}: maintenance finished {when}")
    payload = {"v": 1, "type": "maintenance", "id": uuid.uuid4().hex, "at": now.isoformat(),
               "service": service, "state": state, "kind": kind}
    if state == "begin":
        payload["until"] = (now + MAINTENANCE_MAX).isoformat()
    return {"msgtype": "m.notice", "body": body, CONTENT_KEY: payload}


_WAITING = {"staged_pending_approval": "!approve", "awaiting_backup_decision": "!confirm-backup",
            "awaiting_reboot_decision": "!confirm-reboot"}
STATUS_REFRESH = timedelta(hours=6)


def status_snapshot(records: list, findings: list[dict], window: dict | None, now: datetime) -> dict:
    waiting = []
    for r in records:
        cmd = _WAITING.get(r.stage.value)
        if cmd is None:
            continue
        kind = getattr(r, "kind", "container")
        what = {"os_patch": "OS patches", "reboot": "reboot"}.get(kind) or (
            f"{r.current_version} → {r.new_version}" if r.current_version != r.new_version
            else f"new {r.new_version} build")
        waiting.append({"id": r.id, "service": r.service_name, "what": what, "command": f"{cmd} {r.id}"})
    sev = {"critical": 0, "warning": 0, "new_critical": 0, "new_warning": 0}
    for f in findings:
        level = f.get("severity")
        if level not in ("critical", "warning"):
            continue
        sev[level] += 1
        try:
            if now - datetime.fromisoformat(f["created_at"]) < timedelta(hours=24):
                sev[f"new_{level}"] += 1
        except (KeyError, TypeError, ValueError):
            pass
    return {"waiting": waiting, "window": window, "findings": sev}


def status_notice(snapshot: dict, now: datetime) -> dict:
    parts = []
    if snapshot["waiting"]:
        parts.append("waiting on The owner: " + ", ".join(f"`{w['command']}` ({w['service']})" for w in snapshot["waiting"]))
    w = snapshot["window"]
    if w:
        start = datetime.fromisoformat(w["start"]).strftime("%a %-I:%M %p")
        parts.append(f"window {start} ({w['approval'] or 'not asked yet'})")
    f = snapshot["findings"]
    parts.append(f"open findings: {f['critical']} critical, {f['warning']} warning "
                 f"({f['new_critical']} / {f['new_warning']} new in 24h)")
    payload = {"v": 1, "type": "status", "id": uuid.uuid4().hex, "at": now.isoformat(),
               "valid_for_s": int((STATUS_REFRESH + timedelta(hours=1)).total_seconds()), **snapshot}
    return {"msgtype": "m.notice", "body": "[update bot] Status: " + "; ".join(parts), CONTENT_KEY: payload}


HEARTBEAT_SOURCE = "pass_bot"
HEARTBEAT_MISSED_AFTER = 3


def parse_heartbeat(content: dict, sender: str, trusted_sender: str, now: datetime) -> dict | None:
    if not trusted_sender or sender != trusted_sender:
        return None
    d = content.get(CONTENT_KEY)
    if not isinstance(d, dict) or d.get("v") != 1 or d.get("type") != "heartbeat":
        return None
    try:
        at = datetime.fromisoformat(d["at"])
        interval = timedelta(seconds=max(60.0, min(float(d.get("interval_s") or 0), 6 * 3600)))
    except (KeyError, TypeError, ValueError):
        return None
    if at.tzinfo is None or at > now + MAX_CLOCK_SKEW:
        return None
    checks = []
    for c in d.get("checks") or []:
        if not isinstance(c, dict) or not str(c.get("id", "")).startswith("passbot:"):
            continue
        checks.append({"id": str(c["id"])[:64], "ok": bool(c.get("ok")), "detail": str(c.get("detail") or "")[:120]})
    return {"at": at, "interval": interval, "checks": checks}


def heartbeat_ops_checks(hb: dict) -> list[dict]:
    return [{"check_id": c["id"], "source": HEARTBEAT_SOURCE, "status": "ok" if c["ok"] else "failing",
             "detail": c["detail"] or ("ok" if c["ok"] else "failing"), "is_bad": not c["ok"]}
            for c in hb["checks"]]


def heartbeat_overdue(last_at: datetime | None, interval: timedelta, now: datetime) -> dict | None:
    if last_at is None:
        return None
    late = now - last_at > interval * HEARTBEAT_MISSED_AFTER
    detail = (f"no heartbeat since {last_at.astimezone(timezone.utc):%Y-%m-%d %H:%M} UTC" if late
              else "heartbeats arriving")
    return {"check_id": "passbot:heartbeat", "source": HEARTBEAT_SOURCE,
            "status": "missing" if late else "ok", "detail": detail, "is_bad": late}
