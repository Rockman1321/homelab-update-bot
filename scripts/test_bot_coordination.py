#!/usr/bin/env python3
"""Offline test of the pass-bot coordination messages."""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rbd_update_bot.bot_coordination import (
    CONTENT_KEY, classify_rule_change, guardrail_issues, maintenance_notice, parse_declaration,
    heartbeat_ops_checks, heartbeat_overdue, parse_heartbeat, status_notice, status_snapshot,
)
from rbd_update_bot.db import Store

PASS_BOT = "@pass-bot:example.com"
MBX = "bills@example.com"
MAILBOXES = ["owner@example.com", "bills@example.com", "subscriptions@example.com"]
NOW = datetime(2026, 10, 29, 20, 0, tzinfo=timezone.utc)

DECLARED = {"displayName": "pass-bot: Promotions", "isEnabled": True,
            "conditions": {"senderContains": ["@shop.example"]}, "exceptions": {},
            "actions": {"moveToFolder": "AAMkFolder1", "stopProcessingRules": True}}
SEEN = {"id": "AQAAAJ5dZp8=", "displayName": "pass-bot: Promotions", "sequence": 4, "isEnabled": True,
        "hasError": False, "isReadOnly": False,
        "conditions": {"senderContains": ["@SHOP.EXAMPLE"]}, "exceptions": None,
        "actions": {"moveToFolder": "AAMkFolder1", "stopProcessingRules": True}}


def content(action="create", at=NOW - timedelta(minutes=20), rule=DECLARED, **over):
    d = {"v": 1, "type": "mail_rule", "id": over.pop("id", "d1"), "at": at.isoformat(), "ttl_s": 7200,
         "mailbox": MBX, "action": action, "rule_id": "", "rule": rule, "folder_name": "Promotions",
         "reason": "from shop.example"}
    d.update(over)
    return {"msgtype": "m.notice", "body": "[pass-bot] Creating …", CONTENT_KEY: d}


def classify(kind, rule, decls, previous=None, mailbox=MBX, now=NOW):
    return classify_rule_change(kind, mailbox, rule, previous, decls, MAILBOXES, now)


def check_parse() -> None:
    assert parse_declaration(content(), PASS_BOT, PASS_BOT, NOW)["mailbox"] == MBX
    assert parse_declaration(content(), "@mallory:example.com", PASS_BOT, NOW) is None
    assert parse_declaration(content(), PASS_BOT, "", NOW) is None
    assert parse_declaration({"body": "hi"}, PASS_BOT, PASS_BOT, NOW) is None
    assert parse_declaration(content(v=2), PASS_BOT, PASS_BOT, NOW) is None
    assert parse_declaration(content(action="forward"), PASS_BOT, PASS_BOT, NOW) is None
    assert parse_declaration(content(at=NOW + timedelta(hours=1)), PASS_BOT, PASS_BOT, NOW) is None
    bad = content(); bad[CONTENT_KEY]["at"] = "2026-10-29T19:00:00"
    assert parse_declaration(bad, PASS_BOT, PASS_BOT, NOW) is None
    d = parse_declaration(content(ttl_s=10 ** 9), PASS_BOT, PASS_BOT, NOW)
    assert datetime.fromisoformat(d["expires_at"]) == NOW - timedelta(minutes=20) + timedelta(hours=2)


def check_store_replay() -> None:
    store = Store(":memory:")
    d = parse_declaration(content(), PASS_BOT, PASS_BOT, NOW)
    assert store.record_bot_declaration(d, PASS_BOT) is True
    assert store.record_bot_declaration(d, PASS_BOT) is False
    live = store.live_bot_declarations(MBX.upper(), NOW.isoformat())
    assert len(live) == 1 and live[0]["rule"]["displayName"] == "pass-bot: Promotions"
    assert store.live_bot_declarations(MBX, (NOW + timedelta(hours=3)).isoformat()) == []
    store.live_bot_declarations(MBX, (NOW + timedelta(days=3)).isoformat())
    assert store._conn.execute("SELECT COUNT(*) FROM bot_declarations").fetchone()[0] == 0

    store.record_mailbox_rule_sightings(MBX, [SEEN])
    assert store.mailbox_rule_bodies(MBX)[SEEN["id"]] == json.loads(json.dumps(SEEN, sort_keys=True))


def check_classify() -> None:
    d = parse_declaration(content(), PASS_BOT, PASS_BOT, NOW)
    assert classify("new", SEEN, [d]) == ("expected", "from shop.example")
    assert classify("new", SEEN, [])[0] == "warn"
    assert classify("new", SEEN, [d], mailbox="subscriptions@example.com")[0] == "warn"
    assert classify("new", SEEN, [d], now=NOW + timedelta(hours=3))[0] == "warn"
    assert classify("new", {**SEEN, "displayName": "pass-bot: Bills"}, [d])[0] == "warn"
    folder2 = {**SEEN, "actions": {**SEEN["actions"], "moveToFolder": "AAMkFolder2"}}
    assert classify("new", folder2, [d])[0] == "warn"

    fwd = {**DECLARED, "actions": {**DECLARED["actions"], "forwardTo": [{"emailAddress": {"address": "x@evil.test"}}]}}
    d_fwd = parse_declaration(content(rule=fwd, id="d2"), PASS_BOT, PASS_BOT, NOW)
    verdict, why = classify("new", {**SEEN, "actions": fwd["actions"]}, [d_fwd])
    assert verdict == "warn" and "forwardTo" in why, why
    assert classify("new", {**SEEN, "displayName": "Promotions"}, [])[1].startswith("name doesn't")
    assert guardrail_issues(SEEN, "someone@example.org", MAILBOXES) == ["someone@example.org isn't one of pass-bot's mailboxes"]
    for bad in ({"delete": True}, {"markAsRead": True}, {"redirectTo": [{"x": 1}]}, {"permanentDelete": True}):
        assert guardrail_issues({**SEEN, "actions": {**SEEN["actions"], **bad}}, MBX, MAILBOXES)

    moved = {**SEEN, "sequence": 3}
    assert classify("modified", moved, [], previous=SEEN)[0] == "order"
    edited = {**SEEN, "conditions": {"senderContains": ["@SHOP.EXAMPLE", "@EXAMPLE.COM"]}}
    assert classify("modified", edited, [d], previous=SEEN)[0] == "warn"
    upd_rule = {**DECLARED, "conditions": {"senderContains": ["@example.com", "@shop.example"]}}
    d_upd = parse_declaration(content(action="update", rule=upd_rule, rule_id=SEEN["id"], id="d3"), PASS_BOT, PASS_BOT, NOW)
    assert classify("modified", edited, [d_upd], previous=SEEN)[0] == "expected"
    other_id = parse_declaration(content(action="update", rule=upd_rule, rule_id="OTHER", id="d4"), PASS_BOT, PASS_BOT, NOW)
    assert classify("modified", edited, [other_id], previous=SEEN)[0] == "warn"
    d_upd_noid = parse_declaration(content(action="update", rule=upd_rule, id="d5"), PASS_BOT, PASS_BOT, NOW)
    assert classify("new", edited, [d_upd_noid])[0] == "expected"

    d_del = parse_declaration(content(action="delete", rule_id=SEEN["id"], id="d6"), PASS_BOT, PASS_BOT, NOW)
    gone = {"id": SEEN["id"], "displayName": "pass-bot: Promotions"}
    assert classify("deleted", gone, [d_del])[0] == "expected"
    assert classify("deleted", {"id": "USERS", "displayName": "Apple Glen"}, [d_del])[0] == "warn"


def check_maintenance_notice() -> None:
    b = maintenance_notice("mass", "begin", "update", NOW)
    d = b[CONTENT_KEY]
    assert b["msgtype"] == "m.notice" and b["body"].startswith("[update bot] mass: update started")
    assert d["v"] == 1 and d["type"] == "maintenance" and d["state"] == "begin"
    assert datetime.fromisoformat(d["until"]) == NOW + timedelta(hours=3)
    e = maintenance_notice("mass", "end", "", NOW)
    assert "until" not in e[CONTENT_KEY] and "finished" in e["body"]
    assert parse_declaration(b, PASS_BOT, PASS_BOT, NOW) is None


def check_status_snapshot() -> None:
    from types import SimpleNamespace as NS
    from rbd_update_bot.models import Stage
    recs = [NS(id=130, service_name="nextcloud", stage=Stage.STAGED_PENDING_APPROVAL, kind="container",
               current_version="31.0.9", new_version="32.0.1"),
            NS(id=150, service_name="mass", stage=Stage.AWAITING_REBOOT_DECISION, kind="reboot",
               current_version="n/a", new_version="n/a"),
            NS(id=135, service_name="discourse", stage=Stage.STAGED_PENDING_APPROVAL, kind="container",
               current_version="release", new_version="release"),
            NS(id=151, service_name="joplin", stage=Stage.UPDATING, kind="container",
               current_version="1", new_version="2")]
    old = (NOW - timedelta(days=5)).isoformat()
    findings = [{"severity": "critical", "created_at": old, "summary": "192.168.50.5 port 22 open"},
                {"severity": "warning", "created_at": (NOW - timedelta(hours=2)).isoformat(), "summary": "x"},
                {"severity": "info", "created_at": old, "summary": "y"}]
    window = {"start": "2026-10-31T01:00:00-05:00", "services": ["joplin", "mass"], "approval": "pending"}
    snap = status_snapshot(recs, findings, window, NOW)
    assert snap["waiting"] == [
        {"id": 130, "service": "nextcloud", "what": "31.0.9 → 32.0.1", "command": "!approve 130"},
        {"id": 150, "service": "mass", "what": "reboot", "command": "!confirm-reboot 150"},
        {"id": 135, "service": "discourse", "what": "new release build", "command": "!approve 135"}]
    assert snap["findings"] == {"critical": 1, "warning": 1, "new_critical": 0, "new_warning": 1}
    assert "10.91" not in json.dumps(snap)
    assert status_snapshot(recs, findings, window, NOW) == snap
    n = status_notice(snap, NOW)
    assert n[CONTENT_KEY]["type"] == "status" and n[CONTENT_KEY]["waiting"] == snap["waiting"]
    assert "`!approve 130` (nextcloud)" in n["body"] and "window Sat 1:00 AM (pending)" in n["body"], n["body"]
    assert parse_declaration(n, PASS_BOT, PASS_BOT, NOW) is None


def hb_content(at=NOW - timedelta(minutes=1), checks=None, **over):
    d = {"v": 1, "type": "heartbeat", "id": "h1", "at": at.isoformat(), "interval_s": 1800,
         "checks": checks if checks is not None else [
             {"id": "passbot:ha_calendars", "ok": True, "detail": ""},
             {"id": "passbot:wedding_hub", "ok": False, "detail": "ConnectionError"}]}
    d.update(over)
    return {"msgtype": "m.notice", "body": "[pass-bot] heartbeat", CONTENT_KEY: d}


def check_heartbeat() -> None:
    hb = parse_heartbeat(hb_content(), PASS_BOT, PASS_BOT, NOW)
    assert hb["interval"] == timedelta(minutes=30) and len(hb["checks"]) == 2
    assert parse_heartbeat(hb_content(), "@mallory:example.com", PASS_BOT, NOW) is None
    assert parse_heartbeat(hb_content(at=NOW + timedelta(hours=1)), PASS_BOT, PASS_BOT, NOW) is None
    assert parse_heartbeat(content(), PASS_BOT, PASS_BOT, NOW) is None
    assert parse_declaration(hb_content(), PASS_BOT, PASS_BOT, NOW) is None
    sneaky = parse_heartbeat(hb_content(checks=[{"id": "kuma:immich", "ok": True},
                                                {"id": "passbot:ollama", "ok": True}]), PASS_BOT, PASS_BOT, NOW)
    assert [c["id"] for c in sneaky["checks"]] == ["passbot:ollama"]
    assert parse_heartbeat(hb_content(interval_s=10 ** 9), PASS_BOT, PASS_BOT, NOW)["interval"] == timedelta(hours=6)

    store = Store(":memory:")
    ops = heartbeat_ops_checks(hb)
    assert ops[1] == {"check_id": "passbot:wedding_hub", "source": "pass_bot", "status": "failing",
                      "detail": "ConnectionError", "is_bad": True}
    assert store.record_ops_health(ops) == []
    later = heartbeat_ops_checks(parse_heartbeat(hb_content(checks=[
        {"id": "passbot:ha_calendars", "ok": False, "detail": "HTTPError"},
        {"id": "passbot:wedding_hub", "ok": True, "detail": ""}]), PASS_BOT, PASS_BOT, NOW))
    assert sorted((e["check_id"], e["event"]) for e in store.record_ops_health(later)) == [
        ("passbot:ha_calendars", "alert"), ("passbot:wedding_hub", "recovered")]

    assert heartbeat_overdue(None, timedelta(minutes=30), NOW) is None
    assert not heartbeat_overdue(NOW - timedelta(minutes=80), timedelta(minutes=30), NOW)["is_bad"]
    late = heartbeat_overdue(NOW - timedelta(minutes=95), timedelta(minutes=30), NOW)
    assert late["is_bad"] and late["check_id"] == "passbot:heartbeat" and "18:25" in late["detail"], late


def main() -> None:
    check_parse()
    check_store_replay()
    check_classify()
    check_maintenance_notice()
    check_status_snapshot()
    check_heartbeat()
    print("test_bot_coordination: all checks passed")


if __name__ == "__main__":
    main()
