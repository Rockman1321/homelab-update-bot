"""SQLite state store: updates, stage events, findings and the audit trail."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .models import RiskAssessment, Stage, UpdateRecord

_SCHEMA = """
CREATE TABLE IF NOT EXISTS updates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_name TEXT NOT NULL,
    image TEXT NOT NULL,
    current_version TEXT NOT NULL,
    new_version TEXT NOT NULL,
    diun_entry_id TEXT NOT NULL UNIQUE,
    stage TEXT NOT NULL,
    risk_level TEXT,
    breaking_changes INTEGER,
    risk_summary TEXT,
    release_notes_url TEXT,
    approved_by TEXT,
    approved_at TEXT,
    error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    backup_decision TEXT,
    kind TEXT NOT NULL DEFAULT 'container',
    reboot_decision TEXT,
    digest TEXT,
    security_severity TEXT
);

CREATE TABLE IF NOT EXISTS stage_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    update_id INTEGER NOT NULL REFERENCES updates(id),
    stage TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- Small generic key/value table for bot-internal bookkeeping that isn't
-- about any one update -- currently just matrix_bot.py's "last processed
-- message timestamp" watermark, so a restart doesn't replay the room's
-- entire history through every command handler again.
CREATE TABLE IF NOT EXISTS bot_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Baseline/state for the active network monitor (Omada + FortiGate DHCP
-- device collection). mac is normalized lowercase-colon by
-- investigate_wrapper.py's collector before this ever sees it, so the
-- same physical device reported by both sources collapses to one row.
CREATE TABLE IF NOT EXISTS known_devices (
    mac TEXT PRIMARY KEY,
    ip TEXT,
    hostname TEXT,
    vlan TEXT,
    port TEXT,
    source TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    label TEXT,
    trusted_at TEXT
);

-- Unified incident record for the two cheap collect+diff monitors
-- (network_monitor, disk_health) -- the connective tissue between
-- "detect" and "investigate/fix". Gives each monitor's finding a
-- severity and a status lifecycle instead of being a fire-and-forget
-- Matrix message with no persistent record. See virtual_engineer_vision
-- memory / the 2026-09-29 findings-table plan for the full rationale.
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    subject TEXT NOT NULL,
    severity TEXT NOT NULL,
    summary TEXT NOT NULL,
    detail TEXT,
    status TEXT NOT NULL,
    investigation_report TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    resolved_at TEXT
);

-- State-transition tracking for the disk/storage health monitor (Proxmox
-- node boot drives, PBS host, Synology). Unlike known_devices (presence/
-- absence), this tracks the last-seen *state* of each disk so a
-- notification only fires on a genuine transition (good -> bad, or
-- bad -> recovered), not on every poll while a disk stays in whatever
-- state it's already in.
CREATE TABLE IF NOT EXISTS disk_health (
    disk_id TEXT PRIMARY KEY,
    source TEXT,
    model TEXT,
    health TEXT,
    wearout INTEGER,
    last_checked TEXT NOT NULL,
    last_alerted_bad INTEGER NOT NULL DEFAULT 0
);

-- Same state-transition pattern as disk_health, generalized for the
-- operational health checks (backup job status, disk space, TLS
-- expiry) -- source-agnostic naming (check_id/status) since these
-- aren't about a disk specifically.
CREATE TABLE IF NOT EXISTS ops_health (
    check_id TEXT PRIMARY KEY,
    source TEXT,
    status TEXT,
    detail TEXT,
    last_checked TEXT NOT NULL,
    last_alerted_bad INTEGER NOT NULL DEFAULT 0
);

-- Pure append-only history, unlike known_devices/disk_health/ops_health's
-- current-state tracking -- the on-demand network investigator cites this
-- directly, and flap-alerting (see Store.count_recent_roams) needs the
-- full recent history, not just a single last-known value.
CREATE TABLE IF NOT EXISTS ap_roams (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT NOT NULL,
    from_ap TEXT,
    to_ap TEXT,
    occurred_at TEXT NOT NULL
);

-- WireGuard peer registry -- same known-vs-new diffing shape as
-- known_devices, but keyed by public key (WG's real identity), not a
-- MAC. allowed_ips is the peer's assigned tunnel IP (static,
-- config-defined, doesn't roam) -- kept purely as a human-friendly
-- reference alongside the label, never used as an identity key.
-- currently_connected tracks whether the most recent poll saw a fresh
-- handshake (see Store.record_wg_peer_sightings) so a "connected" event
-- fires once on the idle->connected transition, not on every routine
-- WG keepalive rekey while a peer stays connected.
CREATE TABLE IF NOT EXISTS known_wg_peers (
    pubkey TEXT PRIMARY KEY,
    allowed_ips TEXT,
    label TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    last_handshake_at TEXT,
    currently_connected INTEGER NOT NULL DEFAULT 0,
    trusted_at TEXT
);

-- Pure append-only history, same shape as ap_roams -- one row per
-- genuine "came online" transition, for "what connected and when."
CREATE TABLE IF NOT EXISTS wg_connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pubkey TEXT NOT NULL,
    endpoint TEXT,
    occurred_at TEXT NOT NULL
);

-- Which upstream caddy:builder digest each locally-built Caddy target was
-- last successfully built against -- see caddy_rebuild.py. Updated only
-- on a successful (possibly auto-reverted-but-healthy) outcome, so a
-- persistently broken upstream keeps retrying on the next poll rather
-- than being marked done.
CREATE TABLE IF NOT EXISTS caddy_builds (
    name TEXT PRIMARY KEY,
    last_built_digest TEXT NOT NULL,
    last_built_at TEXT NOT NULL
);

-- Microsoft Graph mailbox inbox-rule baseline -- same known-set-diffing
-- shape as known_wg_peers (a rule has a stable id the way a WireGuard
-- peer has a pubkey), not ops_health's boolean check-id shape (a rule
-- change isn't a persistent is_bad state). content_hash covers the
-- full rule body so a modification (not just add/remove) is caught
-- too -- see Store.record_mailbox_rule_sightings.
CREATE TABLE IF NOT EXISTS known_mailbox_rules (
    user_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    display_name TEXT,
    content_hash TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    PRIMARY KEY (user_id, rule_id)
);

-- Matrix messages that couldn't be sent yet (homeserver restarting, a
-- patch window), sent in order by MatrixBot.run_outbox_loop (2026-10-29).
-- txn_id is reused on every retry so the homeserver deduplicates a send
-- that landed but lost its response.
CREATE TABLE IF NOT EXISTS matrix_outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id TEXT NOT NULL,
    txn_id TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT
);

-- Declarations from rbd-pass-bot via the bot-to-bot room (2026-10-29) --
-- see bot_coordination.py. Keyed by the declaration's own id, so the
-- room-history replay on every restart is idempotent.
CREATE TABLE IF NOT EXISTS bot_declarations (
    id TEXT PRIMARY KEY,
    sender TEXT NOT NULL,
    mailbox TEXT NOT NULL,
    action TEXT NOT NULL,
    rule_id TEXT,
    rule_json TEXT NOT NULL,
    folder_name TEXT,
    reason TEXT,
    declared_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    received_at TEXT NOT NULL
);

-- !security-scan's diffable findings -- CVEs and concerning open ports
-- extracted from its own free-text report by security_findings.py, same
-- known-set-diffing shape as known_devices, plus a resolved_at half
-- (disk_health's state-transition style) since a CVE/port genuinely goes
-- away once patched/closed, unlike a network device. See
-- Store.record_security_scan_findings.
CREATE TABLE IF NOT EXISTS known_security_findings (
    host TEXT NOT NULL,
    finding_type TEXT NOT NULL,
    identifier TEXT NOT NULL,
    severity TEXT,
    has_fix INTEGER,
    detail TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    miss_count INTEGER NOT NULL DEFAULT 0,
    accepted_at TEXT,
    resolved_at TEXT,
    PRIMARY KEY (host, finding_type, identifier)
);

-- Pure append-only history, same shape as ap_roams -- the WiFi RF
-- monitor's "sustained for N samples" alerting and the morning
-- briefing's 24h peak both need the real recent history, not just a
-- current-state row. See planned-features/wifi-rf-monitoring.md.
CREATE TABLE IF NOT EXISTS wifi_rf_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    ap_name TEXT,
    ap_mac TEXT,
    band TEXT,
    channel TEXT,
    width TEXT,
    tx_power INTEGER,
    busy_util INTEGER,
    inter_util INTEGER,
    tx_util INTEGER,
    rx_util INTEGER,
    retry_rate REAL,
    err_rate REAL,
    rx_pkts INTEGER,
    rx_retry_pkts INTEGER,
    rx_err_pkts INTEGER
);
CREATE INDEX IF NOT EXISTS idx_wifi_rf_samples_ap_band_ts
    ON wifi_rf_samples (ap_mac, band, ts);

-- Phase 2 (planned-features/wifi-rf-monitoring.md): a per-poll rollup of
-- foreign-neighbor pressure per band+channel (from Omada's
-- insight/rogueaps, Homelab's own SSIDs excluded), not a raw per-BSSID
-- log -- one real poll alone saw ~40 foreign 2.4GHz BSSIDs, so logging
-- every row every 15 min for 90 days would be the single largest table
-- in the DB for no benefit the rollup doesn't already give. Used by the
-- on-demand channel-suggestion check and the briefing's crowding line --
-- informational only, never a paging alert (see that section for why).
CREATE TABLE IF NOT EXISTS wifi_rf_channel_crowding (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    band TEXT NOT NULL,
    channel INTEGER NOT NULL,
    neighbor_count INTEGER NOT NULL,
    strongest_signal INTEGER
);
CREATE INDEX IF NOT EXISTS idx_wifi_rf_channel_crowding_band_channel_ts
    ON wifi_rf_channel_crowding (band, channel, ts);

-- One row per Anthropic API call (2026-11-24): the Nov bill neared its
-- $40 cap with no way to tell which feature spent it. Written by
-- llm_usage.py's client wrapper; `feature` is the bot function that made
-- the call (module.function), cost_usd is an estimate from list prices.
CREATE TABLE IF NOT EXISTS llm_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    feature TEXT NOT NULL,
    model TEXT NOT NULL,
    input_tokens INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    cache_write_tokens INTEGER NOT NULL DEFAULT 0,
    cache_read_tokens INTEGER NOT NULL DEFAULT 0,
    web_searches INTEGER NOT NULL DEFAULT 0,
    cost_usd REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_llm_usage_ts ON llm_usage (ts);

-- Self-service requests for Wedding Planning App (Cloudflare Access)
-- membership -- see wedding_access_request.py/cloudflare_access.py. One
-- row per submission; status moves pending -> approved/denied, and
-- approved rows move on to expired once run_access_grant_expiry_loop
-- removes them from the Cloudflare policy.
CREATE TABLE IF NOT EXISTS access_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    reason TEXT NOT NULL,
    client_ip TEXT NOT NULL,
    match_source TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    requested_at TEXT NOT NULL,
    decided_at TEXT,
    decided_by TEXT,
    expires_at TEXT,
    policy_id TEXT
);

-- Manual override/supplement to wedding_hub_contacts.is_known_contact --
-- for anyone who should be able to reach the wedding-access-request
-- form but isn't in the Wedding Ledger's own guest data. See
-- !whitelist-requester / !unwhitelist-requester.
CREATE TABLE IF NOT EXISTS access_request_whitelist (
    email TEXT PRIMARY KEY,
    label TEXT,
    added_at TEXT NOT NULL
);
"""

_WG_CONNECTED_THRESHOLD_SECONDS = 200

_RESOLVE_AFTER_MISSES = 2

_lock = threading.Lock()


class Store:
    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with _lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()
            existing_cols = {row["name"] for row in self._conn.execute("PRAGMA table_info(updates)")}
            if "backup_decision" not in existing_cols:
                self._conn.execute("ALTER TABLE updates ADD COLUMN backup_decision TEXT")
                self._conn.commit()
            if "superseded_by" not in existing_cols:
                self._conn.execute("ALTER TABLE updates ADD COLUMN superseded_by INTEGER")
                self._conn.commit()
            if "proposed_repair" not in existing_cols:
                self._conn.execute("ALTER TABLE updates ADD COLUMN proposed_repair TEXT")
                self._conn.commit()
            rule_cols = {row["name"] for row in self._conn.execute("PRAGMA table_info(known_mailbox_rules)")}
            if "rule_json" not in rule_cols:
                self._conn.execute("ALTER TABLE known_mailbox_rules ADD COLUMN rule_json TEXT")
                self._conn.commit()
            sec_cols = {row["name"] for row in self._conn.execute("PRAGMA table_info(known_security_findings)")}
            if "has_fix" not in sec_cols:
                self._conn.execute("ALTER TABLE known_security_findings ADD COLUMN has_fix INTEGER")
                self._conn.commit()
            if "miss_count" not in sec_cols:
                self._conn.execute("ALTER TABLE known_security_findings ADD COLUMN miss_count INTEGER NOT NULL DEFAULT 0")
                self._conn.commit()
            if "accepted_at" not in sec_cols:
                self._conn.execute("ALTER TABLE known_security_findings ADD COLUMN accepted_at TEXT")
                self._conn.commit()
            if "kind" not in existing_cols:
                self._conn.execute("ALTER TABLE updates ADD COLUMN kind TEXT NOT NULL DEFAULT 'container'")
                self._conn.commit()
            if "reboot_decision" not in existing_cols:
                self._conn.execute("ALTER TABLE updates ADD COLUMN reboot_decision TEXT")
                self._conn.commit()
            if "digest" not in existing_cols:
                self._conn.execute("ALTER TABLE updates ADD COLUMN digest TEXT")
                self._conn.commit()
            if "security_severity" not in existing_cols:
                self._conn.execute("ALTER TABLE updates ADD COLUMN security_severity TEXT")
                self._conn.commit()
            existing_device_cols = {row["name"] for row in self._conn.execute("PRAGMA table_info(known_devices)")}
            if "label" not in existing_device_cols:
                self._conn.execute("ALTER TABLE known_devices ADD COLUMN label TEXT")
                self._conn.commit()
            if "trusted_at" not in existing_device_cols:
                self._conn.execute("ALTER TABLE known_devices ADD COLUMN trusted_at TEXT")
                self._conn.commit()

    def create_update(
        self,
        *,
        service_name: str,
        image: str,
        current_version: str,
        new_version: str,
        diun_entry_id: str,
        kind: str = "container",
        digest: str | None = None,
    ) -> int:
        now = _now()
        with _lock:
            cur = self._conn.execute(
                """INSERT INTO updates
                   (service_name, image, current_version, new_version,
                    diun_entry_id, stage, created_at, updated_at, kind, digest)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (service_name, image, current_version, new_version,
                 diun_entry_id, Stage.RECEIVED.value, now, now, kind, digest),
            )
            self._conn.commit()
            update_id = cur.lastrowid
        self.add_event(update_id, Stage.RECEIVED,
                        f"Diun reported {image} {current_version} -> {new_version}")
        return update_id

    def get(self, update_id: int) -> UpdateRecord | None:
        with _lock:
            row = self._conn.execute("SELECT * FROM updates WHERE id = ?", (update_id,)).fetchone()
        return _row_to_record(row) if row else None

    def get_by_diun_entry(self, diun_entry_id: str) -> UpdateRecord | None:
        with _lock:
            row = self._conn.execute(
                "SELECT * FROM updates WHERE diun_entry_id = ?", (diun_entry_id,)
            ).fetchone()
        return _row_to_record(row) if row else None

    def get_last_known_version(self, service_name: str) -> str | None:
        with _lock:
            row = self._conn.execute(
                """SELECT new_version FROM updates
                   WHERE service_name = ? AND stage = ? AND kind = 'container'
                   ORDER BY created_at DESC LIMIT 1""",
                (service_name, Stage.DONE_SUCCESS.value),
            ).fetchone()
        return row["new_version"] if row else None

    def get_last_known_digest(self, service_name: str, image: str) -> str | None:
        with _lock:
            row = self._conn.execute(
                """SELECT digest FROM updates
                   WHERE service_name = ? AND image = ? AND stage = ?
                   ORDER BY created_at DESC LIMIT 1""",
                (service_name, image, Stage.DONE_SUCCESS.value),
            ).fetchone()
        return row["digest"] if row else None

    def get_last_success_timestamp(self, service_name: str) -> str | None:
        with _lock:
            row = self._conn.execute(
                """SELECT created_at FROM updates
                   WHERE service_name = ? AND stage = ?
                   ORDER BY created_at DESC LIMIT 1""",
                (service_name, Stage.DONE_SUCCESS.value),
            ).fetchone()
        return row["created_at"] if row else None

    def get_last_container_success_timestamp(self, service_name: str) -> str | None:
        with _lock:
            row = self._conn.execute(
                """SELECT updated_at FROM updates
                   WHERE service_name = ? AND stage = ? AND kind = 'container'
                   ORDER BY updated_at DESC LIMIT 1""",
                (service_name, Stage.DONE_SUCCESS.value),
            ).fetchone()
        return row["updated_at"] if row else None

    def list_active(self) -> list[UpdateRecord]:
        terminal = tuple(s.value for s in Stage if s.terminal)
        placeholders = ",".join("?" for _ in terminal)
        with _lock:
            rows = self._conn.execute(
                f"SELECT * FROM updates WHERE stage NOT IN ({placeholders}) ORDER BY created_at",
                terminal,
            ).fetchall()
        return [_row_to_record(r) for r in rows]

    def list_recent(self, limit: int = 20) -> list[UpdateRecord]:
        with _lock:
            rows = self._conn.execute(
                "SELECT * FROM updates ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [_row_to_record(r) for r in rows]

    def list_ops_health(self) -> list[dict]:
        with _lock:
            rows = self._conn.execute("SELECT * FROM ops_health ORDER BY check_id").fetchall()
        return [dict(r) for r in rows]

    def list_disk_health(self) -> list[dict]:
        with _lock:
            rows = self._conn.execute("SELECT * FROM disk_health ORDER BY disk_id").fetchall()
        return [dict(r) for r in rows]

    def list_known_devices(self) -> list[dict]:
        with _lock:
            rows = self._conn.execute(
                "SELECT * FROM known_devices ORDER BY last_seen DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def list_wg_peers(self) -> list[dict]:
        with _lock:
            rows = self._conn.execute(
                "SELECT * FROM known_wg_peers ORDER BY last_seen DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def list_caddy_builds(self) -> list[dict]:
        with _lock:
            rows = self._conn.execute(
                "SELECT * FROM caddy_builds ORDER BY name"
            ).fetchall()
        return [dict(r) for r in rows]

    def list_by_service(self, service_name: str) -> list[UpdateRecord]:
        with _lock:
            rows = self._conn.execute(
                "SELECT * FROM updates WHERE service_name = ? ORDER BY created_at",
                (service_name,),
            ).fetchall()
        return [_row_to_record(r) for r in rows]

    def mark_superseded_failures(self, service_name: str, success_id: int) -> list[int]:
        with _lock:
            rows = self._conn.execute(
                """SELECT id FROM updates
                   WHERE service_name = ? AND stage = ? AND superseded_by IS NULL AND id < ?""",
                (service_name, Stage.DONE_FAILED.value, success_id),
            ).fetchall()
            ids = [r["id"] for r in rows]
            if ids:
                now = _now()
                self._conn.executemany(
                    "UPDATE updates SET superseded_by = ?, updated_at = ? WHERE id = ?",
                    [(success_id, now, i) for i in ids],
                )
                self._conn.commit()
        return ids

    _SIBLING_WINDOW_SECONDS = 300

    def mark_superseded_pending(
        self, service_name: str, new_update_id: int, new_version: str,
    ) -> list[int]:
        with _lock:
            anchor = self._conn.execute(
                "SELECT created_at FROM updates WHERE id = ?", (new_update_id,),
            ).fetchone()
            if anchor is None:
                return []
            anchor_created = datetime.fromisoformat(anchor["created_at"])
            rows = self._conn.execute(
                """SELECT id, new_version, created_at FROM updates
                   WHERE service_name = ? AND stage = ? AND id != ?""",
                (service_name, Stage.STAGED_PENDING_APPROVAL.value, new_update_id),
            ).fetchall()
            ids = []
            for r in rows:
                if r["new_version"] == new_version:
                    delta = abs((datetime.fromisoformat(r["created_at"]) - anchor_created).total_seconds())
                    if delta <= self._SIBLING_WINDOW_SECONDS:
                        continue
                ids.append(r["id"])
            if ids:
                now = _now()
                note = (
                    f"Resolved automatically: update #{new_update_id} (same service, a newer "
                    f"target version) superseded this one -- it was still sitting unapproved for "
                    f"a version that's no longer current."
                )
                self._conn.executemany(
                    "UPDATE updates SET stage = ?, superseded_by = ?, error = ?, updated_at = ? "
                    "WHERE id = ?",
                    [(Stage.ABORTED.value, new_update_id, note, now, i) for i in ids],
                )
                self._conn.commit()
        return ids

    def resolve_sibling_stack_updates(
        self, service_name: str, new_version: str, applied_update_id: int,
    ) -> list[int]:
        with _lock:
            rows = self._conn.execute(
                """SELECT id FROM updates
                   WHERE service_name = ? AND new_version = ? AND stage = ? AND id != ?""",
                (service_name, new_version, Stage.STAGED_PENDING_APPROVAL.value, applied_update_id),
            ).fetchall()
            ids = [r["id"] for r in rows]
            if ids:
                now = _now()
                note = (
                    f"Resolved automatically: update #{applied_update_id} (same service+version, "
                    f"a different tracked image) already redeployed the whole stack, which applied "
                    f"this image too -- never independently approved."
                )
                self._conn.executemany(
                    "UPDATE updates SET stage = ?, error = ?, updated_at = ? WHERE id = ?",
                    [(Stage.DONE_SUCCESS.value, note, now, i) for i in ids],
                )
                self._conn.commit()
        return ids

    def resolve_stale_sibling_updates(
        self, service_name: str, image: str, deployed_digest: str, applied_update_id: int,
    ) -> list[int]:
        with _lock:
            rows = self._conn.execute(
                """SELECT id FROM updates
                   WHERE service_name = ? AND image = ? AND digest = ? AND stage = ? AND id != ?""",
                (service_name, image, deployed_digest, Stage.STAGED_PENDING_APPROVAL.value, applied_update_id),
            ).fetchall()
            ids = [r["id"] for r in rows]
            if ids:
                now = _now()
                note = (
                    f"Resolved automatically: update #{applied_update_id} (same stack, a "
                    f"different tracked image) already redeployed this image too, before this "
                    f"request was even staged -- never independently approved."
                )
                self._conn.executemany(
                    "UPDATE updates SET stage = ?, error = ?, updated_at = ? WHERE id = ?",
                    [(Stage.DONE_SUCCESS.value, note, now, i) for i in ids],
                )
                self._conn.commit()
        return ids

    def backfill_sibling_digest(
        self, service_name: str, image: str, new_version: str, digest: str, applied_update_id: int,
    ) -> int | None:
        diun_entry_id = f"{image}:sibling-backfill@{digest}"
        with _lock:
            now = _now()
            try:
                self._conn.execute(
                    """INSERT INTO updates
                       (service_name, image, current_version, new_version,
                        diun_entry_id, stage, created_at, updated_at, kind, digest)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'container', ?)""",
                    (service_name, image, "unknown", new_version, diun_entry_id,
                     Stage.DONE_SUCCESS.value, now, now, digest),
                )
            except sqlite3.IntegrityError:
                return None
            new_id = self._conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            self._conn.commit()
        self.add_event(
            new_id, Stage.DONE_SUCCESS,
            f"Backfilled: redeployed as a side effect of update #{applied_update_id}'s "
            f"stack-wide redeploy, never independently tracked.",
        )
        return new_id

    def mark_passed(self, update_id: int, approved_by: str) -> list[int]:
        record = self.get(update_id)
        if record is None:
            return []
        note = f"Manually marked passed by {approved_by} -- confirmed a false failure after investigation."
        with _lock:
            self._conn.execute(
                "UPDATE updates SET stage = ?, error = ?, updated_at = ? WHERE id = ?",
                (Stage.DONE_SUCCESS.value, note, _now(), update_id),
            )
            self._conn.commit()
        self.add_event(update_id, Stage.DONE_SUCCESS, note)
        return self.resolve_sibling_stack_updates(record.service_name, record.new_version, update_id)

    def list_by_stage(self, stage: Stage) -> list[UpdateRecord]:
        with _lock:
            rows = self._conn.execute(
                "SELECT * FROM updates WHERE stage = ? ORDER BY created_at",
                (stage.value,),
            ).fetchall()
        return [_row_to_record(r) for r in rows]

    _RESTART_SAFE_STAGES = frozenset({Stage.STAGED_PENDING_APPROVAL, Stage.APPROVED})

    def reconcile_orphaned_updates(self) -> list[UpdateRecord]:
        orphaned = [r for r in self.list_active() if r.stage not in self._RESTART_SAFE_STAGES]
        for record in orphaned:
            note = (
                f"Orphaned by a bot restart while mid-pipeline (stage was "
                f"'{record.stage.value}' when the process died) -- the real-world "
                f"change may have completed fine; verify against the live service, "
                f"then !mark-passed {record.id} if so, or !investigate {record.id} if not."
            )
            with _lock:
                self._conn.execute(
                    "UPDATE updates SET stage = ?, error = ?, updated_at = ? WHERE id = ?",
                    (Stage.DONE_FAILED.value, note, _now(), record.id),
                )
                self._conn.commit()
            self.add_event(record.id, Stage.DONE_FAILED, note)
        return orphaned

    def correct_applied_target(self, update_id: int, *, new_version: str, digest: str) -> None:
        with _lock:
            self._conn.execute(
                "UPDATE updates SET new_version = ?, digest = ?, updated_at = ? WHERE id = ?",
                (new_version, digest, _now(), update_id),
            )
            self._conn.commit()

    def set_stage(self, update_id: int, stage: Stage, message: str = "") -> None:
        with _lock:
            self._conn.execute(
                "UPDATE updates SET stage = ?, updated_at = ? WHERE id = ?",
                (stage.value, _now(), update_id),
            )
            self._conn.commit()
        self.add_event(update_id, stage, message or stage.value)

    def set_risk_assessment(self, update_id: int, assessment: RiskAssessment,
                             release_notes_url: str | None) -> None:
        with _lock:
            self._conn.execute(
                """UPDATE updates
                   SET risk_level = ?, breaking_changes = ?, risk_summary = ?,
                       security_severity = ?, release_notes_url = ?, updated_at = ?
                   WHERE id = ?""",
                (assessment.risk_level, int(assessment.breaking_changes), assessment.summary,
                 assessment.security_severity, release_notes_url, _now(), update_id),
            )
            self._conn.commit()

    def set_approved(self, update_id: int, approved_by: str) -> None:
        with _lock:
            self._conn.execute(
                "UPDATE updates SET approved_by = ?, approved_at = ?, updated_at = ? WHERE id = ?",
                (approved_by, _now(), _now(), update_id),
            )
            self._conn.commit()

    def begin_backup_decision(self, update_id: int) -> None:
        with _lock:
            self._conn.execute(
                "UPDATE updates SET stage = ?, backup_decision = NULL, updated_at = ? WHERE id = ?",
                (Stage.AWAITING_BACKUP_DECISION.value, _now(), update_id),
            )
            self._conn.commit()
        self.add_event(update_id, Stage.AWAITING_BACKUP_DECISION, "awaiting confirm-backup/skip-backup")

    def set_backup_decision(self, update_id: int, decision: str) -> None:
        with _lock:
            self._conn.execute(
                "UPDATE updates SET backup_decision = ?, updated_at = ? WHERE id = ?",
                (decision, _now(), update_id),
            )
            self._conn.commit()

    def begin_reboot_decision(self, update_id: int) -> None:
        with _lock:
            self._conn.execute(
                "UPDATE updates SET stage = ?, reboot_decision = NULL, updated_at = ? WHERE id = ?",
                (Stage.AWAITING_REBOOT_DECISION.value, _now(), update_id),
            )
            self._conn.commit()
        self.add_event(update_id, Stage.AWAITING_REBOOT_DECISION, "awaiting confirm-reboot/abort")

    def set_reboot_decision(self, update_id: int, decision: str) -> None:
        with _lock:
            self._conn.execute(
                "UPDATE updates SET reboot_decision = ?, updated_at = ? WHERE id = ?",
                (decision, _now(), update_id),
            )
            self._conn.commit()

    def set_error(self, update_id: int, error: str) -> None:
        with _lock:
            self._conn.execute(
                "UPDATE updates SET error = ?, updated_at = ? WHERE id = ?",
                (error, _now(), update_id),
            )
            self._conn.commit()

    def add_event(self, update_id: int, stage: Stage, message: str) -> None:
        with _lock:
            self._conn.execute(
                "INSERT INTO stage_events (update_id, stage, message, created_at) VALUES (?, ?, ?, ?)",
                (update_id, stage.value, message, _now()),
            )
            self._conn.commit()

    def events_for(self, update_id: int) -> list[sqlite3.Row]:
        with _lock:
            return self._conn.execute(
                "SELECT * FROM stage_events WHERE update_id = ? ORDER BY created_at",
                (update_id,),
            ).fetchall()

    def set_repair_plan(self, update_id: int, commands: list[str]) -> None:
        with _lock:
            self._conn.execute(
                "UPDATE updates SET proposed_repair = ?, updated_at = ? WHERE id = ?",
                (json.dumps(commands), _now(), update_id),
            )
            self._conn.commit()

    def get_meta(self, key: str) -> str | None:
        with _lock:
            row = self._conn.execute("SELECT value FROM bot_meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        with _lock:
            self._conn.execute(
                "INSERT INTO bot_meta (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )
            self._conn.commit()

    def record_device_sightings(self, devices: list[dict]) -> list[dict]:
        now = _now()
        new_devices: list[dict] = []
        with _lock:
            row = self._conn.execute("SELECT COUNT(*) AS c FROM known_devices").fetchone()
            is_first_run = row["c"] == 0

            seen_this_batch: set[str] = set()
            for dev in devices:
                mac = dev.get("mac")
                if not mac or mac in seen_this_batch:
                    continue
                seen_this_batch.add(mac)

                existing = self._conn.execute(
                    "SELECT mac FROM known_devices WHERE mac = ?", (mac,)
                ).fetchone()
                if existing is None:
                    if not is_first_run:
                        new_devices.append(dev)
                    self._conn.execute(
                        "INSERT INTO known_devices "
                        "(mac, ip, hostname, vlan, port, source, first_seen, last_seen) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (mac, dev.get("ip"), dev.get("hostname"), dev.get("vlan"),
                         dev.get("port"), dev.get("source"), now, now),
                    )
                else:
                    self._conn.execute(
                        "UPDATE known_devices SET ip = ?, hostname = ?, vlan = ?, "
                        "port = ?, source = ?, last_seen = ? WHERE mac = ?",
                        (dev.get("ip"), dev.get("hostname"), dev.get("vlan"),
                         dev.get("port"), dev.get("source"), now, mac),
                    )
            self._conn.commit()
        return new_devices

    def record_security_scan_findings(self, findings: list[dict]) -> tuple[list[dict], list[dict]]:
        now = _now()
        new_or_regressed: list[dict] = []
        newly_resolved: list[dict] = []
        with _lock:
            row = self._conn.execute("SELECT COUNT(*) AS c FROM known_security_findings").fetchone()
            is_first_run = row["c"] == 0

            seen_keys: set[tuple[str, str, str]] = set()
            for f in findings:
                host, finding_type, identifier = f["host"], f["finding_type"], f["identifier"]
                has_fix = f.get("has_fix", True)
                seen_keys.add((host, finding_type, identifier))

                existing = self._conn.execute(
                    "SELECT resolved_at, has_fix, accepted_at FROM known_security_findings "
                    "WHERE host = ? AND finding_type = ? AND identifier = ?",
                    (host, finding_type, identifier),
                ).fetchone()
                if existing is None:
                    if not is_first_run:
                        new_or_regressed.append(f)
                    self._conn.execute(
                        "INSERT INTO known_security_findings "
                        "(host, finding_type, identifier, severity, has_fix, detail, first_seen, last_seen, miss_count, resolved_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, NULL)",
                        (host, finding_type, identifier, f.get("severity"), int(has_fix), f.get("detail"), now, now),
                    )
                else:
                    accepted = existing["accepted_at"] is not None
                    fix_now_available = (
                        existing["resolved_at"] is None and not bool(existing["has_fix"]) and has_fix
                    )
                    if not is_first_run and not accepted and (existing["resolved_at"] is not None or fix_now_available):
                        new_or_regressed.append(f)
                    self._conn.execute(
                        "UPDATE known_security_findings SET severity = ?, has_fix = ?, detail = ?, "
                        "last_seen = ?, miss_count = 0, resolved_at = NULL "
                        "WHERE host = ? AND finding_type = ? AND identifier = ?",
                        (f.get("severity"), int(has_fix), f.get("detail"), now, host, finding_type, identifier),
                    )

            if not is_first_run:
                open_rows = self._conn.execute(
                    "SELECT host, finding_type, identifier, severity, detail, miss_count "
                    "FROM known_security_findings WHERE resolved_at IS NULL"
                ).fetchall()
                for r in open_rows:
                    key = (r["host"], r["finding_type"], r["identifier"])
                    if key in seen_keys:
                        continue
                    new_miss_count = r["miss_count"] + 1
                    if new_miss_count >= _RESOLVE_AFTER_MISSES:
                        self._conn.execute(
                            "UPDATE known_security_findings SET miss_count = ?, resolved_at = ? "
                            "WHERE host = ? AND finding_type = ? AND identifier = ?",
                            (new_miss_count, now, r["host"], r["finding_type"], r["identifier"]),
                        )
                        newly_resolved.append(dict(r))
                    else:
                        self._conn.execute(
                            "UPDATE known_security_findings SET miss_count = ? "
                            "WHERE host = ? AND finding_type = ? AND identifier = ?",
                            (new_miss_count, r["host"], r["finding_type"], r["identifier"]),
                        )
            self._conn.commit()
        return new_or_regressed, newly_resolved

    def accept_security_finding(self, host: str, finding_type: str, identifier: str) -> bool:
        now = _now()
        with _lock:
            cur = self._conn.execute(
                "UPDATE known_security_findings SET accepted_at = ? "
                "WHERE host = ? AND finding_type = ? AND identifier = ?",
                (now, host, finding_type, identifier),
            )
            self._conn.commit()
        return cur.rowcount > 0

    def trust_device(self, mac: str, label: str | None) -> bool:
        now = _now()
        with _lock:
            existing = self._conn.execute(
                "SELECT mac FROM known_devices WHERE mac = ?", (mac,)
            ).fetchone()
            if existing is None:
                self._conn.execute(
                    "INSERT INTO known_devices "
                    "(mac, source, first_seen, last_seen, label, trusted_at) "
                    "VALUES (?, 'manual', ?, ?, ?, ?)",
                    (mac, now, now, label, now),
                )
            else:
                if label is not None:
                    self._conn.execute(
                        "UPDATE known_devices SET label = ?, trusted_at = ? WHERE mac = ?",
                        (label, now, mac),
                    )
                else:
                    self._conn.execute(
                        "UPDATE known_devices SET trusted_at = ? WHERE mac = ?",
                        (now, mac),
                    )
            self._conn.commit()
        return existing is not None

    def is_requester_whitelisted(self, email: str) -> bool:
        with _lock:
            row = self._conn.execute(
                "SELECT 1 FROM access_request_whitelist WHERE email = ?", (email.lower(),)
            ).fetchone()
        return row is not None

    def whitelist_requester(self, email: str, label: str | None) -> None:
        with _lock:
            self._conn.execute(
                "INSERT INTO access_request_whitelist (email, label, added_at) VALUES (?, ?, ?) "
                "ON CONFLICT(email) DO UPDATE SET label = excluded.label",
                (email.lower(), label, _now()),
            )
            self._conn.commit()

    def unwhitelist_requester(self, email: str) -> bool:
        with _lock:
            cur = self._conn.execute(
                "DELETE FROM access_request_whitelist WHERE email = ?", (email.lower(),)
            )
            self._conn.commit()
        return cur.rowcount > 0

    def create_access_request(
        self, name: str, email: str, reason: str, client_ip: str, match_source: str,
    ) -> int:
        with _lock:
            cur = self._conn.execute(
                "INSERT INTO access_requests "
                "(name, email, reason, client_ip, match_source, status, requested_at) "
                "VALUES (?, ?, ?, ?, ?, 'pending', ?)",
                (name, email, reason, client_ip, match_source, _now()),
            )
            self._conn.commit()
        return cur.lastrowid

    def get_access_request(self, request_id: int) -> sqlite3.Row | None:
        with _lock:
            return self._conn.execute(
                "SELECT * FROM access_requests WHERE id = ?", (request_id,)
            ).fetchone()

    def approve_access_request(self, request_id: int, policy_id: str, expires_at: str) -> None:
        with _lock:
            self._conn.execute(
                "UPDATE access_requests SET status = 'approved', decided_at = ?, "
                "decided_by = 'matrix', policy_id = ?, expires_at = ? WHERE id = ?",
                (_now(), policy_id, expires_at, request_id),
            )
            self._conn.commit()

    def deny_access_request(self, request_id: int) -> None:
        with _lock:
            self._conn.execute(
                "UPDATE access_requests SET status = 'denied', decided_at = ?, decided_by = 'matrix' "
                "WHERE id = ?",
                (_now(), request_id),
            )
            self._conn.commit()

    def list_expired_access_grants(self) -> list[sqlite3.Row]:
        with _lock:
            return self._conn.execute(
                "SELECT * FROM access_requests WHERE status = 'approved' AND expires_at <= ?",
                (_now(),),
            ).fetchall()

    def mark_access_request_expired(self, request_id: int) -> None:
        with _lock:
            self._conn.execute(
                "UPDATE access_requests SET status = 'expired' WHERE id = ?", (request_id,)
            )
            self._conn.commit()

    def record_disk_health(self, checks: list[dict]) -> list[dict]:
        now = _now()
        events: list[dict] = []
        with _lock:
            row = self._conn.execute("SELECT COUNT(*) AS c FROM disk_health").fetchone()
            is_first_run = row["c"] == 0

            for check in checks:
                disk_id = check.get("disk_id")
                if not disk_id:
                    continue
                is_bad = _is_disk_bad(check.get("health"), check.get("wearout")) or bool(check.get("smart_bad"))

                existing = self._conn.execute(
                    "SELECT last_alerted_bad FROM disk_health WHERE disk_id = ?", (disk_id,)
                ).fetchone()

                if existing is None:
                    last_alerted_bad = 1 if is_bad else 0
                    if is_bad and not is_first_run:
                        events.append({**check, "event": "alert"})
                    self._conn.execute(
                        "INSERT INTO disk_health "
                        "(disk_id, source, model, health, wearout, last_checked, last_alerted_bad) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (disk_id, check.get("source"), check.get("model"), check.get("health"),
                         check.get("wearout"), now, last_alerted_bad),
                    )
                else:
                    was_alerted = bool(existing["last_alerted_bad"])
                    if is_bad and not was_alerted:
                        events.append({**check, "event": "alert"})
                    elif not is_bad and was_alerted:
                        events.append({**check, "event": "recovered"})
                    self._conn.execute(
                        "UPDATE disk_health SET source = ?, model = ?, health = ?, "
                        "wearout = ?, last_checked = ?, last_alerted_bad = ? WHERE disk_id = ?",
                        (check.get("source"), check.get("model"), check.get("health"),
                         check.get("wearout"), now, 1 if is_bad else 0, disk_id),
                    )
            self._conn.commit()
        return events

    def record_ops_health(self, checks: list[dict]) -> list[dict]:
        now = _now()
        events: list[dict] = []
        with _lock:
            sources = {c.get("source") for c in checks if c.get("source")}
            is_first_run_by_source = {
                source: self._conn.execute(
                    "SELECT COUNT(*) AS c FROM ops_health WHERE source = ?", (source,)
                ).fetchone()["c"] == 0
                for source in sources
            }

            for check in checks:
                check_id = check.get("check_id")
                if not check_id:
                    continue
                is_bad = bool(check.get("is_bad"))

                existing = self._conn.execute(
                    "SELECT last_alerted_bad FROM ops_health WHERE check_id = ?", (check_id,)
                ).fetchone()

                if existing is None:
                    last_alerted_bad = 1 if is_bad else 0
                    if is_bad and not is_first_run_by_source.get(check.get("source"), False):
                        events.append({**check, "event": "alert"})
                    self._conn.execute(
                        "INSERT INTO ops_health "
                        "(check_id, source, status, detail, last_checked, last_alerted_bad) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (check_id, check.get("source"), check.get("status"),
                         check.get("detail"), now, last_alerted_bad),
                    )
                else:
                    was_alerted = bool(existing["last_alerted_bad"])
                    if is_bad and not was_alerted:
                        events.append({**check, "event": "alert"})
                    elif not is_bad and was_alerted:
                        events.append({**check, "event": "recovered"})
                    self._conn.execute(
                        "UPDATE ops_health SET source = ?, status = ?, detail = ?, "
                        "last_checked = ?, last_alerted_bad = ? WHERE check_id = ?",
                        (check.get("source"), check.get("status"), check.get("detail"),
                         now, 1 if is_bad else 0, check_id),
                    )
            self._conn.commit()
        return events

    def record_wifi_rf_samples(self, radios: list[dict], *, retention_days: int = 90) -> list[dict]:
        now = _now()
        enriched: list[dict] = []
        with _lock:
            for radio in radios:
                ap_mac = radio.get("_ap_mac")
                band = radio.get("_band")
                traffic = radio.get("traffic") or {}
                rx_pkts = traffic.get("rxPkts")
                rx_retry = traffic.get("rxRetryPkts")
                rx_err = traffic.get("rxErrPkts")

                prev = self._conn.execute(
                    "SELECT rx_pkts, rx_retry_pkts, rx_err_pkts FROM wifi_rf_samples "
                    "WHERE ap_mac = ? AND band = ? ORDER BY ts DESC LIMIT 1",
                    (ap_mac, band),
                ).fetchone()

                retry_rate = None
                err_rate = None
                if prev is not None and rx_pkts is not None and rx_retry is not None \
                        and prev["rx_pkts"] is not None and prev["rx_retry_pkts"] is not None:
                    d_pkts = rx_pkts - prev["rx_pkts"]
                    d_retry = rx_retry - prev["rx_retry_pkts"]
                    if d_pkts > 0 and d_retry >= 0:
                        retry_rate = round(100.0 * d_retry / d_pkts, 2)
                    if rx_err is not None and prev["rx_err_pkts"] is not None:
                        d_err = rx_err - prev["rx_err_pkts"]
                        if d_pkts > 0 and d_err >= 0:
                            err_rate = round(100.0 * d_err / d_pkts, 2)

                self._conn.execute(
                    "INSERT INTO wifi_rf_samples "
                    "(ts, ap_name, ap_mac, band, channel, width, tx_power, busy_util, "
                    "inter_util, tx_util, rx_util, retry_rate, err_rate, "
                    "rx_pkts, rx_retry_pkts, rx_err_pkts) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (now, radio.get("_ap_name"), ap_mac, band,
                     radio.get("actualChannel"), radio.get("bandWidth"),
                     radio.get("txPower"), radio.get("busyUtil"), radio.get("interUtil"),
                     radio.get("txUtil"), radio.get("rxUtil"), retry_rate, err_rate,
                     rx_pkts, rx_retry, rx_err),
                )
                enriched.append({**radio, "retry_rate": retry_rate, "err_rate": err_rate, "ts": now})

            cutoff = (datetime.fromisoformat(now) - timedelta(days=retention_days)).isoformat()
            self._conn.execute("DELETE FROM wifi_rf_samples WHERE ts < ?", (cutoff,))
            self._conn.commit()
        return enriched

    def recent_wifi_rf_bad_streak(self, ap_mac: str, band: str, *, field: str,
                                   threshold: float, samples: int, min_rx_pkts: int = 0) -> bool:
        rows = self._conn.execute(
            f"SELECT {field}, rx_pkts FROM wifi_rf_samples WHERE ap_mac = ? AND band = ? "
            f"ORDER BY ts DESC LIMIT ?",
            (ap_mac, band, samples + 1),
        ).fetchall()
        if len(rows) < samples:
            return False

        def enough_traffic(i: int) -> bool:
            if min_rx_pkts <= 0:
                return True
            if i + 1 >= len(rows):
                return False
            cur, prev = rows[i]["rx_pkts"], rows[i + 1]["rx_pkts"]
            return cur is not None and prev is not None and cur - prev >= min_rx_pkts

        return all(rows[i][field] is not None and rows[i][field] >= threshold and enough_traffic(i)
                   for i in range(samples))

    def wifi_rf_24h_peak(self, field: str) -> dict | None:
        row = self._conn.execute(
            f"SELECT ap_name, band, {field} AS val, ts FROM wifi_rf_samples "
            f"WHERE ts > datetime('now', '-1 day') AND {field} IS NOT NULL "
            f"ORDER BY val DESC LIMIT 1"
        ).fetchone()
        return dict(row) if row else None

    def record_wifi_rf_channel_crowding(self, rows: list[dict], *, retention_days: int = 90) -> None:
        if not rows:
            return
        now = _now()
        with _lock:
            for row in rows:
                self._conn.execute(
                    "INSERT INTO wifi_rf_channel_crowding "
                    "(ts, band, channel, neighbor_count, strongest_signal) VALUES (?, ?, ?, ?, ?)",
                    (now, row["band"], row["channel"], row["neighbor_count"], row["strongest_signal"]),
                )
            cutoff = (datetime.fromisoformat(now) - timedelta(days=retention_days)).isoformat()
            self._conn.execute("DELETE FROM wifi_rf_channel_crowding WHERE ts < ?", (cutoff,))
            self._conn.commit()

    def record_llm_usage(self, row: dict, *, retention_days: int = 400) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with _lock:
            self._conn.execute(
                "INSERT INTO llm_usage (ts, feature, model, input_tokens, output_tokens, "
                "cache_write_tokens, cache_read_tokens, web_searches, cost_usd) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (now, row["feature"], row["model"], row["input_tokens"], row["output_tokens"],
                 row["cache_write_tokens"], row["cache_read_tokens"], row["web_searches"], row["cost_usd"]),
            )
            cutoff = (datetime.fromisoformat(now) - timedelta(days=retention_days)).isoformat()
            self._conn.execute("DELETE FROM llm_usage WHERE ts < ?", (cutoff,))
            self._conn.commit()

    def llm_usage_summary(self, since_iso: str) -> list[dict]:
        with _lock:
            rows = self._conn.execute(
                "SELECT feature, COUNT(*) AS calls, SUM(input_tokens) AS input_tokens, "
                "SUM(output_tokens) AS output_tokens, SUM(cache_read_tokens) AS cache_read_tokens, "
                "SUM(web_searches) AS web_searches, SUM(cost_usd) AS cost_usd "
                "FROM llm_usage WHERE ts >= ? GROUP BY feature ORDER BY cost_usd DESC",
                (since_iso,),
            ).fetchall()
        return [dict(r) for r in rows]

    def latest_wifi_rf_channel_crowding(self) -> list[dict]:
        latest_ts = self._conn.execute(
            "SELECT MAX(ts) AS ts FROM wifi_rf_channel_crowding"
        ).fetchone()["ts"]
        if latest_ts is None:
            return []
        rows = self._conn.execute(
            "SELECT band, channel, neighbor_count, strongest_signal, ts "
            "FROM wifi_rf_channel_crowding WHERE ts = ?",
            (latest_ts,),
        ).fetchall()
        return [dict(r) for r in rows]

    def latest_wifi_rf_radio_state(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT ap_name, ap_mac, band, channel, ts FROM wifi_rf_samples w1 "
            "WHERE ts = (SELECT MAX(ts) FROM wifi_rf_samples w2 "
            "WHERE w2.ap_mac = w1.ap_mac AND w2.band = w1.band)"
        ).fetchall()
        return [dict(r) for r in rows]

    def wifi_rf_channel_crowding_24h_peak(self) -> dict | None:
        row = self._conn.execute(
            "SELECT band, channel, neighbor_count, strongest_signal, ts "
            "FROM wifi_rf_channel_crowding WHERE ts > datetime('now', '-1 day') "
            "ORDER BY neighbor_count DESC LIMIT 1"
        ).fetchone()
        return dict(row) if row else None

    def detect_ap_roams(self, devices: list[dict]) -> list[dict]:
        roams: list[dict] = []
        with _lock:
            for dev in devices:
                new_port = dev.get("port")
                mac = dev.get("mac")
                if not mac or not new_port or "(SSID:" not in new_port:
                    continue
                existing = self._conn.execute(
                    "SELECT port FROM known_devices WHERE mac = ?", (mac,)
                ).fetchone()
                old_port = existing["port"] if existing else None
                if old_port and "(SSID:" in old_port and old_port != new_port:
                    roams.append({"mac": mac, "from_ap": old_port, "to_ap": new_port})
        return roams

    def record_ap_roam(self, mac: str, from_ap: str, to_ap: str) -> None:
        with _lock:
            self._conn.execute(
                "INSERT INTO ap_roams (mac, from_ap, to_ap, occurred_at) VALUES (?, ?, ?, ?)",
                (mac, from_ap, to_ap, _now()),
            )
            self._conn.commit()

    def count_recent_roams(self, mac: str, since_hours: float) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=since_hours)).isoformat()
        with _lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS c FROM ap_roams WHERE mac = ? AND occurred_at >= ?",
                (mac, cutoff),
            ).fetchone()
        return row["c"]

    def get_recent_roams(self, since_hours: float, *, limit: int = 50) -> list[dict]:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=since_hours)).isoformat()
        with _lock:
            rows = self._conn.execute(
                "SELECT mac, from_ap, to_ap, occurred_at FROM ap_roams "
                "WHERE occurred_at >= ? ORDER BY occurred_at DESC LIMIT ?",
                (cutoff, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def record_wg_peer_sightings(self, peers: list[dict]) -> tuple[list[dict], list[dict]]:
        now = _now()
        now_dt = datetime.now(timezone.utc)
        new_peers: list[dict] = []
        connection_events: list[dict] = []
        with _lock:
            row = self._conn.execute("SELECT COUNT(*) AS c FROM known_wg_peers").fetchone()
            is_first_run = row["c"] == 0

            for peer in peers:
                pubkey = peer.get("pubkey")
                if not pubkey:
                    continue
                last_handshake_at = peer.get("last_handshake_at")
                is_connected = False
                if last_handshake_at:
                    age = (now_dt - datetime.fromisoformat(last_handshake_at)).total_seconds()
                    is_connected = age < _WG_CONNECTED_THRESHOLD_SECONDS

                existing = self._conn.execute(
                    "SELECT currently_connected FROM known_wg_peers WHERE pubkey = ?", (pubkey,)
                ).fetchone()

                if existing is None:
                    if not is_first_run:
                        new_peers.append(peer)
                        if is_connected:
                            connection_events.append(peer)
                    self._conn.execute(
                        "INSERT INTO known_wg_peers "
                        "(pubkey, allowed_ips, first_seen, last_seen, last_handshake_at, currently_connected) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (pubkey, peer.get("allowed_ips"), now, now,
                         last_handshake_at, 1 if is_connected else 0),
                    )
                    if is_connected:
                        self._conn.execute(
                            "INSERT INTO wg_connections (pubkey, endpoint, occurred_at) VALUES (?, ?, ?)",
                            (pubkey, peer.get("endpoint"), now),
                        )
                else:
                    was_connected = bool(existing["currently_connected"])
                    if is_connected and not was_connected:
                        connection_events.append(peer)
                        self._conn.execute(
                            "INSERT INTO wg_connections (pubkey, endpoint, occurred_at) VALUES (?, ?, ?)",
                            (pubkey, peer.get("endpoint"), now),
                        )
                    self._conn.execute(
                        "UPDATE known_wg_peers SET allowed_ips = ?, last_seen = ?, "
                        "last_handshake_at = ?, currently_connected = ? WHERE pubkey = ?",
                        (peer.get("allowed_ips"), now, last_handshake_at,
                         1 if is_connected else 0, pubkey),
                    )
            self._conn.commit()
        return new_peers, connection_events

    def trust_wg_peer(self, pubkey: str, label: str | None) -> bool:
        now = _now()
        with _lock:
            existing = self._conn.execute(
                "SELECT pubkey FROM known_wg_peers WHERE pubkey = ?", (pubkey,)
            ).fetchone()
            if existing is None:
                self._conn.execute(
                    "INSERT INTO known_wg_peers "
                    "(pubkey, first_seen, last_seen, label, trusted_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (pubkey, now, now, label, now),
                )
            else:
                if label is not None:
                    self._conn.execute(
                        "UPDATE known_wg_peers SET label = ?, trusted_at = ? WHERE pubkey = ?",
                        (label, now, pubkey),
                    )
                else:
                    self._conn.execute(
                        "UPDATE known_wg_peers SET trusted_at = ? WHERE pubkey = ?",
                        (now, pubkey),
                    )
            self._conn.commit()
        return existing is not None

    def get_wg_peer_label(self, pubkey: str) -> str | None:
        with _lock:
            row = self._conn.execute(
                "SELECT label FROM known_wg_peers WHERE pubkey = ?", (pubkey,)
            ).fetchone()
        return row["label"] if row else None

    def get_wg_connections_near(self, when_iso: str, window_seconds: float) -> list[dict]:
        when_dt = datetime.fromisoformat(when_iso.replace("Z", "+00:00"))
        start = (when_dt - timedelta(seconds=window_seconds)).isoformat()
        end = (when_dt + timedelta(seconds=window_seconds)).isoformat()
        with _lock:
            rows = self._conn.execute(
                "SELECT wc.pubkey, wc.endpoint, wc.occurred_at, kp.label FROM wg_connections wc "
                "LEFT JOIN known_wg_peers kp ON kp.pubkey = wc.pubkey "
                "WHERE wc.occurred_at BETWEEN ? AND ? ORDER BY wc.occurred_at",
                (start, end),
            ).fetchall()
        return [dict(row) for row in rows]

    def outbox_add(self, room_id: str, txn_id: str, content: dict, expires_at: datetime) -> None:
        with _lock:
            self._conn.execute(
                "INSERT INTO matrix_outbox (room_id, txn_id, content, created_at, expires_at, last_error) "
                "VALUES (?, ?, ?, ?, ?, '')",
                (room_id, txn_id, json.dumps(content), _now(), expires_at.astimezone(timezone.utc).isoformat()),
            )
            self._conn.commit()

    def outbox_pending(self) -> list[dict]:
        with _lock:
            rows = self._conn.execute("SELECT * FROM matrix_outbox ORDER BY id").fetchall()
        return [{**dict(row), "content": json.loads(row["content"])} for row in rows]

    def outbox_remove(self, row_id: int) -> None:
        with _lock:
            self._conn.execute("DELETE FROM matrix_outbox WHERE id = ?", (row_id,))
            self._conn.commit()

    def outbox_failed(self, row_id: int, error: str) -> None:
        with _lock:
            self._conn.execute(
                "UPDATE matrix_outbox SET attempts = attempts + 1, last_error = ? WHERE id = ?",
                (error[:300], row_id),
            )
            self._conn.commit()

    def mailbox_rule_bodies(self, user_id: str) -> dict[str, dict | None]:
        with _lock:
            rows = self._conn.execute(
                "SELECT rule_id, rule_json FROM known_mailbox_rules WHERE user_id = ?", (user_id,),
            ).fetchall()
        return {row["rule_id"]: json.loads(row["rule_json"]) if row["rule_json"] else None for row in rows}

    def record_bot_declaration(self, decl: dict, sender: str) -> bool:
        with _lock:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO bot_declarations (id, sender, mailbox, action, rule_id, rule_json, "
                "folder_name, reason, declared_at, expires_at, received_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (decl["id"], sender, decl["mailbox"], decl["action"], decl["rule_id"], json.dumps(decl["rule"]),
                 decl["folder_name"], decl["reason"], decl["declared_at"], decl["expires_at"], _now()),
            )
            self._conn.commit()
            return cur.rowcount == 1

    def live_bot_declarations(self, mailbox: str, at_iso: str) -> list[dict]:
        prune_before = (datetime.fromisoformat(at_iso) - timedelta(days=1)).isoformat()
        with _lock:
            self._conn.execute("DELETE FROM bot_declarations WHERE expires_at < ?", (prune_before,))
            rows = self._conn.execute(
                "SELECT * FROM bot_declarations WHERE mailbox = ? AND expires_at >= ? ORDER BY declared_at DESC",
                (mailbox.lower(), at_iso),
            ).fetchall()
            self._conn.commit()
        return [{**dict(row), "rule": json.loads(row["rule_json"])} for row in rows]

    def record_mailbox_rule_sightings(
        self, user_id: str, rules: list[dict],
    ) -> tuple[list[dict], list[dict], list[dict]]:
        now = _now()
        new_rules: list[dict] = []
        modified_rules: list[dict] = []
        deleted_rules: list[dict] = []

        with _lock:
            existing_rows = self._conn.execute(
                "SELECT rule_id, display_name, content_hash FROM known_mailbox_rules WHERE user_id = ?",
                (user_id,),
            ).fetchall()
            is_first_run = len(existing_rows) == 0
            existing_by_id = {row["rule_id"]: row for row in existing_rows}
            seen_ids: set[str] = set()

            for rule in rules:
                rule_id = rule.get("id")
                if not rule_id:
                    continue
                seen_ids.add(rule_id)
                display_name = rule.get("displayName")
                content_hash = hashlib.sha256(
                    json.dumps(rule, sort_keys=True).encode()
                ).hexdigest()

                existing = existing_by_id.get(rule_id)
                if existing is None:
                    if not is_first_run:
                        new_rules.append(rule)
                    self._conn.execute(
                        "INSERT INTO known_mailbox_rules "
                        "(user_id, rule_id, display_name, content_hash, first_seen, last_seen, rule_json) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (user_id, rule_id, display_name, content_hash, now, now, json.dumps(rule, sort_keys=True)),
                    )
                else:
                    if existing["content_hash"] != content_hash and not is_first_run:
                        modified_rules.append(rule)
                    self._conn.execute(
                        "UPDATE known_mailbox_rules SET display_name = ?, content_hash = ?, last_seen = ?, "
                        "rule_json = ? WHERE user_id = ? AND rule_id = ?",
                        (display_name, content_hash, now, json.dumps(rule, sort_keys=True), user_id, rule_id),
                    )

            if not is_first_run:
                for rule_id, row in existing_by_id.items():
                    if rule_id not in seen_ids:
                        deleted_rules.append({"id": rule_id, "displayName": row["display_name"]})
                        self._conn.execute(
                            "DELETE FROM known_mailbox_rules WHERE user_id = ? AND rule_id = ?",
                            (user_id, rule_id),
                        )

            self._conn.commit()
        return new_rules, modified_rules, deleted_rules

    def get_caddy_build_digest(self, name: str) -> str | None:
        with _lock:
            row = self._conn.execute(
                "SELECT last_built_digest FROM caddy_builds WHERE name = ?", (name,)
            ).fetchone()
        return row["last_built_digest"] if row else None

    def set_caddy_build_digest(self, name: str, digest: str) -> None:
        now = _now()
        with _lock:
            self._conn.execute(
                "INSERT INTO caddy_builds (name, last_built_digest, last_built_at) VALUES (?, ?, ?) "
                "ON CONFLICT(name) DO UPDATE SET last_built_digest = excluded.last_built_digest, "
                "last_built_at = excluded.last_built_at",
                (name, digest, now),
            )
            self._conn.commit()

    def create_finding(self, source: str, subject: str, severity: str,
                        summary: str, detail: dict | None = None) -> int:
        now = _now()
        with _lock:
            cur = self._conn.execute(
                "INSERT INTO findings "
                "(source, subject, severity, summary, detail, status, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, 'open', ?, ?)",
                (source, subject, severity, summary,
                 json.dumps(detail) if detail is not None else None, now, now),
            )
            self._conn.commit()
            return cur.lastrowid

    def get_finding(self, finding_id: int) -> dict | None:
        with _lock:
            row = self._conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["detail"] = json.loads(d["detail"]) if d["detail"] else None
        return d

    def open_finding_subjects(self, source: str) -> set[str]:
        with _lock:
            rows = self._conn.execute(
                "SELECT subject FROM findings WHERE source = ? AND status != 'resolved'", (source,),
            ).fetchall()
        return {row["subject"] for row in rows}

    def resolve_finding_by_subject(self, source: str, subject: str) -> int | None:
        now = _now()
        with _lock:
            rows = self._conn.execute(
                "SELECT id FROM findings WHERE source = ? AND subject = ? AND status != 'resolved' "
                "ORDER BY created_at DESC",
                (source, subject),
            ).fetchall()
            if not rows:
                return None
            ids = [row["id"] for row in rows]
            self._conn.executemany(
                "UPDATE findings SET status = 'resolved', resolved_at = ?, updated_at = ? WHERE id = ?",
                [(now, now, finding_id) for finding_id in ids],
            )
            self._conn.commit()
        return ids[0]

    def resolve_finding(self, finding_id: int) -> bool:
        now = _now()
        with _lock:
            row = self._conn.execute(
                "SELECT status FROM findings WHERE id = ?", (finding_id,),
            ).fetchone()
            if row is None or row["status"] == "resolved":
                return False
            self._conn.execute(
                "UPDATE findings SET status = 'resolved', resolved_at = ?, updated_at = ? WHERE id = ?",
                (now, now, finding_id),
            )
            self._conn.commit()
        return True

    def count_recent_findings(self, source: str, subject: str, since: str) -> int:
        with _lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS c FROM findings WHERE source = ? AND subject = ? AND created_at >= ?",
                (source, subject, since),
            ).fetchone()
        return row["c"]

    def set_finding_status(self, finding_id: int, status: str) -> None:
        with _lock:
            self._conn.execute(
                "UPDATE findings SET status = ?, updated_at = ? WHERE id = ?",
                (status, _now(), finding_id),
            )
            self._conn.commit()

    def set_investigation_report(self, finding_id: int, report: str) -> None:
        with _lock:
            self._conn.execute(
                "UPDATE findings SET investigation_report = ?, updated_at = ? WHERE id = ?",
                (report, _now(), finding_id),
            )
            self._conn.commit()

    def list_findings(self, *, include_resolved: bool = False, limit: int = 20) -> list[dict]:
        where = "" if include_resolved else "WHERE status NOT IN ('resolved', 'deferred')"
        with _lock:
            rows = self._conn.execute(
                f"""SELECT * FROM findings {where}
                    ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END,
                             created_at ASC
                    LIMIT ?""",
                (limit,),
            ).fetchall()
        return [{**dict(r), "detail": json.loads(r["detail"]) if r["detail"] else None} for r in rows]

    def count_deferred_findings(self) -> int:
        with _lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS c FROM findings WHERE status = 'deferred'"
            ).fetchone()
        return row["c"]

    def list_recent_findings_by_source(
        self, sources: list[str], *, hours: float = 18.0, limit: int = 20,
    ) -> list[dict]:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        placeholders = ",".join("?" * len(sources))
        with _lock:
            rows = self._conn.execute(
                f"SELECT * FROM findings WHERE source IN ({placeholders}) AND created_at >= ? "
                f"ORDER BY created_at ASC LIMIT ?",
                (*sources, cutoff, limit),
            ).fetchall()
        return [{**dict(r), "detail": json.loads(r["detail"]) if r["detail"] else None} for r in rows]

    def list_stuck_investigations(self) -> list[dict]:
        with _lock:
            rows = self._conn.execute(
                "SELECT * FROM findings WHERE status = 'investigating' AND investigation_report IS NULL"
            ).fetchall()
        return [{**dict(r), "detail": json.loads(r["detail"]) if r["detail"] else None} for r in rows]


_GOOD_HEALTH_VALUES = {"passed", "normal", "safe", "healthy", "ok", "background_scrubbing"}
_WEAROUT_ALERT_THRESHOLD = 20


def _is_disk_bad(health: str | None, wearout: int | None) -> bool:
    if health is not None and str(health).strip().lower() not in _GOOD_HEALTH_VALUES:
        return True
    if wearout is not None:
        try:
            if int(wearout) < _WEAROUT_ALERT_THRESHOLD:
                return True
        except (TypeError, ValueError):
            pass
    return False


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _row_to_record(row: sqlite3.Row) -> UpdateRecord:
    return UpdateRecord(
        id=row["id"],
        service_name=row["service_name"],
        image=row["image"],
        current_version=row["current_version"],
        new_version=row["new_version"],
        diun_entry_id=row["diun_entry_id"],
        stage=Stage(row["stage"]),
        risk_level=row["risk_level"],
        breaking_changes=bool(row["breaking_changes"]) if row["breaking_changes"] is not None else None,
        risk_summary=row["risk_summary"],
        security_severity=row["security_severity"],
        release_notes_url=row["release_notes_url"],
        approved_by=row["approved_by"],
        approved_at=row["approved_at"],
        error=row["error"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        digest=row["digest"],
        backup_decision=row["backup_decision"],
        superseded_by=row["superseded_by"],
        proposed_repair=json.loads(row["proposed_repair"]) if row["proposed_repair"] else None,
        kind=row["kind"],
        reboot_decision=row["reboot_decision"],
    )
