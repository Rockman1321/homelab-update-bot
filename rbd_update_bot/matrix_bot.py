"""Matrix client: posts notices and parses commands."""
from __future__ import annotations

import asyncio
import logging
import re
import time
import uuid
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone

from nio import Api, AsyncClient, MatrixRoom, RoomMessageNotice, RoomMessageText, RoomSendResponse

from .db import Store

logger = logging.getLogger(__name__)

_COMMAND_RE = re.compile(
    r"^!(approve|abort|status|confirm-backup|skip-backup|confirm-reboot|rollback|investigate|repair|mark-passed)\s+(\d+)\s*$",
    re.IGNORECASE,
)
_HELP_RE = re.compile(r"^!(help|commands)\s*$", re.IGNORECASE)
_CHECK_UPDATES_RE = re.compile(r"^!check-updates\s*$", re.IGNORECASE)
_FINDINGS_RE = re.compile(r"^!findings\s*$", re.IGNORECASE)
_PENDING_RE = re.compile(r"^!pending\s*$", re.IGNORECASE)
_BRIEFING_RE = re.compile(r"^!briefing\s*$", re.IGNORECASE)
_SECURITY_SCAN_RE = re.compile(r"^!security-scan\s*$", re.IGNORECASE)
_TRUST_DEVICE_RE = re.compile(
    r"^!trust-device\s+([0-9a-fA-F:-]{11,17})(?:\s+(.+))?\s*$", re.IGNORECASE
)
_TRUST_PEER_RE = re.compile(
    r"^!trust-peer\s+([A-Za-z0-9+/]{42,44}=?)(?:\s+(.+))?\s*$", re.IGNORECASE
)
_INVESTIGATE_FINDING_RE = re.compile(r"^!investigate-finding\s+(\d+)\s*$", re.IGNORECASE)
_RESTORE_ACCESS_RE = re.compile(r"^!restore-access\s+(\d+)\s*$", re.IGNORECASE)
_RESOLVE_FINDING_RE = re.compile(r"^!resolve-finding\s+(\d+)\s*$", re.IGNORECASE)
_ACCEPT_PORT_RE = re.compile(r"^!accept-port\s+(\d+)\s*$", re.IGNORECASE)
_APPROVE_ACCESS_RE = re.compile(r"^!approve-access\s+(\d+)(?:\s+(\d+))?\s*$", re.IGNORECASE)
_DENY_ACCESS_RE = re.compile(r"^!deny-access\s+(\d+)\s*$", re.IGNORECASE)
_WHITELIST_REQUESTER_RE = re.compile(r"^!whitelist-requester\s+(\S+)(?:\s+(.+))?\s*$", re.IGNORECASE)
_UNWHITELIST_REQUESTER_RE = re.compile(r"^!unwhitelist-requester\s+(\S+)\s*$", re.IGNORECASE)
_INVESTIGATE_NETWORK_RE = re.compile(r"^!investigate-network\s+(.+)$", re.IGNORECASE)
_INVESTIGATE_CLUSTER_RE = re.compile(r"^!investigate-cluster(?:\s+(.+))?\s*$", re.IGNORECASE)
_BLOCK_IP_RE = re.compile(r"^!block-ip\s+(\S+)(?:\s+(.+))?\s*$", re.IGNORECASE)
_UNBLOCK_IP_RE = re.compile(r"^!unblock-ip\s+(\S+)\s*$", re.IGNORECASE)
_BLOCKLIST_RE = re.compile(r"^!blocklist\s*$", re.IGNORECASE)
_KB_ROTATE_TOKEN_RE = re.compile(r"^!kb-rotate-token\s*$", re.IGNORECASE)
_KB_RESTRICT_RE = re.compile(r"^!kb-restrict\s*$", re.IGNORECASE)
_KB_UNRESTRICT_RE = re.compile(r"^!kb-unrestrict\s*$", re.IGNORECASE)
_PATCH_RE = re.compile(r"^!patch\s+(\S+)\s*$", re.IGNORECASE)
_REBOOT_RE = re.compile(r"^!reboot\s+(\S+)\s*$", re.IGNORECASE)
_MAINTENANCE_RE = re.compile(r"^!maintenance\s+(\S+)\s*$", re.IGNORECASE)
_CONFIRM_MAINTENANCE_RE = re.compile(r"^!confirm-maintenance\s*$", re.IGNORECASE)
_SKIP_MAINTENANCE_RE = re.compile(r"^!skip-maintenance\s*$", re.IGNORECASE)
_MAINTENANCE_PREP_RE = re.compile(r"^!maintenance-prep\s*$", re.IGNORECASE)
_DISCOURSE_BACKUPS_RE = re.compile(r"^!discourse-backups\s*$", re.IGNORECASE)
_DISCOURSE_RESTORE_RE = re.compile(r"^!discourse-restore\s+(\S+)\s*$", re.IGNORECASE)
_CONFIRM_DISCOURSE_RESTORE_RE = re.compile(r"^!confirm-discourse-restore\s*$", re.IGNORECASE)
_ABORT_DISCOURSE_RESTORE_RE = re.compile(r"^!abort-discourse-restore\s*$", re.IGNORECASE)
_WIFI_CHANNELS_RE = re.compile(r"^!wifi-channels\s*$", re.IGNORECASE)

_LLM_USAGE_RE = re.compile(r"^!llm-usage(?:\s+(\d{1,3}))?\s*$", re.IGNORECASE)

_OUTBOX_TTL = timedelta(hours=12)
_BOT_OUTBOX_TTL = timedelta(hours=2)
_OUTBOX_RETRY_S = 30

_LAST_PROCESSED_KEY = "matrix_last_processed_ts"

_STARTUP_GRACE_MS = 5 * 60 * 1000


class MatrixBot:
    def __init__(
        self,
        homeserver: str,
        user_id: str,
        access_token: str,
        room_id: str,
        on_command: Callable[[str, int, str], Awaitable[None]],
        on_help: Callable[[], Awaitable[None]] | None = None,
        on_check_updates: Callable[[], Awaitable[None]] | None = None,
        on_findings: Callable[[], Awaitable[None]] | None = None,
        on_pending: Callable[[], Awaitable[None]] | None = None,
        on_briefing: Callable[[], Awaitable[None]] | None = None,
        on_security_scan: Callable[[], Awaitable[None]] | None = None,
        on_trust_device: Callable[[str, str | None], Awaitable[None]] | None = None,
        on_trust_peer: Callable[[str, str | None], Awaitable[None]] | None = None,
        on_block_ip: Callable[[str, str | None], Awaitable[None]] | None = None,
        on_unblock_ip: Callable[[str], Awaitable[None]] | None = None,
        on_blocklist: Callable[[], Awaitable[None]] | None = None,
        on_kb_rotate_token: Callable[[], Awaitable[None]] | None = None,
        on_kb_restrict: Callable[[], Awaitable[None]] | None = None,
        on_kb_unrestrict: Callable[[], Awaitable[None]] | None = None,
        on_investigate_finding: Callable[[int], Awaitable[None]] | None = None,
        on_restore_access: Callable[[int], Awaitable[None]] | None = None,
        on_resolve_finding: Callable[[int], Awaitable[None]] | None = None,
        on_accept_port: Callable[[int], Awaitable[None]] | None = None,
        on_approve_access: Callable[[int, int | None], Awaitable[None]] | None = None,
        on_deny_access: Callable[[int], Awaitable[None]] | None = None,
        on_whitelist_requester: Callable[[str, str | None], Awaitable[None]] | None = None,
        on_unwhitelist_requester: Callable[[str], Awaitable[None]] | None = None,
        on_investigate_network: Callable[[str], Awaitable[None]] | None = None,
        on_investigate_cluster: Callable[[str], Awaitable[None]] | None = None,
        on_patch: Callable[[str], Awaitable[None]] | None = None,
        on_reboot: Callable[[str], Awaitable[None]] | None = None,
        on_maintenance: Callable[[str], Awaitable[None]] | None = None,
        on_confirm_maintenance: Callable[[], Awaitable[None]] | None = None,
        on_skip_maintenance: Callable[[], Awaitable[None]] | None = None,
        on_maintenance_prep: Callable[[], Awaitable[None]] | None = None,
        on_discourse_backups: Callable[[], Awaitable[None]] | None = None,
        on_discourse_restore: Callable[[str], Awaitable[None]] | None = None,
        on_confirm_discourse_restore: Callable[[], Awaitable[None]] | None = None,
        on_abort_discourse_restore: Callable[[], Awaitable[None]] | None = None,
        on_wifi_channels: Callable[[], Awaitable[None]] | None = None,
        on_llm_usage: Callable[[int], Awaitable[None]] | None = None,
        store: Store | None = None,
        admin_user_ids: list[str] | None = None,
        coordination_room_id: str = "",
        wedding_room_id: str = "",
        on_bot_message: Callable[[str, dict], Awaitable[None]] | None = None,
    ):
        self.room_id = room_id
        self.coordination_room_id = coordination_room_id
        self.wedding_room_id = wedding_room_id
        self._on_bot_message = on_bot_message
        self._admin_user_ids = set(admin_user_ids) if admin_user_ids else None
        if self._admin_user_ids is None:
            logger.warning(
                "matrix_admin_user_ids is empty -- ANY account that can post in this room "
                "can issue privileged commands (!patch/!reboot/!block-ip/!approve/etc). "
                "Set it in config.yaml to restrict this."
            )
        self._on_command = on_command
        self._on_help = on_help
        self._on_check_updates = on_check_updates
        self._on_findings = on_findings
        self._on_pending = on_pending
        self._on_briefing = on_briefing
        self._on_security_scan = on_security_scan
        self._on_trust_device = on_trust_device
        self._on_trust_peer = on_trust_peer
        self._on_block_ip = on_block_ip
        self._on_unblock_ip = on_unblock_ip
        self._on_blocklist = on_blocklist
        self._on_kb_rotate_token = on_kb_rotate_token
        self._on_kb_restrict = on_kb_restrict
        self._on_kb_unrestrict = on_kb_unrestrict
        self._on_investigate_finding = on_investigate_finding
        self._on_restore_access = on_restore_access
        self._on_resolve_finding = on_resolve_finding
        self._on_accept_port = on_accept_port
        self._on_approve_access = on_approve_access
        self._on_deny_access = on_deny_access
        self._on_whitelist_requester = on_whitelist_requester
        self._on_unwhitelist_requester = on_unwhitelist_requester
        self._on_investigate_network = on_investigate_network
        self._on_investigate_cluster = on_investigate_cluster
        self._on_patch = on_patch
        self._on_reboot = on_reboot
        self._on_maintenance = on_maintenance
        self._on_confirm_maintenance = on_confirm_maintenance
        self._on_maintenance_prep = on_maintenance_prep
        self._on_skip_maintenance = on_skip_maintenance
        self._on_discourse_backups = on_discourse_backups
        self._on_discourse_restore = on_discourse_restore
        self._on_confirm_discourse_restore = on_confirm_discourse_restore
        self._on_abort_discourse_restore = on_abort_discourse_restore
        self._on_wifi_channels = on_wifi_channels
        self._on_llm_usage = on_llm_usage
        self._store = store
        self.client = AsyncClient(homeserver, user_id)
        self.client.access_token = access_token
        self.client.user_id = user_id
        self.client.add_event_callback(self._on_message, RoomMessageText)
        self.client.add_event_callback(self._on_bot_notice, RoomMessageNotice)
        persisted = store.get_meta(_LAST_PROCESSED_KEY) if store is not None else None
        self._last_processed_ms = (
            int(persisted) if persisted is not None
            else int(time.time() * 1000) - _STARTUP_GRACE_MS
        )

    async def _on_message(self, room: MatrixRoom, event: RoomMessageText) -> None:
        if room.room_id != self.room_id:
            return
        if event.sender == self.client.user_id:
            return
        if event.server_timestamp <= self._last_processed_ms:
            return
        self._last_processed_ms = event.server_timestamp
        if self._store is not None:
            self._store.set_meta(_LAST_PROCESSED_KEY, str(self._last_processed_ms))

        if self._admin_user_ids is not None and event.sender not in self._admin_user_ids:
            logger.warning(
                "ignoring command from non-admin sender %r (not in matrix_admin_user_ids): %r",
                event.sender, event.body.strip()[:200],
            )
            return

        body = event.body.strip()

        if _HELP_RE.match(body):
            if self._on_help is not None:
                await self._on_help()
            return

        if _CHECK_UPDATES_RE.match(body):
            if self._on_check_updates is not None:
                await self._on_check_updates()
            return

        if _FINDINGS_RE.match(body):
            if self._on_findings is not None:
                await self._on_findings()
            return

        if _PENDING_RE.match(body):
            if self._on_pending is not None:
                await self._on_pending()
            return

        if _BRIEFING_RE.match(body):
            if self._on_briefing is not None:
                await self._on_briefing()
            return

        if _SECURITY_SCAN_RE.match(body):
            if self._on_security_scan is not None:
                await self._on_security_scan()
            return

        trust_match = _TRUST_DEVICE_RE.match(body)
        if trust_match:
            if self._on_trust_device is not None:
                mac, label = trust_match.group(1), trust_match.group(2)
                await self._on_trust_device(mac, label.strip() if label else None)
            return

        trust_peer_match = _TRUST_PEER_RE.match(body)
        if trust_peer_match:
            if self._on_trust_peer is not None:
                pubkey, label = trust_peer_match.group(1), trust_peer_match.group(2)
                await self._on_trust_peer(pubkey, label.strip() if label else None)
            return

        block_ip_match = _BLOCK_IP_RE.match(body)
        if block_ip_match:
            if self._on_block_ip is not None:
                ip, reason = block_ip_match.group(1), block_ip_match.group(2)
                await self._on_block_ip(ip, reason.strip() if reason else None)
            return

        unblock_ip_match = _UNBLOCK_IP_RE.match(body)
        if unblock_ip_match:
            if self._on_unblock_ip is not None:
                await self._on_unblock_ip(unblock_ip_match.group(1))
            return

        if _BLOCKLIST_RE.match(body):
            if self._on_blocklist is not None:
                await self._on_blocklist()
            return

        if _KB_ROTATE_TOKEN_RE.match(body):
            if self._on_kb_rotate_token is not None:
                await self._on_kb_rotate_token()
            return

        if _KB_RESTRICT_RE.match(body):
            if self._on_kb_restrict is not None:
                await self._on_kb_restrict()
            return

        if _KB_UNRESTRICT_RE.match(body):
            if self._on_kb_unrestrict is not None:
                await self._on_kb_unrestrict()
            return

        finding_match = _INVESTIGATE_FINDING_RE.match(body)
        if finding_match:
            if self._on_investigate_finding is not None:
                await self._on_investigate_finding(int(finding_match.group(1)))
            return

        restore_access_match = _RESTORE_ACCESS_RE.match(body)
        if restore_access_match:
            if self._on_restore_access is not None:
                await self._on_restore_access(int(restore_access_match.group(1)))
            return

        resolve_finding_match = _RESOLVE_FINDING_RE.match(body)
        if resolve_finding_match:
            if self._on_resolve_finding is not None:
                await self._on_resolve_finding(int(resolve_finding_match.group(1)))
            return

        accept_port_match = _ACCEPT_PORT_RE.match(body)
        if accept_port_match:
            if self._on_accept_port is not None:
                await self._on_accept_port(int(accept_port_match.group(1)))
            return

        approve_access_match = _APPROVE_ACCESS_RE.match(body)
        if approve_access_match:
            if self._on_approve_access is not None:
                request_id, days = approve_access_match.group(1), approve_access_match.group(2)
                await self._on_approve_access(int(request_id), int(days) if days else None)
            return

        deny_access_match = _DENY_ACCESS_RE.match(body)
        if deny_access_match:
            if self._on_deny_access is not None:
                await self._on_deny_access(int(deny_access_match.group(1)))
            return

        whitelist_requester_match = _WHITELIST_REQUESTER_RE.match(body)
        if whitelist_requester_match:
            if self._on_whitelist_requester is not None:
                email, label = whitelist_requester_match.group(1), whitelist_requester_match.group(2)
                await self._on_whitelist_requester(email, label.strip() if label else None)
            return

        unwhitelist_requester_match = _UNWHITELIST_REQUESTER_RE.match(body)
        if unwhitelist_requester_match:
            if self._on_unwhitelist_requester is not None:
                await self._on_unwhitelist_requester(unwhitelist_requester_match.group(1))
            return

        network_match = _INVESTIGATE_NETWORK_RE.match(body)
        if network_match:
            if self._on_investigate_network is not None:
                await self._on_investigate_network(network_match.group(1).strip())
            return

        cluster_match = _INVESTIGATE_CLUSTER_RE.match(body)
        if cluster_match:
            if self._on_investigate_cluster is not None:
                description = cluster_match.group(1)
                await self._on_investigate_cluster(description.strip() if description else "")
            return

        patch_match = _PATCH_RE.match(body)
        if patch_match:
            if self._on_patch is not None:
                await self._on_patch(patch_match.group(1))
            return

        reboot_match = _REBOOT_RE.match(body)
        if reboot_match:
            if self._on_reboot is not None:
                await self._on_reboot(reboot_match.group(1))
            return

        maintenance_match = _MAINTENANCE_RE.match(body)
        if maintenance_match:
            if self._on_maintenance is not None:
                await self._on_maintenance(maintenance_match.group(1))
            return

        if _CONFIRM_MAINTENANCE_RE.match(body):
            if self._on_confirm_maintenance is not None:
                await self._on_confirm_maintenance()
            return

        if _SKIP_MAINTENANCE_RE.match(body):
            if self._on_skip_maintenance is not None:
                await self._on_skip_maintenance()
            return

        if _MAINTENANCE_PREP_RE.match(body):
            if self._on_maintenance_prep is not None:
                await self._on_maintenance_prep()
            return

        if _DISCOURSE_BACKUPS_RE.match(body):
            if self._on_discourse_backups is not None:
                await self._on_discourse_backups()
            return

        discourse_restore_match = _DISCOURSE_RESTORE_RE.match(body)
        if discourse_restore_match:
            if self._on_discourse_restore is not None:
                await self._on_discourse_restore(discourse_restore_match.group(1))
            return

        if _CONFIRM_DISCOURSE_RESTORE_RE.match(body):
            if self._on_confirm_discourse_restore is not None:
                await self._on_confirm_discourse_restore()
            return

        if _ABORT_DISCOURSE_RESTORE_RE.match(body):
            if self._on_abort_discourse_restore is not None:
                await self._on_abort_discourse_restore()
            return

        if _WIFI_CHANNELS_RE.match(body):
            if self._on_wifi_channels is not None:
                await self._on_wifi_channels()
            return

        if m := _LLM_USAGE_RE.match(body):
            if self._on_llm_usage is not None:
                await self._on_llm_usage(int(m.group(1) or 30))
            return

        match = _COMMAND_RE.match(body)
        if not match:
            return
        command, update_id = match.group(1).lower(), int(match.group(2))
        await self._on_command(command, update_id, event.sender)

    async def _on_bot_notice(self, room: MatrixRoom, event: RoomMessageNotice) -> None:
        if not self.coordination_room_id or room.room_id != self.coordination_room_id:
            return
        if self._on_bot_message is None or event.sender == self.client.user_id:
            return
        try:
            await self._on_bot_message(event.sender, event.source.get("content") or {})
        except Exception:
            logger.exception("bot-to-bot message handling failed")

    async def _join_room(self, room_id: str, label: str) -> None:
        _, path = Api.join(self.client.access_token, room_id)
        try:
            resp = await self.client.send("POST", path, data="{}", headers={"Content-Type": "application/json"})
            if resp.status != 200:
                logger.warning("couldn't join the %s room %s: HTTP %s %s",
                               label, room_id, resp.status, (await resp.text())[:200])
        except Exception as exc:
            logger.warning("couldn't join the %s room %s: %s", label, room_id, exc)

    async def join_coordination_room(self) -> None:
        if not self.coordination_room_id:
            return
        await self._join_room(self.coordination_room_id, "bot-to-bot")

    async def join_wedding_room(self) -> None:
        if not self.wedding_room_id:
            return
        await self._join_room(self.wedding_room_id, "wedding")

    async def _put(self, room_id: str, content: dict, txn: str) -> str | None:
        try:
            resp = await asyncio.wait_for(
                self.client.room_send(room_id=room_id, message_type="m.room.message",
                                       content=content, tx_id=txn),
                timeout=20.0,
            )
        except Exception as exc:
            return f"{type(exc).__name__}: {exc}"
        return None if isinstance(resp, RoomSendResponse) else str(resp)

    async def _deliver(self, room_id: str, content: dict, ttl: timedelta) -> None:
        txn = uuid.uuid4().hex
        if self._store is None:
            err = await self._put(room_id, content, txn)
            if err:
                logger.warning("Matrix send failed (no store, not queued): %s", err)
            return
        if not self._store.outbox_pending():
            err = await self._put(room_id, content, txn)
            if err is None:
                return
            logger.warning("Matrix send failed, queued for retry: %s", err)
        self._store.outbox_add(room_id, txn, content, datetime.now(timezone.utc) + ttl)

    async def flush_outbox(self) -> int:
        if self._store is None:
            return 0
        sent, now = 0, datetime.now(timezone.utc)
        for row in self._store.outbox_pending():
            if datetime.fromisoformat(row["expires_at"]) < now:
                logger.warning("dropping a queued Matrix message from %s (expired after %d attempts): %.80s",
                               row["created_at"], row["attempts"], row["content"].get("body", ""))
                self._store.outbox_remove(row["id"])
                continue
            err = await self._put(row["room_id"], row["content"], row["txn_id"])
            if err:
                self._store.outbox_failed(row["id"], err)
                break
            self._store.outbox_remove(row["id"])
            sent += 1
        if sent:
            logger.info("sent %d queued Matrix message(s)", sent)
        return sent

    async def run_outbox_loop(self) -> None:
        while True:
            await asyncio.sleep(_OUTBOX_RETRY_S)
            try:
                if self._store is not None and self._store.outbox_pending():
                    await self.flush_outbox()
            except Exception:
                logger.exception("Matrix outbox flush failed")

    async def send_bot_message(self, content: dict) -> None:
        if not self.coordination_room_id:
            return
        await self._deliver(self.coordination_room_id, content, _BOT_OUTBOX_TTL)

    async def notify(self, text: str) -> None:
        await self._deliver(self.room_id, {"msgtype": "m.text", "body": text}, _OUTBOX_TTL)

    async def notify_wedding(self, text: str) -> None:
        room_id = self.wedding_room_id or self.room_id
        await self._deliver(room_id, {"msgtype": "m.text", "body": text}, _OUTBOX_TTL)

    async def run_forever(self) -> None:
        await self.client.sync_forever(timeout=30000)

    async def close(self) -> None:
        await self.client.close()
