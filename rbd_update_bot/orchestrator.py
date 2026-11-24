"""The state machine: research, approval, backup, update, log watch, plus every scheduled loop."""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import anthropic

from . import (
    bot_coordination, caddy_rebuild, classifier, cloudflare_access, cloudflare_traffic, cluster_maintenance, config_drift,
    diun_trigger, disk_health,
    discourse_backup_pull, discourse_restore, executor, firewall_traffic, fortigate_blocklist,
    fortios_advisory, github_issue, graph_monitor, homeassistant, immich_backup, investigate, kb_access_monitor, kb_access_sync,
    llm_usage,
    local_llm,
    kb_lockdown, external_reachability, kb_page_relay, kernel_cve_watch, kopia, kuma_crash_monitor,
    librenms_monitor, mgmt1_agent, mgmt1_patch, network_monitor, o365_outage_watch, ollama, ops_health, outage_report, portainer, reachability_correlation,
    release_notes, security_findings, security_research, security_scan, tag_resolver, teamspeak,
    uptime_kuma, wedding_access_request, wedding_hub_contacts,
)
from .config import Config, NextcloudDbBackupConfig
from .db import Store
from .matrix_bot import MatrixBot
from .models import Stage, UpdateRecord
from .portainer import PortainerConfig
from .proxmox import PBSClient, ProxmoxClient

logger = logging.getLogger(__name__)

_REPAIR_PLAN_MARKER = "REPAIR PLAN:"
_REPAIR_COMMAND_LINE_RE = re.compile(r"^\$\s+occ\s+(.+)$")
_REPAIR_COMMAND_RE = re.compile(r"^[a-zA-Z0-9_:.-]+(?: -{1,2}[a-zA-Z0-9_.-]+(?:=[\w./:-]+)?| [\w./:-]+)*$")

_CODE_FIX_NEEDED_RE = re.compile(r"^CODE_FIX_NEEDED:\s*(\S+):\s*(.+)$", re.MULTILINE)

_GOOD_HEALTH_DISPLAY_VALUES = {"passed", "normal", "safe", "healthy", "ok"}

_BACKUP_AGO_RE = re.compile(r"(\d+(?:\.\d+)?)h ago")

_CLUSTER_MAINT_PENDING_KEY = "cluster_maint_pending_vmids"
_CLUSTER_MAINT_AWAITING_RESTORE_KEY = "cluster_maint_awaiting_restore"

_HELP_TEXT = """Available commands:

Update pipeline (act on a specific update, referenced by its ID):
  !status <id>              show an update's current stage
  !approve <id>             approve a staged update to begin
  !abort <id>               abort an in-progress update
  !confirm-backup <id>      proceed with the proposed Proxmox backup
  !skip-backup <id>         skip the Proxmox backup, continue the update
  !confirm-reboot <id>      proceed with a pending !reboot (use !abort <id> instead to cancel it)
  !rollback <id>            restore a pinned-tag service's previous compose config (not for floating-tag services)
  !mark-passed <id>         override a confirmed-false DONE_FAILED to passed (bookkeeping only, touches nothing live); cascades to any sibling update for the same service+version
  !investigate <id>         read-only root-cause investigation of a failed update
  !repair <id>              run a previously-proposed occ repair plan (Nextcloud only -- run !investigate <id> first)

Fleet-wide, on-demand:
  !pending                  list every update not yet finished -- staged, awaiting a decision, or mid-pipeline, with its risk/severity
  !check-updates            force an immediate Diun scan
  !security-scan            read-only sweep across every host (ports, auth logs, CVEs, FortiGate, Omada)
  !patch <service_name>     OS-level (apt) patch for a services.yaml-tracked VM, with a Proxmox backup gate first
  !reboot <service_name>    reboot a services.yaml-tracked VM, with pre-flight checks and a post-reboot health check
  !maintenance <service_name>   run the full OS-patch -> reboot-if-needed -> app-update chain for one service right now

Scheduled maintenance (weekly, opt-in per service -- see config.yaml):
  !confirm-maintenance      approve this week's scheduled maintenance window
  !skip-maintenance         decline this week's window (also happens automatically if unanswered)

Cluster-wide maintenance prep (for a manual Proxmox-host/DSM maintenance window -- see planned-features/cluster-maintenance-prep-restore.md):
  !maintenance-prep         gracefully shut down every VM/CT except rbd-ns1/rbd-ns2/rbd-mgmt1/this bot's own VM; restore is automatic on this bot's next startup once ns1/ns2/mgmt1 are confirmed healthy

Findings (from the network/disk/ops-health monitors):
  !findings                            list open findings, ranked critical first (critical ones auto-investigate on creation)
  !briefing                            a plain-English status summary instead of a table (sectioned: Updates Performed / Backup Status / Network Trends / Open Issues). Also posts automatically at configured local times if daily_briefing is set in config.yaml.
  !investigate-finding <finding_id>    read-only investigation of a specific finding
  !investigate-network <description>   on-demand investigation of a free-text report, e.g. "wifi is bad"
  !investigate-cluster [description]   read-only Proxmox cluster resource/rebalancing review
  !restore-access <finding_id>         undo an emergency-containment action early (source="security_containment" findings only) -- normally restores itself once the real patch lands
  !resolve-finding <finding_id>        manually close a finding that's already been investigated/explained and needs no action (e.g. config_drift, which never auto-resolves)
  !accept-port <finding_id>            permanently accept a !security-scan open-port finding as an intentional listener -- unlike !resolve-finding, it also stops that exact host+port from ever re-flagging
  !wifi-channels                       on-demand WiFi channel-crowding suggestion per AP/band, from Omada's own neighbor scan -- suggest-only, never changes anything
  !llm-usage [days]                    Anthropic API spend by feature over the last N days (default 30) -- calls, tokens, web searches, estimated $

Trust / baselines:
  !trust-device <mac> [label]      mark a network device as known-good
  !trust-peer <pubkey> [label]     mark a WireGuard peer as known-good

Wedding Planning App access requests (public form at /wedding-access-request):
  !approve-access <id> [days]          grant Cloudflare Access to a pending request (default 30 days) -- auto-expires, no manual Cloudflare cleanup needed
  !deny-access <id>                    deny a pending request, no Cloudflare change
  !whitelist-requester <email> [label] let someone not already in the Wedding Ledger's own guest data reach the request form (anyone with a weddingRole set there is covered automatically)
  !unwhitelist-requester <email>       stop future requests from this email reaching Matrix (does not revoke access already granted)

Firewall (always human-triggered, never automated):
  !block-ip <ip> [reason]          block an IP via the FortiGate BLOCKLIST group
  !unblock-ip <ip>                 remove a previously-blocked IP
  !blocklist                       list IPs currently blocked by this bot

KB access lockdown (always human-triggered, never automated):
  !kb-rotate-token          rotate the Matrix registration token published on the restricted KB page
  !kb-restrict              temporarily swap the matrix/teamspeak restricted path to the strict allowlist policy
  !kb-unrestrict            swap it back to the normal Everyone+OTP policy

Discourse backup/restore (V1, always human-confirmed, never automated):
  !discourse-backups                   list available backups + how much would be lost restoring to each
  !discourse-restore <filename>        stage a restore (asks for !confirm-discourse-restore before touching anything)
  !confirm-discourse-restore            proceed with the staged restore (takes a fresh safety backup first)
  !abort-discourse-restore              cancel a staged restore

!help or !commands shows this message."""


def _parse_repair_plan(report: str) -> list[str]:
    if _REPAIR_PLAN_MARKER not in report:
        return []
    after = report.split(_REPAIR_PLAN_MARKER, 1)[1]
    commands: list[str] = []
    for line in after.splitlines():
        line = line.strip()
        if not line:
            if commands:
                break
            continue
        match = _REPAIR_COMMAND_LINE_RE.match(line)
        if not match:
            break
        subcommand = match.group(1).strip()
        if not _REPAIR_COMMAND_RE.match(subcommand):
            break
        commands.append(subcommand)
    return commands


_ROLLBACK_SAFETY_RE = re.compile(r"ROLLBACK SAFETY:\s*(safe|unsafe)", re.IGNORECASE)


def _parse_rollback_safety(report: str) -> bool:
    match = _ROLLBACK_SAFETY_RE.search(report)
    return bool(match) and match.group(1).lower() == "safe"


_MASS_RECOVERY_RE = re.compile(
    r"MASS RECOVERY:\s*(redeploy-only|restore-and-redeploy|needs-vm-restore|unknown)", re.IGNORECASE,
)


def _parse_mass_recovery(report: str) -> str:
    match = _MASS_RECOVERY_RE.search(report)
    return match.group(1).lower() if match else "unknown"


_IMMICH_RECOVERY_RE = re.compile(
    r"IMMICH RECOVERY:\s*(redeploy-safe|restore-db-and-redeploy|unknown)", re.IGNORECASE,
)


def _parse_immich_recovery(report: str) -> str:
    match = _IMMICH_RECOVERY_RE.search(report)
    return match.group(1).lower() if match else "unknown"


_NEXTCLOUD_RECOVERY_RE = re.compile(
    r"NEXTCLOUD RECOVERY:\s*(redeploy-safe|restore-db-and-redeploy|unknown)", re.IGNORECASE,
)


def _parse_nextcloud_recovery(report: str) -> str:
    match = _NEXTCLOUD_RECOVERY_RE.search(report)
    return match.group(1).lower() if match else "unknown"


_DISCOURSE_RECOVERY_RE = re.compile(
    r"DISCOURSE RECOVERY:\s*(restore-recommended|unknown)", re.IGNORECASE,
)


def _parse_discourse_recovery(report: str) -> str:
    match = _DISCOURSE_RECOVERY_RE.search(report)
    return match.group(1).lower() if match else "unknown"


class Orchestrator:
    def __init__(self, config: Config, store: Store):
        self.config = config
        self.store = store
        self.anthropic_client = anthropic.Anthropic(api_key=config.anthropic_api_key)
        llm_usage.install(self.anthropic_client, store)
        local_llm.configure(
            model=config.llm_local_fallback_model, mgmt_host=config.mgmt_host,
            mgmt_user=config.mgmt_ssh_user, identity_file=config.ssh_identity_file,
        )
        self.proxmox = ProxmoxClient(config.proxmox_api_host, config.proxmox_token,
                                      config.proxmox_verify_tls)
        self.pbs = PBSClient(config.pbs_api_host, config.pbs_token, config.pbs_verify_tls)
        self.matrix: MatrixBot | None = None
        self._pipelines_started: set[int] = set()


    async def handle_diun_event(self, service_name: str, parsed: dict) -> None:
        existing = self.store.get_by_diun_entry(parsed["diun_entry_id"])
        if existing is not None:
            logger.info("duplicate diun event for %s, ignoring", parsed["diun_entry_id"])
            return

        service = self.config.services[service_name]
        current_version = self.store.get_last_known_version(service_name) or service.current_version or "unknown"
        new_tag = parsed["tag"]
        new_version = new_tag

        effective_registry = service.registry_overrides.get(parsed["image"]) or service.registry
        if effective_registry and not re.search(r"\d+\.\d+", new_tag):
            github_repo = (
                service.release_source.repo
                if service.release_source and service.release_source.type == "github"
                else None
            )
            try:
                resolved = await asyncio.to_thread(
                    tag_resolver.resolve_tag, effective_registry, new_tag, parsed["digest"],
                    github_releases_repo=github_repo,
                )
            except Exception:
                logger.exception("tag resolution failed for %s", service_name)
                resolved = None
            if resolved:
                new_version = resolved
                await self._notify(f"{service_name}'s floating tag {new_tag!r} resolved to {resolved}")
            else:
                logger.warning(
                    "could not resolve floating tag %r for %s (digest=%s) -- "
                    "staging with no version delta, classifier will see no release notes",
                    new_tag, service_name, parsed["digest"],
                )

        update_id = self.store.create_update(
            service_name=service_name,
            image=parsed["image"],
            current_version=current_version,
            new_version=new_version,
            diun_entry_id=parsed["diun_entry_id"],
            digest=parsed.get("digest"),
        )
        asyncio.create_task(self._research_and_stage(update_id, service_name))

    async def handle_command(self, command: str, update_id: int, approved_by: str) -> None:
        record = self.store.get(update_id)
        if record is None:
            await self._notify(f"No update #{update_id} found.")
            return

        if command == "status":
            await self._notify(_format_status(record))
            return

        if command == "abort":
            if record.stage.terminal:
                await self._notify(f"Update #{update_id} is already {record.stage.value}.")
                return
            self.store.set_stage(update_id, Stage.ABORTED, f"aborted by {approved_by}")
            await self._notify(f"Update #{update_id} ({record.service_name}) aborted by {approved_by}.")
            return

        if command == "approve":
            if record.stage != Stage.STAGED_PENDING_APPROVAL:
                await self._notify(
                    f"Update #{update_id} isn't awaiting approval (currently: {record.stage.value})."
                )
                return
            self.store.set_approved(update_id, approved_by)
            self.store.set_stage(update_id, Stage.APPROVED, f"approved by {approved_by}")
            await self._notify(f"Update #{update_id} approved by {approved_by}, starting pipeline...")
            return

        if command in ("confirm-backup", "skip-backup"):
            if record.stage != Stage.AWAITING_BACKUP_DECISION:
                await self._notify(
                    f"Update #{update_id} isn't awaiting a backup decision (currently: {record.stage.value})."
                )
                return
            decision = "confirm" if command == "confirm-backup" else "skip"
            self.store.set_backup_decision(update_id, decision)
            await self._notify(f"Update #{update_id}: backup decision set to '{decision}' by {approved_by}.")
            return

        if command == "confirm-reboot":
            if record.stage != Stage.AWAITING_REBOOT_DECISION:
                await self._notify(
                    f"Update #{update_id} isn't awaiting a reboot decision (currently: {record.stage.value})."
                )
                return
            self.store.set_reboot_decision(update_id, "confirm")
            await self._notify(f"Update #{update_id}: reboot confirmed by {approved_by}.")
            return

        if command == "rollback":
            if not record.stage.terminal:
                await self._notify(
                    f"Update #{update_id} is still in progress (currently: {record.stage.value}) -- "
                    f"wait for it to finish before rolling back."
                )
                return
            service = self.config.services[record.service_name]
            if service.portainer and service.registry is not None:
                pins, missing = [], []
                for tracked_image in service.images:
                    digest = self.store.get_last_known_digest(record.service_name, tracked_image)
                    (pins.append((tracked_image, digest)) if digest else missing.append(tracked_image))
                if missing:
                    await self._notify(
                        f"{record.service_name}: no prior successful digest on record for "
                        f"{', '.join(missing)} yet -- can't roll back."
                    )
                    return
                await self._notify(f"Update #{update_id}: redeploying {record.service_name} to its last known-good images...")
                ok, detail = await asyncio.to_thread(
                    portainer.redeploy_pinned_digests, service.portainer, self.config.portainer_token, pins,
                )
                await self._notify(f"Update #{update_id}: {detail if ok else 'redeploy failed -- ' + detail}")
                return
            if not service.compose_dir:
                await self._notify(
                    f"{record.service_name} isn't a Compose-based service (Portainer/launcher-managed) -- "
                    f"!rollback doesn't apply here."
                )
                return
            if service.registry is not None and not service.occ_container:
                last_digest = self.store.get_last_known_digest(record.service_name, record.image)
                if not last_digest:
                    await self._notify(
                        f"{record.service_name}: no prior successful digest on record for "
                        f"{record.image} yet -- can't roll back."
                    )
                    return
                await self._notify(f"Update #{update_id}: redeploying {record.service_name} to its last known-good image...")
                ok, detail = await asyncio.to_thread(
                    executor.redeploy_pinned_digest, service, record.image, last_digest,
                    identity_file=self.config.ssh_identity_file,
                )
                await self._notify(f"Update #{update_id}: {detail if ok else 'redeploy failed -- ' + detail}")
                return
            await self._notify(f"Update #{update_id}: rolling back {record.service_name}...")
            ok, detail = await asyncio.to_thread(
                executor.rollback_compose_file, service, update_id,
                identity_file=self.config.ssh_identity_file,
            )
            if not ok:
                await self._notify(f"Update #{update_id}: rollback failed or doesn't apply -- {detail}")
                return
            await self._notify(
                f"Update #{update_id}: rolled back and recreated {record.service_name} "
                f"against the pre-update compose file ({record.new_version} -> {record.current_version})."
            )
            return

        if command == "mark-passed":
            if record.stage != Stage.DONE_FAILED:
                await self._notify(
                    f"Update #{update_id} isn't marked failed (currently: {record.stage.value}) -- "
                    f"nothing to override."
                )
                return
            sibling_ids = self.store.mark_passed(update_id, approved_by)
            msg = f"Update #{update_id} ({record.service_name}) marked passed by {approved_by}."
            if sibling_ids:
                msg += (
                    f" Also resolved sibling update(s) "
                    f"{', '.join(f'#{i}' for i in sibling_ids)} (same service+version, "
                    f"a different tracked image already applied by the same stack redeploy)."
                )
            await self._notify(msg)
            return

        if command == "investigate":
            if not self.config.mgmt_host:
                await self._notify("!investigate isn't configured (no mgmt host set).")
                return
            await self._notify(
                f"Update #{update_id}: starting a read-only Claude Code investigation into "
                f"{record.service_name} (can take a few minutes)..."
            )
            asyncio.create_task(self._run_investigation(update_id, record))
            return

        if command == "repair":
            if not record.proposed_repair:
                await self._notify(
                    f"Update #{update_id}: no repair plan on file -- run `!investigate {update_id}` first."
                )
                return
            service = self.config.services[record.service_name]
            if not service.occ_container:
                await self._notify(
                    f"{record.service_name} doesn't support !repair (no occ_container configured)."
                )
                return
            plan = "\n".join(f"  $ occ {c}" for c in record.proposed_repair)
            await self._notify(f"Update #{update_id}: running repair plan on {record.service_name}...\n{plan}")
            ok, output_lines = await asyncio.to_thread(
                executor.run_repair_plan, service, record.proposed_repair,
                identity_file=self.config.ssh_identity_file,
            )
            joined = "\n\n".join(output_lines)
            status = "completed" if ok else "STOPPED (a command failed -- see output below)"
            await self._notify(f"Update #{update_id}: repair plan {status}.\n{joined}")
            return

    async def handle_help(self) -> None:
        await self._notify(_HELP_TEXT)

    async def handle_check_updates(self) -> None:
        if not self.config.monitoring_host:
            await self._notify("!check-updates isn't configured (no monitoring host set).")
            return
        await self._notify("Checking for updates now (restarting Diun to force an immediate scan)...")
        ok, detail = await asyncio.to_thread(
            diun_trigger.trigger_check,
            self.config.monitoring_host, self.config.monitoring_ssh_user,
            identity_file=self.config.ssh_identity_file,
        )
        if not ok:
            await self._notify(f"Couldn't trigger the check: {detail}")
            return
        await self._notify(
            "Check triggered -- if anything new turns up, it'll be staged here in the next "
            "10-15 seconds. No message here after that means everything's current."
        )

    async def handle_trust_device(self, mac: str, label: str | None) -> None:
        normalized = mac.lower().replace("-", ":")
        already_known = self.store.trust_device(normalized, label)
        self.store.resolve_finding_by_subject("network_monitor", normalized)
        label_note = f" as \"{label}\"" if label else ""
        if already_known:
            await self._notify(f"Trusted {normalized}{label_note}. Won't be flagged as new again.")
        else:
            await self._notify(
                f"Trusted {normalized}{label_note} (wasn't seen before -- pre-approved; "
                f"its first real sighting won't trigger a new-device alert)."
            )

    async def handle_trust_peer(self, pubkey: str, label: str | None) -> None:
        already_known = self.store.trust_wg_peer(pubkey, label)
        self.store.resolve_finding_by_subject("wireguard", pubkey)
        label_note = f" as \"{label}\"" if label else ""
        if already_known:
            await self._notify(f"Trusted WireGuard peer {pubkey}{label_note}. Won't be flagged as new again.")
        else:
            await self._notify(
                f"Trusted WireGuard peer {pubkey}{label_note} (wasn't seen before -- pre-approved; "
                f"its first real sighting won't trigger a new-peer alert)."
            )

    async def handle_block_ip(self, ip: str, reason: str | None) -> None:
        if not self.config.fortigate_write_token_file:
            await self._notify("!block-ip: no fortigate_write_token_file configured, can't do this yet.")
            return
        ok, detail = await asyncio.to_thread(
            fortigate_blocklist.trigger_block_ip,
            self.config.mgmt_host, self.config.mgmt_ssh_user, ip, reason or "blocked via !block-ip",
            fortigate_api_host=self.config.fortigate_api_host,
            fortigate_write_token_file=self.config.fortigate_write_token_file,
            identity_file=self.config.ssh_identity_file,
        )
        await self._notify(f"!block-ip {ip}: {detail}" if ok else f"!block-ip {ip} FAILED: {detail}")

    async def handle_unblock_ip(self, ip: str) -> None:
        if not self.config.fortigate_write_token_file:
            await self._notify("!unblock-ip: no fortigate_write_token_file configured, can't do this yet.")
            return
        ok, detail = await asyncio.to_thread(
            fortigate_blocklist.trigger_unblock_ip,
            self.config.mgmt_host, self.config.mgmt_ssh_user, ip,
            fortigate_api_host=self.config.fortigate_api_host,
            fortigate_write_token_file=self.config.fortigate_write_token_file,
            identity_file=self.config.ssh_identity_file,
        )
        await self._notify(f"!unblock-ip {ip}: {detail}" if ok else f"!unblock-ip {ip} FAILED: {detail}")

    def _kb_active_registration_token(self) -> str:
        return self.store.get_meta("kb_matrix_active_registration_token") or self.config.matrix_registration_token

    _KB_PAGE_PUSH_MAX_ATTEMPTS = 3
    _KB_PAGE_PUSH_RETRY_DELAY_SECONDS = 15.0

    async def _kb_finish_rotation(self, new_token: str, *, trigger_label: str) -> str:
        relay_ok, relay_detail = False, ""
        for attempt in range(1, self._KB_PAGE_PUSH_MAX_ATTEMPTS + 1):
            relay_ok, relay_detail = await asyncio.to_thread(
                kb_page_relay.trigger_update_registration_token_page,
                self.config.mgmt_host, self.config.mgmt_ssh_user, new_token,
                identity_file=self.config.ssh_identity_file,
            )
            if relay_ok or attempt == self._KB_PAGE_PUSH_MAX_ATTEMPTS:
                break
            await asyncio.sleep(self._KB_PAGE_PUSH_RETRY_DELAY_SECONDS)
        self.store.set_meta("kb_matrix_active_registration_token", new_token)
        if relay_ok:
            return "KB page updated automatically."
        finding_id, trailer = self._create_finding(
            "kb_lockdown", f"page_push:{trigger_label}", "warning",
            f"Rotated the Matrix registration token but couldn't push the KB page update after "
            f"{self._KB_PAGE_PUSH_MAX_ATTEMPTS} attempts: {relay_detail}",
            {"new_token": new_token, "trigger": trigger_label, "attempts": self._KB_PAGE_PUSH_MAX_ATTEMPTS},
        )
        return (
            f"Rotated successfully, but the KB page push failed after "
            f"{self._KB_PAGE_PUSH_MAX_ATTEMPTS} attempts: {relay_detail}\n{trailer}\n"
            f"Manually update kb-site's matrix/restricted/registration-token.md to "
            f"`{new_token}` in the meantime."
        )

    async def handle_kb_rotate_token(self) -> None:
        old_token = self._kb_active_registration_token()
        if not (self.config.matrix_admin_access_token and self.config.kb_admin_room_id
                and self.config.kb_admin_bot_user_id and old_token):
            await self._notify(
                "!kb-rotate-token: MATRIX_ADMIN_ACCESS_TOKEN/kb_admin_room_id/kb_admin_bot_user_id/"
                "a known current registration token not fully configured, can't do this yet."
            )
            return
        new_token, err = await asyncio.to_thread(
            kb_lockdown.rotate_registration_token,
            self.config.matrix_homeserver, self.config.matrix_admin_access_token, self.config.kb_admin_room_id,
            self.config.kb_admin_bot_user_id, old_token, issue_flag="--immortal",
        )
        if not new_token:
            await self._notify(f"!kb-rotate-token FAILED: {err}")
            return
        warn = f" (note: {err})" if err else ""
        status = await self._kb_finish_rotation(new_token, trigger_label="manual")
        await self._notify(f"!kb-rotate-token: new registration token is `{new_token}`{warn}\n{status}")

    async def _handle_kb_set_policy(self, command: str, policy_id: str, label: str) -> None:
        if not (self.config.cloudflare_access_api_token and self.config.cloudflare_account_id
                and self.config.kb_matrix_teamspeak_app_id and policy_id):
            await self._notify(f"{command}: not fully configured yet, can't do this.")
            return
        ok, err = await asyncio.to_thread(
            kb_lockdown.set_application_policies,
            self.config.cloudflare_access_api_token, self.config.cloudflare_account_id,
            self.config.kb_matrix_teamspeak_app_id, [policy_id],
        )
        await self._notify(f"{command}: now using the {label} policy." if ok else f"{command} FAILED: {err}")

    async def handle_kb_restrict(self) -> None:
        await self._handle_kb_set_policy("!kb-restrict", self.config.kb_strict_policy_id, "strict allowlist")

    async def handle_kb_unrestrict(self) -> None:
        await self._handle_kb_set_policy("!kb-unrestrict", self.config.kb_loose_policy_id, "normal Everyone+OTP")

    async def handle_blocklist(self) -> None:
        if not self.config.fortigate_write_token_file:
            await self._notify("!blocklist: no fortigate_write_token_file configured, can't do this yet.")
            return
        ok, blocked_ips, detail = await asyncio.to_thread(
            fortigate_blocklist.trigger_list_blocked_ips,
            self.config.mgmt_host, self.config.mgmt_ssh_user,
            fortigate_api_host=self.config.fortigate_api_host,
            fortigate_write_token_file=self.config.fortigate_write_token_file,
            identity_file=self.config.ssh_identity_file,
        )
        if not ok:
            await self._notify(f"!blocklist FAILED: {detail}")
            return
        if not blocked_ips:
            await self._notify("!blocklist: nothing currently blocked.")
            return
        await self._notify("Currently blocked:\n" + "\n".join(f"  {ip}" for ip in blocked_ips))

    async def handle_findings(self) -> None:
        findings = self.store.list_findings()
        deferred_count = self.store.count_deferred_findings()
        if not findings:
            msg = "No open findings."
            if deferred_count:
                msg += f" ({deferred_count} CVE finding(s) deferred -- no fix-pipeline action needed right now.)"
            await self._notify(msg)
            return
        lines = [f"{len(findings)} open finding(s):"]
        for f in findings:
            age_hours = (
                datetime.now(timezone.utc) - datetime.fromisoformat(f["created_at"])
            ).total_seconds() / 3600
            lines.append(
                f"#{f['id']} [{f['severity']}] ({f['status']}, {age_hours:.1f}h old) "
                f"{f['source']}: {f['summary']}"
            )
        if deferred_count:
            lines.append(f"(+ {deferred_count} CVE finding(s) deferred -- no fix-pipeline action needed right now.)")
        await self._notify("\n".join(lines))

    async def handle_pending(self) -> None:
        records = self.store.list_active()
        if not records:
            await self._notify("No outstanding updates -- everything's either done or hasn't been staged yet.")
            return
        lines = [f"{len(records)} outstanding update(s):"]
        for r in records:
            risk_note = ""
            if r.risk_level:
                breaking = ", breaking changes" if r.breaking_changes else ""
                sec = (
                    f", security: {r.security_severity}"
                    if r.security_severity and r.security_severity != "none"
                    else ""
                )
                risk_note = f" (risk: {r.risk_level}{breaking}{sec})"
            lines.append(
                f"#{r.id} {r.service_name} {r.current_version} -> {r.new_version} "
                f"[{r.stage.value}]{risk_note}"
            )
        await self._notify("\n".join(lines))

    async def handle_briefing(self) -> None:
        briefing = await self._generate_briefing(
            "This briefing was requested on-demand via !briefing."
        )
        await self._notify(briefing)

    async def _generate_briefing(self, framing: str, period: str = "on_demand") -> str:
        findings = self.store.list_findings()
        local_tz = ZoneInfo(self.config.local_timezone)
        now_local = datetime.now(local_tz)
        today_start_local = now_local.replace(hour=0, minute=0, second=0, microsecond=0)
        updates_period_label: str | None = None
        upcoming_period_label: str | None = None
        updates_window: tuple[datetime, datetime] | None = None
        if period == "morning":
            updates_period_label, upcoming_period_label = "yesterday", "today"
            updates_window = (today_start_local - timedelta(days=1), today_start_local)
        elif period == "evening":
            updates_period_label, upcoming_period_label = "today", "tonight/tomorrow"
            updates_window = (today_start_local, now_local)

        if updates_window is not None:
            window_start_utc, window_end_utc = (
                t.astimezone(timezone.utc) for t in updates_window
            )
            recent_updates = [
                u for u in self.store.list_recent(limit=200)
                if u.stage in (Stage.DONE_SUCCESS, Stage.DONE_FAILED) and u.updated_at
                and window_start_utc <= datetime.fromisoformat(u.updated_at) < window_end_utc
            ]
        else:
            recent_updates = [
                u for u in self.store.list_recent(limit=60)
                if u.stage in (Stage.DONE_SUCCESS, Stage.DONE_FAILED)
            ][:15]
        ops_health = self.store.list_ops_health()
        disk_health = self.store.list_disk_health()
        pending_updates = self.store.list_by_stage(Stage.STAGED_PENDING_APPROVAL)
        auto_remediation = self.store.list_recent_findings_by_source(
            ["kuma_monitor", "discourse_backup"], hours=18.0,
        )

        current_pending_ids = {u.id for u in pending_updates}
        last_pending_raw = self.store.get_meta("briefing_last_pending_ids")
        last_pending_ids = set(json.loads(last_pending_raw)) if last_pending_raw else set()
        new_pending_ids = current_pending_ids - last_pending_ids
        cleared_pending_lines: list[str] = []
        for cleared_id in sorted(last_pending_ids - current_pending_ids):
            rec = self.store.get(cleared_id)
            if rec is None:
                continue
            if rec.stage == Stage.ABORTED and rec.superseded_by:
                outcome = f"superseded by #{rec.superseded_by} (a newer version came in)"
            elif rec.stage == Stage.DONE_SUCCESS:
                outcome = "approved and deployed successfully"
            elif rec.stage == Stage.DONE_FAILED:
                outcome = "approved, but the update failed"
            elif rec.stage == Stage.ABORTED:
                outcome = "manually aborted"
            else:
                outcome = f"now in stage {rec.stage.value} (still in progress)"
            cleared_pending_lines.append(
                f"#{cleared_id} {rec.service_name} ({rec.current_version} -> {rec.new_version}): {outcome}"
            )
        self.store.set_meta("briefing_last_pending_ids", json.dumps(sorted(current_pending_ids)))

        next_maintenance: dict | None = None
        cfg = self.config.scheduled_maintenance
        if cfg.enabled:
            now = datetime.now(ZoneInfo(self.config.local_timezone))
            next_maintenance = {
                "window_start": _next_window_start(now, cfg.weekday, cfg.start_hour, cfg.window_hours),
                "services": cfg.services,
                "approval": self.store.get_meta("sched_maint_approval") or "",
            }

        network_trend: dict = {}
        if self.config.librenms_api_host and self.config.mgmt_host:
            ok, network_trend, _err = await asyncio.to_thread(
                librenms_monitor.trigger_bandwidth_trend,
                self.config.mgmt_host, self.config.mgmt_ssh_user,
                _backup_checks_payload(ops_health),
                identity_file=self.config.ssh_identity_file,
            )
            if not ok:
                network_trend = {}

        network_baseline_raw = self.store.get_meta("network_trend_baseline")
        network_baseline = json.loads(network_baseline_raw) if network_baseline_raw else {}
        network_notable, network_steady, new_network_baseline = _network_trend_delta(
            network_trend, network_baseline,
        )
        self.store.set_meta("network_trend_baseline", json.dumps(new_network_baseline))

        reachability = reachability_correlation.correlate(ops_health)

        wifi_rf_peaks: dict[str, dict] | None = None
        wifi_rf_crowding_peak: dict | None = None
        if self.config.wifi_rf.enabled:
            wifi_rf_peaks = {
                "busy_util": await asyncio.to_thread(self.store.wifi_rf_24h_peak, "busy_util"),
                "inter_util": await asyncio.to_thread(self.store.wifi_rf_24h_peak, "inter_util"),
            }
            wifi_rf_crowding_peak = await asyncio.to_thread(
                self.store.wifi_rf_channel_crowding_24h_peak,
            )

        return await asyncio.to_thread(
            classifier.generate_health_briefing,
            client=self.anthropic_client, model=self.config.llm_light_model or self.config.llm_model,
            fallback_model=self.config.llm_model,
            findings=findings, recent_updates=recent_updates,
            ops_health=ops_health, disk_health=disk_health,
            network_trend=network_trend,
            network_notable=network_notable, network_steady=network_steady,
            pending_updates=pending_updates, next_maintenance=next_maintenance,
            auto_remediation=auto_remediation,
            new_pending_ids=new_pending_ids, cleared_pending_lines=cleared_pending_lines,
            reachability=reachability,
            wifi_rf_peaks=wifi_rf_peaks,
            wifi_rf_crowding_peak=wifi_rf_crowding_peak,
            framing=framing,
            updates_period_label=updates_period_label,
            upcoming_period_label=upcoming_period_label,
        )

    async def run_daily_briefing_loop(self, poll_interval_seconds: float) -> None:
        cfg = self.config
        while True:
            await asyncio.sleep(poll_interval_seconds)
            now = datetime.now(ZoneInfo(cfg.local_timezone))
            today = now.date().isoformat()

            if cfg.daily_briefing_morning_hour >= 0 and now.hour >= cfg.daily_briefing_morning_hour:
                if self.store.get_meta("daily_briefing_morning_date") != today:
                    briefing = await self._generate_briefing(
                        "This is the scheduled morning briefing -- a quick look at where "
                        "things stand heading into the day.",
                        period="morning",
                    )
                    await self._notify(f"Good morning! Here's today's briefing:\n\n{briefing}")
                    self.store.set_meta("daily_briefing_morning_date", today)

            if cfg.daily_briefing_evening_hour >= 0 and now.hour >= cfg.daily_briefing_evening_hour:
                if self.store.get_meta("daily_briefing_evening_date") != today:
                    briefing = await self._generate_briefing(
                        "This is the scheduled evening briefing -- a recap framing, covering "
                        "the same current state as the morning one.",
                        period="evening",
                    )
                    await self._notify(f"Evening recap:\n\n{briefing}")
                    self.store.set_meta("daily_briefing_evening_date", today)

    _DIGEST_ONLY_SOURCES = frozenset({"config_drift"})

    def _create_finding(
        self, source: str, subject: str, severity: str, summary: str, detail: dict | None = None,
        *, notify_message: str | None = None,
    ) -> tuple[int, str]:
        finding_id = self.store.create_finding(source, subject, severity, summary, detail)
        if severity == "critical" and self.config.mgmt_host:
            finding = self.store.get_finding(finding_id)
            self.store.set_finding_status(finding_id, "investigating")
            asyncio.create_task(self._run_finding_investigation(finding_id, finding))
            trailer = f"Finding #{finding_id} (critical) -- investigating automatically, see the follow-up report."
        else:
            trailer = f"Finding #{finding_id} -- to investigate further: `!investigate-finding {finding_id}`"
        if notify_message is not None and severity == "critical" and source not in self._DIGEST_ONLY_SOURCES:
            asyncio.create_task(self._notify(f"{notify_message}\n{trailer}"))
        return finding_id, trailer

    _OUTAGE_REPORT_COOLDOWN_SECONDS = 300

    async def handle_outage_report(self, form: dict, client_ip: str) -> tuple[bool, str]:
        ok, error = outage_report.validate_submission(form)
        if not ok:
            return False, error

        cooldown_key = f"outage_report_last:{client_ip}"
        last_raw = self.store.get_meta(cooldown_key)
        if last_raw:
            elapsed = (datetime.now(timezone.utc) - datetime.fromisoformat(last_raw)).total_seconds()
            if elapsed < self._OUTAGE_REPORT_COOLDOWN_SECONDS:
                return False, "Only one report every few minutes, please -- try again shortly."
        self.store.set_meta(cooldown_key, datetime.now(timezone.utc).isoformat())

        service = (form.get("service") or "").strip()
        description = (form.get("description") or "").strip()
        reporter = (form.get("reporter") or "").strip() or "anonymous"
        symptom = outage_report.resolve_symptom(form, service)

        severity = "critical" if symptom == outage_report.CRITICAL_SYMPTOM else "warning"

        finding_id, trailer = self._create_finding(
            "user_report", service, severity,
            f"User-reported issue with {service}: {symptom}", {
                "service": service, "symptom": symptom, "description": description,
                "reporter": reporter, "client_ip": client_ip,
            },
        )
        await self._notify(
            f"User report: {service} -- {symptom} ({reporter})\n  \"{description}\"\n{trailer}"
        )
        return True, "Thanks — that's been sent."

    async def handle_investigate_finding(self, finding_id: int) -> None:
        finding = self.store.get_finding(finding_id)
        if finding is None:
            await self._notify(f"No finding #{finding_id} found.")
            return
        if finding["status"] == "resolved":
            await self._notify(f"Finding #{finding_id} is already resolved -- nothing to investigate.")
            return
        if not self.config.mgmt_host:
            await self._notify("!investigate-finding isn't configured (no mgmt host set).")
            return

        self.store.set_finding_status(finding_id, "investigating")
        await self._notify(
            f"Finding #{finding_id}: starting a read-only Claude Code investigation into "
            f"{finding['subject']} (can take a few minutes)..."
        )
        asyncio.create_task(self._run_finding_investigation(finding_id, finding))

    async def _resolve_kuma_monitor_proxmox_context(self, monitor_name: str) -> dict | None:
        service_key = kuma_crash_monitor.KUMA_MONITOR_TO_SERVICE.get(
            monitor_name.lower(), monitor_name.lower(),
        )
        tracked_service = self.config.services.get(service_key)
        if tracked_service is None:
            return None
        try:
            node = await asyncio.to_thread(self.proxmox.node_for_vmid, tracked_service.vmid)
            vm_type = await asyncio.to_thread(self.proxmox.vm_type_for_vmid, tracked_service.vmid)
            locked = await asyncio.to_thread(
                self.proxmox.vm_locked_for_backup, node, tracked_service.vmid, vm_type,
            )
            last_backup = await asyncio.to_thread(self.proxmox.last_vm_backup, node, tracked_service.vmid)
            return {
                "vmid": tracked_service.vmid, "node": node,
                "currently_locked_for_backup": locked,
                "last_vm_backup": last_backup,
            }
        except Exception as exc:
            logger.warning("kuma_monitor proxmox context lookup for %s failed: %s", monitor_name, exc)
            return None

    async def _run_finding_investigation(
        self, finding_id: int, finding: dict, *, notify: bool = True,
    ) -> tuple[bool, str]:
        recent_roams = None
        if finding.get("source") == "ap_flapping":
            mac = finding.get("subject")
            recent_roams = [r for r in self.store.get_recent_roams(since_hours=24) if r.get("mac") == mac]

        proxmox_backup_context = None
        if finding.get("source") == "kuma_monitor":
            monitor_name = ((finding.get("detail") or {}).get("raw_detail") or {}).get("name", "")
            if monitor_name:
                proxmox_backup_context = await self._resolve_kuma_monitor_proxmox_context(monitor_name)

        ok, output = await asyncio.to_thread(
            investigate.trigger_finding_investigation,
            self.config.mgmt_host, self.config.mgmt_ssh_user,
            finding=finding,
            omada_config_file=self.config.omada_config_file,
            fortigate_api_host=self.config.fortigate_api_host,
            fortigate_token_file=self.config.fortigate_token_file,
            synology_config_file=self.config.synology_config_file,
            recent_roams=recent_roams,
            hosts=self._build_fleet_hosts(),
            proxmox_backup_context=proxmox_backup_context,
            identity_file=self.config.ssh_identity_file,
        )
        if not ok:
            if notify:
                await self._notify(f"Finding #{finding_id}: investigation failed to run -- {output.strip()}")
            return ok, output
        self.store.set_investigation_report(finding_id, output.strip())
        if notify:
            await self._notify(f"Finding #{finding_id} investigation report:\n{output.strip()}")
        asyncio.create_task(self._maybe_file_code_fix_issue(finding_id, output.strip()))
        return ok, output

    async def _maybe_file_code_fix_issue(self, finding_id: int, report: str) -> None:
        if not (self.config.github_repo and self.config.github_issue_token_file and self.config.mgmt_host):
            return
        match = _CODE_FIX_NEEDED_RE.search(report)
        if not match:
            return
        file_path, summary = match.group(1), match.group(2).strip()

        dedup_key = f"code_fix_issue:{file_path}:{summary}"
        existing = self.store.get_meta(dedup_key)
        if existing:
            await self._notify(
                f"Finding #{finding_id}: already filed as code-fix issue #{existing} -- not refiling."
            )
            return

        title = f"{file_path}: {summary}"[:250]
        body = (
            f"Filed automatically from finding #{finding_id}'s investigation report.\n\n"
            f"**File:** `{file_path}`\n**Summary:** {summary}\n\n---\n\nFull investigation report:\n\n{report}"
        )
        ok, issue_number, detail = await asyncio.to_thread(
            github_issue.trigger_create_issue,
            self.config.mgmt_host, self.config.mgmt_ssh_user,
            repo=self.config.github_repo, issue_token_file=self.config.github_issue_token_file,
            title=title, body=body, labels=["from-bot", "bug"],
            identity_file=self.config.ssh_identity_file,
        )
        if not ok:
            logger.warning("code-fix issue filing failed for finding #%s: %s", finding_id, detail)
            return
        self.store.set_meta(dedup_key, str(issue_number))
        await self._notify(
            f"Finding #{finding_id}'s investigation flagged a likely bug in this bot's own code "
            f"({file_path}) -- filed as issue #{issue_number}. Apply the \"claude\" label on GitHub "
            "if you want the agent to take a pass at a fix."
        )

    async def handle_resolve_finding(self, finding_id: int) -> None:
        finding = self.store.get_finding(finding_id)
        if finding is None:
            await self._notify(f"No finding #{finding_id} found.")
            return
        if finding["status"] == "resolved":
            await self._notify(f"Finding #{finding_id} is already resolved.")
            return
        self.store.set_finding_status(finding_id, "resolved")
        await self._notify(f"Finding #{finding_id} ({finding['subject']}) marked resolved.")

    async def handle_accept_port(self, finding_id: int) -> None:
        finding = self.store.get_finding(finding_id)
        if finding is None:
            await self._notify(f"No finding #{finding_id} found.")
            return
        detail = finding.get("detail") or {}
        if finding.get("source") != "security_scan" or detail.get("finding_type") != "open_port":
            await self._notify(f"Finding #{finding_id} isn't a !security-scan open-port finding.")
            return
        ok = self.store.accept_security_finding(detail["host"], "open_port", detail["identifier"])
        if not ok:
            await self._notify(f"Finding #{finding_id}: no matching known-finding row to accept.")
            return
        self.store.resolve_finding(finding_id)
        await self._notify(
            f"Finding #{finding_id} ({finding['subject']}) accepted as an intentional listener -- won't resurface."
        )

    _WEDDING_ACCESS_REQUEST_COOLDOWN_SECONDS = 3600

    async def handle_wedding_access_request(self, form: dict, client_ip: str) -> tuple[bool, str]:
        ok, error = wedding_access_request.validate_submission(form)
        if not ok:
            return False, error

        cooldown_key = f"wedding_access_request_last:{client_ip}"
        last_raw = self.store.get_meta(cooldown_key)
        if last_raw:
            elapsed = (datetime.now(timezone.utc) - datetime.fromisoformat(last_raw)).total_seconds()
            if elapsed < self._WEDDING_ACCESS_REQUEST_COOLDOWN_SECONDS:
                return False, "Only one request per hour, please -- try again shortly."
        self.store.set_meta(cooldown_key, datetime.now(timezone.utc).isoformat())

        name = (form.get("name") or "").strip()
        email = (form.get("email") or "").strip().lower()
        reason = (form.get("reason") or "").strip()

        match_source = None
        service = self.config.services.get("wp-web1")
        if service is not None and await asyncio.to_thread(
            wedding_hub_contacts.is_known_contact, service, self.config.wedding_hub_db_path, email,
            identity_file=self.config.ssh_identity_file,
            mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
        ):
            match_source = "wedding ledger guest"
        elif self.store.is_requester_whitelisted(email):
            match_source = "manual whitelist"

        if match_source is None:
            return True, "Thanks — that's been sent."

        request_id = self.store.create_access_request(name, email, reason, client_ip, match_source)
        await self._notify_wedding(
            f"Access request #{request_id}: {name} <{email}> ({match_source}) -- \"{reason}\"\n"
            f"  !approve-access {request_id} [days] / !deny-access {request_id}"
        )
        return True, "Thanks — that's been sent."

    async def handle_approve_access(self, request_id: int, days: int | None) -> None:
        request = self.store.get_access_request(request_id)
        if request is None:
            await self._notify_wedding(f"No access request #{request_id} found.")
            return
        if request["status"] != "pending":
            await self._notify_wedding(f"Access request #{request_id} is already {request['status']}.")
            return
        if not self.config.wedding_access_request_app_id or not self.config.wedding_access_request_policy_id:
            await self._notify_wedding(
                f"Access request #{request_id}: wedding_access_request.app_id/policy_id aren't configured yet."
            )
            return

        ok, error = await asyncio.to_thread(
            cloudflare_access.add_policy_include_email,
            self.config.cloudflare_api_token, self.config.cloudflare_account_id,
            self.config.wedding_access_request_app_id, self.config.wedding_access_request_policy_id,
            request["email"],
        )
        if not ok:
            await self._notify_wedding(f"Access request #{request_id}: Cloudflare update failed -- {error}")
            return

        if days is not None:
            expires_at = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()
            expiry_note = f"access for {days} days, expires {expires_at}"
        elif self.config.wedding_access_request_date:
            expires_at = datetime.fromisoformat(
                self.config.wedding_access_request_date
            ).astimezone(timezone.utc).isoformat()
            expiry_note = f"access until the wedding, expires {expires_at}"
        else:
            grant_days = int(self.config.wedding_access_request_grant_days)
            expires_at = (datetime.now(timezone.utc) + timedelta(days=grant_days)).isoformat()
            expiry_note = f"access for {grant_days} days, expires {expires_at}"

        self.store.approve_access_request(
            request_id, self.config.wedding_access_request_policy_id, expires_at,
        )
        await self._notify_wedding(f"Access request #{request_id} ({request['email']}) approved -- {expiry_note}.")

    async def handle_deny_access(self, request_id: int) -> None:
        request = self.store.get_access_request(request_id)
        if request is None:
            await self._notify_wedding(f"No access request #{request_id} found.")
            return
        if request["status"] != "pending":
            await self._notify_wedding(f"Access request #{request_id} is already {request['status']}.")
            return
        self.store.deny_access_request(request_id)
        await self._notify_wedding(f"Access request #{request_id} ({request['email']}) denied.")

    async def handle_whitelist_requester(self, email: str, label: str | None) -> None:
        self.store.whitelist_requester(email.lower(), label)
        label_note = f" as \"{label}\"" if label else ""
        await self._notify_wedding(f"Whitelisted {email}{label_note} to request wedding-planning access.")

    async def handle_unwhitelist_requester(self, email: str) -> None:
        removed = self.store.unwhitelist_requester(email.lower())
        if removed:
            await self._notify_wedding(f"Removed {email} from the access-request whitelist.")
        else:
            await self._notify_wedding(f"{email} wasn't on the whitelist.")

    async def run_access_grant_expiry_loop(self, interval_seconds: float) -> None:
        while True:
            await self._sleep_until_due("access_grant_expiry", interval_seconds)
            if not self.config.wedding_access_request_app_id or not self.config.wedding_access_request_policy_id:
                continue

            for request in self.store.list_expired_access_grants():
                ok, error = await asyncio.to_thread(
                    cloudflare_access.remove_policy_include_email,
                    self.config.cloudflare_api_token, self.config.cloudflare_account_id,
                    self.config.wedding_access_request_app_id, self.config.wedding_access_request_policy_id,
                    request["email"],
                )
                if not ok:
                    await self._notify_wedding(
                        f"Access request #{request['id']} ({request['email']}): "
                        f"expiry removal failed -- {error}. Will retry next pass."
                    )
                    continue
                self.store.mark_access_request_expired(request["id"])
                await self._notify_wedding(f"Access for {request['email']} expired -- removed from the guest policy.")

    async def handle_restore_access(self, finding_id: int) -> None:
        finding = self.store.get_finding(finding_id)
        if finding is None:
            await self._notify(f"No finding #{finding_id} found.")
            return
        if finding.get("source") != "security_containment":
            await self._notify(f"Finding #{finding_id} isn't an emergency-containment record -- !restore-access doesn't apply here.")
            return
        if finding["status"] == "resolved":
            await self._notify(f"Finding #{finding_id} is already resolved -- access should already be restored.")
            return

        detail = finding.get("detail") or {}
        service_name = detail.get("service_name")
        action_taken = detail.get("action_taken")
        service = self.config.services.get(service_name) if service_name else None
        if service is None or action_taken not in ("stop_tunnel", "stop_service"):
            await self._notify(f"Finding #{finding_id}: can't restore automatically -- missing/invalid service or action in its record ({detail}).")
            return

        if action_taken == "stop_tunnel":
            ok, output = await asyncio.to_thread(
                executor.start_cf_tunnel, service, identity_file=self.config.ssh_identity_file,
                mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
            )
        else:
            ok, output = await asyncio.to_thread(
                executor.start_service, service, identity_file=self.config.ssh_identity_file,
                mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
            )
        if not ok:
            await self._notify(f"Finding #{finding_id}: restore failed -- {output}. Still contained; try again or fix by hand.")
            return
        self.store.set_finding_status(finding_id, "resolved")
        await self._notify(f"Finding #{finding_id} ({service_name}): access restored -- {output}.")

    async def handle_investigate_network(self, description: str) -> None:
        if not self.config.mgmt_host:
            await self._notify("!investigate-network isn't configured (no mgmt host set).")
            return

        subject = f"ondemand-{int(time.time())}"
        finding_id = self.store.create_finding(
            "on_demand", subject, "info", f"On-demand investigation: {description}",
            {"description": description},
        )
        self.store.set_finding_status(finding_id, "investigating")
        await self._notify(
            f"Finding #{finding_id}: starting a read-only investigation into \"{description}\" "
            f"(can take a few minutes)..."
        )
        asyncio.create_task(self._run_network_issue_investigation(finding_id, description))

    async def _run_network_issue_investigation(self, finding_id: int, description: str) -> None:
        recent_roams = self.store.get_recent_roams(since_hours=24)

        ok, output = await asyncio.to_thread(
            investigate.trigger_network_issue_investigation,
            self.config.mgmt_host, self.config.mgmt_ssh_user,
            description=description,
            recent_roams=recent_roams,
            omada_config_file=self.config.omada_config_file,
            fortigate_api_host=self.config.fortigate_api_host,
            fortigate_token_file=self.config.fortigate_token_file,
            hosts=self._build_fleet_hosts(),
            identity_file=self.config.ssh_identity_file,
        )
        if not ok:
            await self._notify(f"Finding #{finding_id}: investigation failed to run -- {output.strip()}")
            return
        self.store.set_investigation_report(finding_id, output.strip())
        self.store.set_finding_status(finding_id, "resolved")
        await self._notify(f"Finding #{finding_id} investigation report:\n{output.strip()}")

    async def handle_investigate_cluster(self, description: str) -> None:
        if not self.config.mgmt_host:
            await self._notify("!investigate-cluster isn't configured (no mgmt host set).")
            return

        subject = f"ondemand-{int(time.time())}"
        detail_desc = description or "standard cluster resource/rebalancing review"
        finding_id = self.store.create_finding(
            "on_demand", subject, "info", f"On-demand investigation: {detail_desc}",
            {"description": detail_desc},
        )
        self.store.set_finding_status(finding_id, "investigating")
        await self._notify(
            f"Finding #{finding_id}: starting a read-only cluster resource review "
            f"(can take a few minutes)..."
        )
        asyncio.create_task(self._run_cluster_investigation(finding_id, description))

    async def _run_cluster_investigation(self, finding_id: int, description: str) -> None:
        nodes = await asyncio.to_thread(self.proxmox.list_nodes)
        node_resources = []
        for node in nodes:
            try:
                status = await asyncio.to_thread(self.proxmox.node_status, node)
            except Exception as exc:
                node_resources.append({"node": node, "error": str(exc)})
                continue
            mem = status.get("memory", {})
            node_resources.append({
                "node": node,
                "cpu_fraction": status.get("cpu"),
                "memory": mem,
                "loadavg": status.get("loadavg"),
                "uptime": status.get("uptime"),
            })
        vm_resources = await asyncio.to_thread(self.proxmox.cluster_vm_resources)

        ok, output = await asyncio.to_thread(
            investigate.trigger_cluster_investigation,
            self.config.mgmt_host, self.config.mgmt_ssh_user,
            description=description,
            node_resources=node_resources,
            vm_resources=vm_resources,
            hosts=self._build_fleet_hosts(),
            identity_file=self.config.ssh_identity_file,
        )
        if not ok:
            await self._notify(f"Finding #{finding_id}: investigation failed to run -- {output.strip()}")
            return
        self.store.set_investigation_report(finding_id, output.strip())
        self.store.set_finding_status(finding_id, "resolved")
        await self._notify(f"Finding #{finding_id} investigation report:\n{output.strip()}")

    async def handle_security_scan(self) -> None:
        if not self.config.mgmt_host:
            await self._notify("!security-scan isn't configured (no mgmt host set).")
            return

        hosts = self._build_fleet_hosts()
        await self._notify(
            f"Starting a read-only security sweep across {len(hosts)} hosts "
            f"(ports, failed-auth patterns, CVE staleness via Trivy) -- can take a while..."
        )
        asyncio.create_task(self._run_security_scan(hosts))

    def _build_fleet_hosts(self) -> list[dict]:
        hosts = [
            {"name": name, "ssh_host": s.ssh_host, "ssh_user": s.ssh_user, "compose_dir": s.compose_dir}
            for name, s in self.config.services.items()
        ]
        if self.config.monitoring_host:
            hosts.append({
                "name": "rbd-monitor", "ssh_host": self.config.monitoring_host,
                "ssh_user": self.config.monitoring_ssh_user,
            })
        if self.config.self_ssh_host:
            hosts.append({
                "name": "rbd-update-bot", "ssh_host": self.config.self_ssh_host,
                "ssh_user": self.config.self_ssh_user,
            })
        hosts.extend(self.config.security_scan_extra_hosts)
        return hosts

    async def _run_security_scan(self, hosts: list[dict]) -> None:
        ok, output = await asyncio.to_thread(
            security_scan.trigger_security_scan,
            self.config.mgmt_host, self.config.mgmt_ssh_user,
            hosts=hosts,
            fortigate_api_host=self.config.fortigate_api_host,
            fortigate_token_file=self.config.fortigate_token_file,
            omada_config_file=self.config.omada_config_file,
            identity_file=self.config.ssh_identity_file,
        )
        if not ok:
            await self._notify(f"Security scan failed to run -- {output.strip()}")
            return
        report = output.strip()

        try:
            parsed = await asyncio.to_thread(
                security_findings.extract_findings,
                client=self.anthropic_client, model=self.config.llm_model, report_text=report,
                host_names=[h["name"] for h in hosts],
            )
        except Exception:
            logger.exception("security scan finding extraction failed")
            await self._notify(f"Security scan report (couldn't diff this run -- extraction failed):\n{report}")
            return

        findings = [
            {"host": f.host, "finding_type": f.finding_type, "identifier": f.identifier,
             "severity": f.severity, "has_fix": f.has_fix, "detail": f.detail}
            for f in parsed
        ]
        new_or_regressed, newly_resolved = self.store.record_security_scan_findings(findings)

        created: list[tuple[int, dict, str]] = []
        for f in new_or_regressed:
            subject = f"{f['host']}:{f['finding_type']}:{f['identifier']}"
            kind = "CVE" if f["finding_type"] == "cve" else "open port"
            summary = f"New {kind} on {f['host']}: {f['identifier']} -- {f['detail']}"
            self.store.resolve_finding_by_subject("security_scan", subject)
            finding_id = self.store.create_finding("security_scan", subject, f["severity"], summary, f)
            if f["finding_type"] == "cve":
                self.store.set_finding_status(finding_id, "deferred")
            created.append((finding_id, f, summary))

        for f in newly_resolved:
            subject = f"{f['host']}:{f['finding_type']}:{f['identifier']}"
            self.store.resolve_finding_by_subject("security_scan", subject)

        all_critical = [
            (fid, f, summary) for fid, f, summary in created
            if f["severity"] == "critical" and f["finding_type"] == "open_port"
        ]
        _MAX_CONCURRENT_SECURITY_INVESTIGATIONS = 8
        critical = all_critical[:_MAX_CONCURRENT_SECURITY_INVESTIGATIONS]
        capped = all_critical[_MAX_CONCURRENT_SECURITY_INVESTIGATIONS:]
        report_by_id: dict[int, tuple[bool, str]] = {}
        if critical:
            for fid, _f, _summary in critical:
                self.store.set_finding_status(fid, "investigating")
            results = await asyncio.gather(*(
                self._run_finding_investigation(fid, self.store.get_finding(fid), notify=False)
                for fid, _f, _summary in critical
            ))
            report_by_id = {fid: result for (fid, _f, _summary), result in zip(critical, results)}
        capped_ids = {fid for fid, _f, _summary in capped}

        lines = [
            f"Security scan complete: {len(new_or_regressed)} new finding(s), "
            f"{len(newly_resolved)} resolved."
        ]
        if capped:
            lines.append(
                f"({len(capped)} critical finding(s) past the {_MAX_CONCURRENT_SECURITY_INVESTIGATIONS}/run "
                f"investigation cap -- recorded below, not auto-investigated; `!investigate-finding <id>` "
                f"for any of them by hand.)"
            )
        for fid, f, summary in created:
            deferred_note = " -- deferred, won't resurface unless it escalates or clears" \
                if f["finding_type"] == "cve" else ""
            if fid in report_by_id:
                ok, output = report_by_id[fid]
                body = output.strip() if ok else f"investigation failed to run -- {output.strip()}"
                lines.append(f"\n--- Finding #{fid} (critical) -- {summary}{deferred_note} ---\n{body}")
            elif fid in capped_ids:
                lines.append(f"- Finding #{fid} (critical, not auto-investigated){deferred_note}: {summary}")
            else:
                lines.append(f"- Finding #{fid} ({f['severity']}){deferred_note}: {summary}")
        if not created:
            lines.append("Nothing new.")
        await self._notify("\n".join(lines))

    async def _sleep_until_due(self, loop_name: str, interval_seconds: float) -> None:
        meta_key = f"loop_last_fire_{loop_name}"
        last_fire_raw = self.store.get_meta(meta_key)
        now = datetime.now(timezone.utc)
        remaining = interval_seconds
        if last_fire_raw:
            try:
                last_fire = datetime.fromisoformat(last_fire_raw)
                remaining = max(0.0, interval_seconds - (now - last_fire).total_seconds())
            except ValueError:
                pass
        if remaining > 0:
            await asyncio.sleep(remaining)
        self.store.set_meta(meta_key, datetime.now(timezone.utc).isoformat())

    async def run_security_scan_loop(self, interval_seconds: float) -> None:
        while True:
            await self._sleep_until_due("security_scan", interval_seconds)
            await self.handle_security_scan()

    async def run_network_monitor_loop(self, interval_seconds: float) -> None:
        while True:
            await self._sleep_until_due("network_monitor", interval_seconds)
            ok, devices, errors = await asyncio.to_thread(
                network_monitor.trigger_network_collect,
                self.config.mgmt_host, self.config.mgmt_ssh_user,
                omada_config_file=self.config.omada_config_file,
                fortigate_api_host=self.config.fortigate_api_host,
                fortigate_token_file=self.config.fortigate_token_file,
                identity_file=self.config.ssh_identity_file,
            )
            if not ok:
                logger.warning("network monitor collection failed: %s", errors)
                continue
            if errors:
                logger.warning("network monitor collector errors: %s", errors)

            roams = self.store.detect_ap_roams(devices)
            for roam in roams:
                self.store.record_ap_roam(roam["mac"], roam["from_ap"], roam["to_ap"])
                count = self.store.count_recent_roams(roam["mac"], since_hours=1)
                flap_check = {
                    "check_id": f"ap_flap:{roam['mac']}", "source": "ap_flapping",
                    "status": f"{count} roams/hr",
                    "detail": f"{roam['from_ap']} -> {roam['to_ap']} ({count} roams in the last hour)",
                    "is_bad": count >= 3,
                }
                for ev in self.store.record_ops_health([flap_check]):
                    if ev["event"] == "alert":
                        self._create_finding(
                            "ap_flapping", roam["mac"], "warning",
                            f"AP flapping: {roam['mac']} ({count} roams/hr)", ev,
                            notify_message=(
                                f"AP flapping detected:\n"
                                f"  MAC:    {roam['mac']}\n"
                                f"  Recent: {roam['from_ap']} -> {roam['to_ap']}\n"
                                f"  Roams:  {count} in the last hour"
                            ),
                        )
                    else:
                        self.store.resolve_finding_by_subject("ap_flapping", roam["mac"])

            new_devices = self.store.record_device_sightings(devices)
            for dev in new_devices:
                self._create_finding(
                    "network_monitor", dev.get("mac"), "info",
                    f"New device detected ({dev.get('source', 'unknown')}): {dev.get('mac')}",
                    dev,
                    notify_message=(
                        f"New device detected ({dev.get('source', 'unknown')}):\n"
                        f"  MAC:      {dev.get('mac')}\n"
                        f"  Vendor:   {dev.get('vendor') or 'Unknown'}\n"
                        f"  IP:       {dev.get('ip') or '(none)'}\n"
                        f"  VLAN:     {dev.get('vlan') or '(unknown)'}\n"
                        f"  Port:     {dev.get('port') or '(unknown)'}\n"
                        f"  Hostname: {dev.get('hostname') or '(none)'}\n"
                        f"To label/confirm this device: `!trust-device {dev.get('mac')} <name>`"
                    ),
                )

            if self.config.wireguard_ssh_host:
                ok, peers, wg_errors = await asyncio.to_thread(
                    network_monitor.trigger_wg_collect,
                    self.config.mgmt_host, self.config.mgmt_ssh_user,
                    wg_ssh_host=self.config.wireguard_ssh_host,
                    wg_ssh_user=self.config.wireguard_ssh_user,
                    identity_file=self.config.ssh_identity_file,
                )
                if not ok:
                    logger.warning("wireguard peer collection failed: %s", wg_errors)
                elif wg_errors:
                    logger.warning("wireguard collector errors: %s", wg_errors)

                if ok and peers:
                    new_peers, connected_peers = self.store.record_wg_peer_sightings(peers)
                    for peer in new_peers:
                        pubkey = peer.get("pubkey")
                        finding_id, trailer = self._create_finding(
                            "wireguard", pubkey, "warning",
                            f"New WireGuard peer: {pubkey}", peer,
                        )
                        await self._notify(
                            f"New WireGuard peer (never seen before):\n"
                            f"  Public key:  {pubkey}\n"
                            f"  Allowed IPs: {peer.get('allowed_ips') or '(unknown)'}\n"
                            f"  Endpoint:    {peer.get('endpoint') or '(none yet)'}\n"
                            f"To label/confirm this peer: `!trust-peer {pubkey} <name>`\n"
                            f"{trailer}"
                        )
                    for peer in connected_peers:
                        pubkey = peer.get("pubkey")
                        if any(p.get("pubkey") == pubkey for p in new_peers):
                            continue
                        label = self.store.get_wg_peer_label(pubkey)
                        await self._notify(
                            f"WireGuard peer connected: {label or pubkey}\n"
                            f"  Endpoint: {peer.get('endpoint') or '(unknown)'}"
                        )

    async def run_wifi_rf_monitor_loop(self, interval_seconds: float) -> None:
        while True:
            await self._sleep_until_due("wifi_rf", interval_seconds)
            ok, data, errors = await asyncio.to_thread(
                network_monitor.trigger_wifi_rf_collect,
                self.config.mgmt_host, self.config.mgmt_ssh_user,
                omada_config_file=self.config.omada_config_file,
                watched_macs=self.config.wifi_rf.watched_macs,
                identity_file=self.config.ssh_identity_file,
            )
            if not ok:
                logger.warning("wifi_rf collection failed: %s", errors)
                continue
            if errors:
                logger.warning("wifi_rf collector errors: %s", errors)

            radios = data.get("radios", [])
            if not radios:
                continue

            open_drift = self.store.open_finding_subjects("wifi_rf_drift")
            for radio in radios:
                cfg = radio.get("config") or {}
                live_channel = str(radio.get("actualChannel", ""))
                cfg_channel = cfg.get("channel")
                cfg_freq = cfg.get("freq")
                live_mhz = re.search(r"(\d{4})\s*MHz", live_channel)
                drifted = bool(cfg_freq and live_mhz and int(live_mhz.group(1)) != int(cfg_freq))
                subject = f"{radio.get('_ap_mac')}:{radio.get('_band')}"
                if drifted and subject in open_drift:
                    continue
                if drifted:
                    self._create_finding(
                        "wifi_rf_drift", subject, "info",
                        f"Channel drift on {radio.get('_ap_name')} {radio.get('_band')}: "
                        f"configured {cfg_freq}MHz, live {live_channel}",
                        {"configured_channel_index": cfg_channel, "configured_freq": cfg_freq,
                         "live_channel": live_channel},
                        notify_message=(
                            f"WiFi channel drift on {radio.get('_ap_name')} ({radio.get('_band')}):\n"
                            f"  Configured: {cfg_freq}MHz\n"
                            f"  Live:       {live_channel}\n"
                            f"Likely auto-channel/DFS, not a config change."
                        ),
                    )
                else:
                    self.store.resolve_finding_by_subject("wifi_rf_drift", subject)

            enriched = await asyncio.to_thread(self.store.record_wifi_rf_samples, radios)

            crowding_rows = _compute_wifi_rf_crowding(
                data.get("neighbors", []), self.config.wifi_rf.own_ssid_prefix,
            )
            if crowding_rows:
                await asyncio.to_thread(self.store.record_wifi_rf_channel_crowding, crowding_rows)

            checks = []
            for radio in enriched:
                ap_mac, band = radio.get("_ap_mac"), radio.get("_band")
                ap_name = radio.get("_ap_name")
                for field_name, threshold, label, min_pkts in (
                    ("inter_util", self.config.wifi_rf.inter_util_threshold, "interference", 0),
                    ("busy_util", self.config.wifi_rf.busy_util_threshold, "busy airtime", 0),
                    ("retry_rate", self.config.wifi_rf.retry_rate_threshold, "retry rate",
                     self.config.wifi_rf.retry_min_rx_pkts),
                ):
                    is_bad = await asyncio.to_thread(
                        self.store.recent_wifi_rf_bad_streak, ap_mac, band,
                        field=field_name, threshold=threshold,
                        samples=self.config.wifi_rf.sustained_samples, min_rx_pkts=min_pkts,
                    )
                    checks.append({
                        "check_id": f"wifi_rf:{field_name}:{ap_mac}:{band}",
                        "source": "wifi_rf", "status": f"{label} sustained high" if is_bad else "ok",
                        "detail": f"{ap_name} {band} {label}: {radio.get(field_name)}",
                        "is_bad": is_bad,
                    })
            for ev in self.store.record_ops_health(checks):
                subject = ev["check_id"].split(":", 1)[1]
                if ev["event"] == "alert":
                    self._create_finding(
                        "wifi_rf", subject, "warning", ev["detail"], ev,
                        notify_message=f"WiFi RF sustained issue: {ev['detail']}",
                    )
                else:
                    self.store.resolve_finding_by_subject("wifi_rf", subject)

            for client in data.get("watched_clients", []):
                mac = (client.get("mac") or "").lower().replace("-", ":")
                rssi = client.get("rssi")
                uptime = client.get("uptime")
                rssi_check = {
                    "check_id": f"wifi_rf_client_rssi:{mac}", "source": "wifi_rf_client",
                    "status": f"rssi {rssi}",
                    "detail": f"{mac} RSSI {rssi} dBm (threshold {self.config.wifi_rf.watched_rssi_threshold})",
                    "is_bad": rssi is not None and rssi <= self.config.wifi_rf.watched_rssi_threshold,
                }
                for ev in self.store.record_ops_health([rssi_check]):
                    if ev["event"] == "alert":
                        self._create_finding(
                            "wifi_rf_client", mac, "warning", ev["detail"], ev,
                            notify_message=f"Watched WiFi client weak signal: {ev['detail']}",
                        )
                    else:
                        self.store.resolve_finding_by_subject("wifi_rf_client", mac)

                if uptime is not None:
                    meta_key = f"wifi_rf_watched_last_uptime:{mac}"
                    last_uptime_raw = self.store.get_meta(meta_key)
                    if last_uptime_raw is not None:
                        try:
                            if uptime < float(last_uptime_raw):
                                await self._notify(
                                    f"Watched WiFi client reconnected: {mac} "
                                    f"(association uptime reset, was {last_uptime_raw}s)"
                                )
                        except ValueError:
                            pass
                    self.store.set_meta(meta_key, str(uptime))

    async def handle_llm_usage(self, days: int) -> None:
        days = max(1, min(days, 400))
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        rows = await asyncio.to_thread(self.store.llm_usage_summary, since)
        if not rows:
            await self._notify(f"No API usage recorded in the last {days} day(s) (logging started 2026-11-24).")
            return
        total = sum(r["cost_usd"] or 0 for r in rows)
        lines = [f"API usage, last {days} day(s): ~${total:.2f} across {sum(r['calls'] for r in rows)} calls"]
        for r in rows:
            share = (r["cost_usd"] or 0) / total * 100 if total else 0
            extra = f", {r['web_searches']} searches" if r["web_searches"] else ""
            lines.append(
                f"  ${r['cost_usd'] or 0:.2f} ({share:.0f}%)  {r['feature']} -- {r['calls']} calls, "
                f"{(r['input_tokens'] or 0) / 1000:.0f}k in / {(r['output_tokens'] or 0) / 1000:.0f}k out{extra}"
            )
        await self._notify("\n".join(lines))

    async def handle_wifi_channels(self) -> None:
        radio_state = await asyncio.to_thread(self.store.latest_wifi_rf_radio_state)
        if not radio_state:
            await self._notify("No WiFi RF data yet (monitor just started, or disabled).")
            return
        crowding = await asyncio.to_thread(self.store.latest_wifi_rf_channel_crowding)
        if not crowding:
            await self._notify(
                "WiFi RF radio data exists, but no channel-crowding data yet "
                "(next poll within 15 minutes)."
            )
            return

        by_band: dict[str, list[dict]] = {}
        for row in crowding:
            by_band.setdefault(row["band"], []).append(row)
        crowding_by_key = {(row["band"], row["channel"]): row for row in crowding}

        lines = [f"WiFi channel crowding (as of {crowding[0]['ts']}):"]
        for radio in sorted(radio_state, key=lambda r: (r["ap_name"] or "", r["band"])):
            band_label = "2.4GHz" if radio["band"] == "2g" else "5GHz"
            channel_match = re.match(r"\s*(\d+)", radio["channel"] or "")
            if channel_match is None:
                continue
            current_channel = int(channel_match.group(1))
            current = crowding_by_key.get((radio["band"], current_channel))
            current_count = current["neighbor_count"] if current else 0
            current_signal = current["strongest_signal"] if current else None

            band_rows = by_band.get(radio["band"], [])
            if current is None:
                band_rows = band_rows + [{
                    "band": radio["band"], "channel": current_channel,
                    "neighbor_count": 0, "strongest_signal": None,
                }]
            quietest = min(
                band_rows, key=lambda r: (r["neighbor_count"], r["strongest_signal"] or -100),
                default=None,
            )

            current_desc = (
                f"{current_count} neighbor(s)"
                + (f", strongest {current_signal}dBm" if current_signal is not None else "")
            )
            if quietest is None or quietest["channel"] == current_channel:
                lines.append(
                    f"{radio['ap_name']} {band_label}: ch{current_channel} ({current_desc}) "
                    f"-- already the quietest channel Omada's scan saw in this band."
                )
            else:
                quietest_signal = quietest["strongest_signal"]
                quietest_desc = (
                    f"{quietest['neighbor_count']} neighbor(s)"
                    + (f", strongest {quietest_signal}dBm" if quietest_signal is not None else "")
                )
                lines.append(
                    f"{radio['ap_name']} {band_label}: ch{current_channel} ({current_desc}). "
                    f"Quietest in-band: ch{quietest['channel']} ({quietest_desc}). "
                    f"Consider switching if interference/busy-airtime keeps alerting."
                )
        await self._notify("\n".join(lines))

    async def run_disk_health_loop(self, interval_seconds: float) -> None:
        while True:
            await self._sleep_until_due("disk_health", interval_seconds)
            checks, errors = await asyncio.to_thread(
                disk_health.collect_proxmox_pbs, self.proxmox, self.pbs,
            )
            if self.config.synology_config_file:
                ok, syn_disks, syn_errors = await asyncio.to_thread(
                    disk_health.trigger_synology_collect,
                    self.config.mgmt_host, self.config.mgmt_ssh_user,
                    synology_config_file=self.config.synology_config_file,
                    identity_file=self.config.ssh_identity_file,
                )
                if ok:
                    checks.extend(syn_disks)
                errors.extend(syn_errors)
            if errors:
                logger.warning("disk health collector errors: %s", errors)
            if not checks:
                continue

            events = self.store.record_disk_health(checks)
            for ev in events:
                if ev["event"] == "alert":
                    wearout = ev.get("wearout")
                    wearout_line = (f"{wearout}% life remaining ({100 - int(wearout)}% used)"
                                    if isinstance(wearout, (int, float)) else "(n/a)")
                    health = (ev.get("health") or "").strip().lower()
                    severity = (
                        "critical" if (health not in _GOOD_HEALTH_DISPLAY_VALUES or ev.get("smart_bad"))
                        else "warning"
                    )
                    summary = f"Disk health alert ({ev.get('source', 'unknown')}): {ev.get('disk_id')}"
                    smart_line = ""
                    if ev.get("smart_bad"):
                        critical_warning = ev.get("critical_warning") or 0
                        smart_line = (
                            f"  SMART:   Critical Warning=0x{critical_warning:02x}, "
                            f"Media errors={ev.get('media_errors')}, "
                            f"Available spare={ev.get('available_spare')}% "
                            f"(threshold {ev.get('available_spare_threshold')}%)\n"
                        )
                    self._create_finding(
                        "disk_health", ev.get("disk_id"), severity, summary, ev,
                        notify_message=(
                            f"Disk health alert ({ev.get('source', 'unknown')}):\n"
                            f"  Disk:    {ev.get('disk_id')}\n"
                            f"  Model:   {ev.get('model') or '(unknown)'}\n"
                            f"  Health:  {ev.get('health') or '(unknown)'}\n"
                            f"  Life:    {wearout_line}\n"
                            f"{smart_line}"
                        ),
                    )
                else:
                    self.store.resolve_finding_by_subject("disk_health", ev.get("disk_id"))

    async def run_ops_health_loop(self, interval_seconds: float) -> None:
        while True:
            await self._sleep_until_due("ops_health", interval_seconds)
            checks: list[dict] = []
            errors: list[str] = []

            backup_checks, backup_errors = await asyncio.to_thread(
                ops_health.collect_backup_status, self.proxmox, self.pbs,
            )
            checks.extend(backup_checks)
            errors.extend(backup_errors)

            if self.config.synology_config_file:
                ok, syn_backup_checks, syn_backup_errors = await asyncio.to_thread(
                    ops_health.trigger_synology_backup_collect,
                    self.config.mgmt_host, self.config.mgmt_ssh_user,
                    synology_config_file=self.config.synology_config_file,
                    identity_file=self.config.ssh_identity_file,
                )
                if ok:
                    checks.extend(syn_backup_checks)
                errors.extend(syn_backup_errors)

            space_checks, space_errors = await asyncio.to_thread(
                ops_health.collect_node_resources, self.proxmox, self.pbs,
                datastore=self.config.pbs_datastore,
            )
            checks.extend(space_checks)
            errors.extend(space_errors)

            try:
                trend_nodes = await asyncio.to_thread(self.proxmox.list_nodes)
            except Exception as exc:
                trend_nodes = []
                errors.append(f"capacity-trend: couldn't list cluster nodes: {exc}")
            if trend_nodes:
                trend_checks, trend_errors = await asyncio.to_thread(
                    ops_health.collect_capacity_trend, self.proxmox, trend_nodes,
                )
                checks.extend(trend_checks)
                errors.extend(trend_errors)

            if self.config.tls_check_hostnames:
                cert_checks, cert_errors = await asyncio.to_thread(
                    ops_health.collect_cert_expiry, self.config.tls_check_hostnames,
                )
                checks.extend(cert_checks)
                errors.extend(cert_errors)

            guest_checks, guest_errors = await asyncio.to_thread(
                ops_health.collect_guest_resources, self.config.services,
                identity_file=self.config.ssh_identity_file,
                mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
            )
            checks.extend(guest_checks)
            errors.extend(guest_errors)

            local_checks, local_errors = await asyncio.to_thread(ops_health.collect_local_disk)
            checks.extend(local_checks)
            errors.extend(local_errors)

            db_container_checks, db_container_errors = await asyncio.to_thread(
                ops_health.collect_db_container_health, self.config.services,
                identity_file=self.config.ssh_identity_file,
                mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
            )
            checks.extend(db_container_checks)
            errors.extend(db_container_errors)

            gate_checks, gate_errors = await asyncio.to_thread(
                ops_health.collect_auth_gates, self.config.services,
                identity_file=self.config.ssh_identity_file,
                mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
            )
            checks.extend(gate_checks)
            errors.extend(gate_errors)

            if errors:
                logger.warning("ops health collector errors: %s", errors)
            if not checks:
                continue

            events = self.store.record_ops_health(checks)
            for ev in events:
                if ev["event"] == "alert":
                    severity = (
                        "critical" if ev.get("source") in ("backup_status", "disk_space", "guest_incident", "auth_gate")
                        else "warning"
                    )
                    summary = f"Ops health alert ({ev.get('source')}): {ev.get('check_id')} -- {ev.get('status')}"
                    self._create_finding(
                        "ops_health", ev.get("check_id"), severity, summary, ev,
                        notify_message=(
                            f"Ops health alert ({ev.get('source')}):\n"
                            f"  Check:  {ev.get('check_id')}\n"
                            f"  Status: {ev.get('status')}\n"
                            f"  Detail: {ev.get('detail')}"
                        ),
                    )
                else:
                    self.store.resolve_finding_by_subject("ops_health", ev.get("check_id"))

    async def run_mgmt1_patch_loop(self, interval_seconds: float) -> None:
        while True:
            await self._sleep_until_due("mgmt1_patch", interval_seconds)
            status = await asyncio.to_thread(
                mgmt1_patch.trigger_collect, self.config.mgmt_host, self.config.mgmt_ssh_user,
                identity_file=self.config.ssh_identity_file,
            )
            if status is None:
                logger.warning("mgmt1 patch collect failed")
                continue

            if status.get("upgradable_count", 0) > 0:
                ok, detail = await asyncio.to_thread(
                    mgmt1_patch.trigger_apply, self.config.mgmt_host, self.config.mgmt_ssh_user,
                    identity_file=self.config.ssh_identity_file,
                )
                if not ok:
                    logger.warning("mgmt1 patch apply failed: %s", detail)
                else:
                    await self._notify(f"mgmt1: applied {status['upgradable_count']} package update(s).")
                    status = await asyncio.to_thread(
                        mgmt1_patch.trigger_collect, self.config.mgmt_host, self.config.mgmt_ssh_user,
                        identity_file=self.config.ssh_identity_file,
                    ) or status

            check = mgmt1_patch.build_reboot_check(status)
            events = self.store.record_ops_health([check])
            for ev in events:
                if ev["event"] == "alert":
                    self._create_finding(
                        "mgmt1_patch", ev.get("check_id"), "critical",
                        f"mgmt1 needs a reboot ({ev.get('detail')}) -- this is the host every write-capable "
                        f"credential and !investigate* feature in this project depends on. Reboot it yourself "
                        f"when you're not mid-session; this bot will never do it automatically.",
                        ev, notify_message=(
                            f"mgmt1 reboot required: {ev.get('detail')}\n"
                            f"This is the credential-holding host -- reboot it yourself when convenient, "
                            f"not something this bot will ever trigger."
                        ),
                    )
                else:
                    self.store.resolve_finding_by_subject("mgmt1_patch", ev.get("check_id"))

    async def run_firewall_traffic_loop(self, interval_seconds: float) -> None:
        while True:
            await self._sleep_until_due("firewall_traffic", interval_seconds)

            ok, data, errors = await asyncio.to_thread(
                firewall_traffic.trigger_firewall_traffic_collect,
                self.config.mgmt_host, self.config.mgmt_ssh_user,
                fortigate_api_host=self.config.fortigate_api_host,
                fortigate_token_file=self.config.fortigate_token_file,
                identity_file=self.config.ssh_identity_file,
            )
            if not ok:
                logger.warning("firewall traffic collection failed: %s", errors)
                continue
            if errors:
                logger.warning("firewall traffic collector errors: %s", errors)

            checks = firewall_traffic.build_checks(data, self.store)
            if not checks:
                continue

            events = self.store.record_ops_health(checks)
            for ev in events:
                if ev["event"] == "alert":
                    severity = "critical" if ev.get("check_id", "").startswith("fw_exposure_geo") else "warning"
                    summary = f"Firewall traffic alert: {ev.get('check_id')} -- {ev.get('status')}"
                    finding_id, trailer = self._create_finding(
                        "firewall_traffic", ev.get("check_id"), severity, summary, ev,
                    )
                    await self._notify(
                        f"Firewall traffic alert:\n"
                        f"  Check:  {ev.get('check_id')}\n"
                        f"  Status: {ev.get('status')}\n"
                        f"  Detail: {ev.get('detail')}\n"
                        f"{trailer}"
                    )
                else:
                    self.store.resolve_finding_by_subject("firewall_traffic", ev.get("check_id"))
                    await self._notify(
                        f"Firewall traffic recovered: {ev.get('detail')}."
                    )

    async def run_fortios_advisory_check_loop(self, interval_seconds: float) -> None:
        while True:
            await self._sleep_until_due("fortios_advisory", interval_seconds)
            if not self.config.fortigate_api_host:
                continue

            status, err = await asyncio.to_thread(
                fortigate_blocklist.trigger_get_status,
                self.config.mgmt_host, self.config.mgmt_ssh_user,
                fortigate_api_host=self.config.fortigate_api_host,
                fortigate_token_file=self.config.fortigate_token_file,
                identity_file=self.config.ssh_identity_file,
            )
            if status is None or err or not status.get("version"):
                logger.warning("fortios_advisory: couldn't read current version: %s", err or status)
                continue

            current_version = status["version"]
            serial = status.get("serial") or "unknown"
            model_name = status.get("model") or status.get("hostname") or "FortiGate"

            psirt_ids = await asyncio.to_thread(fortios_advisory.fetch_fortios_psirt_ids)
            cache_key = f"fortios_advisory_research:{serial}"
            cached = None
            if raw_cached := self.store.get_meta(cache_key):
                try:
                    cached = json.loads(raw_cached)
                except ValueError:
                    cached = None
            reason = fortios_advisory.research_reason(
                cached, now_ts=time.time(),
                max_age_hours=self.config.fortios_advisory_research_max_age_hours,
                current_version=current_version, psirt_ids=psirt_ids,
            )
            fields = fortios_advisory.FortiOSAdvisory.__dataclass_fields__
            if reason is None:
                advisory = fortios_advisory.FortiOSAdvisory(**{f: cached[f] for f in fields})
                logger.info("fortios_advisory: %s reusing cached research (%d FortiOS PSIRT ids known)",
                            current_version, len(cached.get("psirt_ids") or []))
            else:
                logger.info("fortios_advisory: %s researching (%s)", current_version, reason)
                try:
                    advisory = await asyncio.to_thread(
                        fortios_advisory.check_fortios_advisory,
                        client=self.anthropic_client, model=self.config.llm_model,
                        current_version=current_version, model_name=model_name,
                    )
                except Exception:
                    logger.exception("fortios_advisory: research call failed")
                    continue
                known = set((cached or {}).get("psirt_ids") or []) | (psirt_ids or set())
                self.store.set_meta(cache_key, json.dumps({
                    **{f: getattr(advisory, f) for f in fields},
                    "version": current_version, "researched_at": time.time(),
                    "psirt_ids": sorted(known),
                }))

            check_id = f"fortios_advisory:{serial}"
            checks = [{
                "check_id": check_id, "source": "fortios_advisory",
                "status": f"{current_version} -- advisory: {advisory.has_advisory}",
                "detail": advisory.summary,
                "is_bad": advisory.has_advisory,
            }]
            events = self.store.record_ops_health(checks)
            for ev in events:
                if ev["event"] == "alert":
                    backup_note = ""
                    raw_config, backup_err = await asyncio.to_thread(
                        fortigate_blocklist.trigger_config_backup,
                        self.config.mgmt_host, self.config.mgmt_ssh_user,
                        fortigate_api_host=self.config.fortigate_api_host,
                        fortigate_token_file=self.config.fortigate_token_file,
                        identity_file=self.config.ssh_identity_file,
                    )
                    if raw_config:
                        backup_path = fortigate_blocklist.save_config_backup(raw_config, serial=serial)
                        backup_note = f"Config backed up to {backup_path}."
                    else:
                        backup_note = f"Config backup FAILED ({backup_err}) -- back it up manually before restoring."

                    finding_id, trailer = self._create_finding(
                        "fortios_advisory", check_id, advisory.severity,
                        f"FortiOS advisory: {model_name} running {current_version}, "
                        f"fix is {advisory.fixed_version or 'unknown'} -- {advisory.summary}", ev,
                    )
                    await self._notify(
                        f"FortiOS security advisory for {model_name} (running {current_version}):\n"
                        f"{advisory.summary}\n"
                        f"Fixed version: {advisory.fixed_version or 'unknown'}\n"
                        f"Source: {advisory.source_url or '(no official source found)'}\n"
                        f"{backup_note}\n"
                        f"The TFTP restore itself is still a manual step.\n{trailer}"
                    )
                else:
                    self.store.resolve_finding_by_subject("fortios_advisory", check_id)
                    await self._notify(
                        f"FortiOS advisory cleared for {model_name} -- now running {current_version}."
                    )

    @staticmethod
    def _kernel_fix_available_in_packages(packages: str, fixed_version: str) -> bool:
        fixed_tuple = Orchestrator._version_tuple(fixed_version)
        if fixed_tuple is None:
            return False
        for line in packages.splitlines():
            if "linux-image" not in line:
                continue
            fields = line.split()
            if len(fields) < 2:
                continue
            candidate = Orchestrator._version_tuple(fields[1])
            if candidate is not None and candidate[:len(fixed_tuple)] >= fixed_tuple:
                return True
        return False

    @staticmethod
    def _version_tuple(text: str) -> tuple[int, ...] | None:
        match = re.search(r"\d+(?:[.-]\d+)+", text)
        if not match:
            return None
        return tuple(int(part) for part in re.split(r"[.-]", match.group()))

    async def run_kernel_cve_watch_loop(self, interval_seconds: float) -> None:
        while True:
            await self._sleep_until_due("kernel_cve_watch", interval_seconds)

            groups: dict[tuple[str, str], list[str]] = {}
            installed_versions: dict[tuple[str, str], str] = {}
            for service_name, service in self.config.services.items():
                info = await asyncio.to_thread(
                    executor.kernel_version_info, service,
                    identity_file=self.config.ssh_identity_file,
                    mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
                )
                if info is None:
                    continue
                distro, kernel_version, installed_pkg_version = info
                key = (distro, kernel_version)
                groups.setdefault(key, []).append(service_name)
                if installed_pkg_version and key not in installed_versions:
                    installed_versions[key] = installed_pkg_version

            current_check_ids = {f"kernel_cve:{distro}:{kv}" for distro, kv in groups}

            for subject in self.store.open_finding_subjects("kernel_cve") - current_check_ids:
                self.store.resolve_finding_by_subject("kernel_cve", subject)
                await self._notify(f"Kernel CVE cleared: no host still runs the affected kernel ({subject}).")

            notices_by_codename: dict[str, list[dict] | None] = {}
            for (distro, kernel_version), hosts in groups.items():
                check_id = f"kernel_cve:{distro}:{kernel_version}"
                latest_usn = None
                src = kernel_cve_watch.ubuntu_source_package(
                    distro, kernel_version, installed_versions.get((distro, kernel_version), ""),
                )
                if src is not None:
                    package, codename = src
                    if codename not in notices_by_codename:
                        notices_by_codename[codename] = await asyncio.to_thread(
                            kernel_cve_watch.fetch_kernel_notices, codename,
                        )
                    latest_usn = kernel_cve_watch.latest_usn_for(notices_by_codename[codename], package)

                cache_key = f"kernel_cve_research:{check_id}"
                cached = None
                if raw_cached := self.store.get_meta(cache_key):
                    try:
                        cached = json.loads(raw_cached)
                    except ValueError:
                        cached = None
                reason = kernel_cve_watch.research_reason(
                    cached, now_ts=time.time(),
                    max_age_hours=self.config.kernel_cve_watch.research_max_age_hours,
                    latest_usn=latest_usn,
                )
                if reason is None:
                    advisory = kernel_cve_watch.KernelCVEAdvisory(**{
                        f: cached[f] for f in kernel_cve_watch.KernelCVEAdvisory.__dataclass_fields__
                    })
                    logger.info("kernel_cve_watch: %s reusing cached research (latest USN %s)",
                                check_id, latest_usn or "unknown")
                else:
                    logger.info("kernel_cve_watch: %s researching (%s)", check_id, reason)
                    try:
                        advisory = await asyncio.to_thread(
                            kernel_cve_watch.check_kernel_cve,
                            client=self.anthropic_client, model=self.config.llm_model,
                            distro=distro, kernel_version=kernel_version,
                        )
                    except Exception:
                        logger.exception("kernel_cve_watch: research call failed for %s %s", distro, kernel_version)
                        continue
                raw_advisory = advisory

                tracker = None
                if advisory.has_critical_cve and advisory.cve_id:
                    tracker = await asyncio.to_thread(
                        kernel_cve_watch.ubuntu_tracker_status, advisory.cve_id, distro,
                        kernel_version, installed_versions.get((distro, kernel_version), ""),
                    )
                if tracker is not None:
                    logger.info("kernel_cve_watch: %s %s tracker row %s/%s: %s %s", check_id,
                                advisory.cve_id, tracker["package"], tracker["codename"],
                                tracker["status"], tracker["fixed_version"])
                    if tracker["status"] in ("not-affected", "DNE"):
                        advisory = kernel_cve_watch.replace(advisory, has_critical_cve=False)
                    else:
                        advisory = kernel_cve_watch.replace(
                            advisory, fixed_version=tracker["fixed_version"],
                            fix_available=tracker["status"] == "released",
                        )
                if reason is not None:
                    self.store.set_meta(cache_key, json.dumps({
                        **{f: getattr(raw_advisory, f)
                           for f in kernel_cve_watch.KernelCVEAdvisory.__dataclass_fields__},
                        "researched_at": time.time(),
                        "usn": latest_usn or (cached or {}).get("usn"),
                        "tracker_ok": tracker is not None,
                    }))

                patched_already = kernel_cve_watch.already_patched(
                    installed_versions.get((distro, kernel_version), ""), advisory.fixed_version,
                )
                effective_has_cve = advisory.has_critical_cve and not patched_already
                if patched_already:
                    logger.info(
                        "kernel_cve_watch: %s already running fixed_version %r -- suppressing alert",
                        check_id, advisory.fixed_version,
                    )
                    if check_id in self.store.open_finding_subjects("kernel_cve"):
                        self.store.resolve_finding_by_subject("kernel_cve", check_id)

                checks = [{
                    "check_id": check_id, "source": "kernel_cve",
                    "status": f"{kernel_version} -- cve: {effective_has_cve}",
                    "detail": advisory.summary,
                    "is_bad": effective_has_cve,
                }]
                events = self.store.record_ops_health(checks)
                for ev in events:
                    if ev["event"] == "alert":
                        finding_id, trailer = self._create_finding(
                            "kernel_cve", check_id, advisory.severity,
                            f"Kernel CVE on {distro} {kernel_version}: {advisory.summary}",
                            {
                                "cve_id": advisory.cve_id, "hosts": hosts,
                                "fixed_version": advisory.fixed_version, "source_url": advisory.source_url,
                            },
                        )
                        await self._notify(
                            f"\U0001f6a8 Kernel CVE: {advisory.cve_id or '(id unknown)'} affects "
                            f"{distro}, kernel {kernel_version} ({advisory.severity}):\n"
                            f"{advisory.summary}\n"
                            f"Fixed version: {advisory.fixed_version or 'not yet released'}\n"
                            f"Source: {advisory.source_url or '(no official source found)'}\n"
                            f"Affected hosts ({len(hosts)}): {', '.join(hosts)}\n"
                            f"No action taken yet -- watching for a real released fix.{trailer}"
                        )

                if not effective_has_cve or not advisory.fix_available:
                    continue
                if self.store.get_meta(f"kernel_cve_remediated:{check_id}"):
                    continue

                packages = await asyncio.to_thread(
                    executor.list_upgradable_packages, self.config.services[hosts[0]],
                    identity_file=self.config.ssh_identity_file,
                    mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
                )
                fix_confirmed = self._kernel_fix_available_in_packages(packages, advisory.fixed_version)
                if not fix_confirmed:
                    installed = await asyncio.to_thread(
                        executor.list_installed_kernel_packages, self.config.services[hosts[0]],
                        identity_file=self.config.ssh_identity_file,
                        mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
                    )
                    fix_confirmed = self._kernel_fix_available_in_packages(installed, advisory.fixed_version)
                if not fix_confirmed:
                    logger.info(
                        "kernel_cve_watch: %s not yet confirmed via apt (fixed_version=%r) on %s",
                        check_id, advisory.fixed_version, hosts[0],
                    )
                    continue

                self.store.set_meta(f"kernel_cve_remediated:{check_id}", "1")
                self.store.resolve_finding_by_subject("kernel_cve", check_id)
                finding_id, _ = self._create_finding(
                    "kernel_cve", check_id, "critical",
                    f"Kernel CVE fix available for {distro} {kernel_version} -- auto-patching {len(hosts)} host(s) now.",
                    {
                        "cve_id": advisory.cve_id, "hosts": hosts,
                        "fixed_version": advisory.fixed_version, "source_url": advisory.source_url,
                    },
                )
                await self._notify(
                    f"Kernel CVE fix confirmed available for {distro} {kernel_version} "
                    f"(target {advisory.fixed_version or 'see package list'}) -- "
                    f"patching {len(hosts)} host(s) now, one at a time: {', '.join(hosts)}"
                )
                for service_name in hosts:
                    await self._run_kernel_cve_remediation(service_name, finding_id)

    _RECLAIMED_RE = re.compile(r"^Total(?: reclaimed space)?:\s*([\d.]+)\s*([KMGT]?B)",
                               re.IGNORECASE | re.MULTILINE)
    _RECLAIMED_UNIT_MB = {"B": 1 / (1024 * 1024), "KB": 1 / 1024, "MB": 1, "GB": 1024, "TB": 1024 * 1024}

    @staticmethod
    def _parse_reclaimed_mb(output: str) -> float:
        total_mb = 0.0
        for amount, unit in Orchestrator._RECLAIMED_RE.findall(output):
            total_mb += float(amount) * Orchestrator._RECLAIMED_UNIT_MB.get(unit.upper(), 0.0)
        return total_mb

    async def run_docker_prune_loop(self, interval_seconds: float) -> None:
        while True:
            await self._sleep_until_due("docker_prune", interval_seconds)
            reclaimed_lines: list[str] = []
            for name, service in self.config.services.items():
                ok, out = await asyncio.to_thread(
                    executor.prune_docker_images, service,
                    identity_file=self.config.ssh_identity_file,
                    mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
                )
                if not ok:
                    logger.warning("docker_prune: failed on %s: %s", name, out)
                    continue
                reclaimed_mb = self._parse_reclaimed_mb(out)
                if reclaimed_mb >= self.config.docker_prune.notify_threshold_mb:
                    reclaimed_lines.append(
                        f"{name}: {reclaimed_mb / 1024:.1f}GB" if reclaimed_mb >= 1024
                        else f"{name}: {reclaimed_mb:.0f}MB"
                    )
            ok, out = await asyncio.to_thread(executor.prune_local_docker)
            if not ok:
                logger.warning("docker_prune: failed on rbd-update-bot (local): %s", out)
            else:
                reclaimed_mb = self._parse_reclaimed_mb(out)
                if reclaimed_mb >= self.config.docker_prune.notify_threshold_mb:
                    reclaimed_lines.append(
                        f"rbd-update-bot: {reclaimed_mb / 1024:.1f}GB" if reclaimed_mb >= 1024
                        else f"rbd-update-bot: {reclaimed_mb:.0f}MB"
                    )
            if reclaimed_lines:
                await self._notify(
                    "Docker image/build-cache prune reclaimed space on " + ", ".join(reclaimed_lines)
                )

    async def run_config_drift_loop(self, interval_seconds: float) -> None:
        recent_window = timedelta(seconds=interval_seconds * 1.5)
        while True:
            await self._sleep_until_due("config_drift", interval_seconds)

            immich_content = ""
            immich_service = self.config.services.get("immich")
            if immich_service and immich_service.portainer:
                try:
                    stack_id, _ = await asyncio.to_thread(
                        portainer.find_stack, immich_service.portainer, self.config.portainer_token,
                    )
                    immich_content = await asyncio.to_thread(
                        portainer.get_stack_file_content,
                        immich_service.portainer, self.config.portainer_token, stack_id,
                    )
                except Exception:
                    logger.exception("could not fetch Immich's stack content for config-drift archive")

            ok, data, errors = await asyncio.to_thread(
                config_drift.trigger_config_archive_collect,
                self.config.mgmt_host, self.config.mgmt_ssh_user,
                immich_stack_content=immich_content,
                identity_file=self.config.ssh_identity_file,
            )
            if not ok:
                logger.warning("config-drift collection failed: %s", errors)
                continue
            if errors:
                logger.warning("config-drift collector errors: %s", errors)

            if not data.get("committed"):
                continue

            commit_hash = data.get("commit_hash") or ""
            diffs = data.get("diffs", {})
            expected_files, unexpected_files = [], []

            for filename in data.get("changed_files", []):
                service_name = filename.removesuffix(".yml")
                last_success = self.store.get_last_container_success_timestamp(service_name)
                is_expected = (
                    last_success is not None
                    and datetime.now(timezone.utc) - datetime.fromisoformat(last_success) <= recent_window
                )
                if is_expected:
                    expected_files.append(filename)
                else:
                    unexpected_files.append(filename)
                    summary = f"Unexplained config change: {service_name} ({filename})"
                    self._create_finding(
                        "config_drift", service_name, "critical", summary,
                        {
                            "service": service_name, "file": filename,
                            "commit_hash": commit_hash,
                            "archived_at": datetime.now(timezone.utc).isoformat(),
                            "diff": diffs.get(filename, ""),
                        },
                        notify_message=(
                            f"Config-drift archive: {filename} changed with no matching recent "
                            f"bot update for {service_name}"
                        ),
                    )

            if expected_files:
                await self._notify(
                    f"Config-drift archive: {', '.join(expected_files)} changed "
                    f"(matches a recent bot update), committed as {commit_hash[:10]}."
                )

    async def run_discourse_backup_pull_loop(self, interval_seconds: float) -> None:
        while True:
            await self._sleep_until_due("discourse_backup_pull", interval_seconds)

            ok, data, errors = await asyncio.to_thread(
                discourse_backup_pull.trigger_discourse_backup_pull,
                self.config.mgmt_host, self.config.mgmt_ssh_user,
                retention_days=self.config.discourse_backup_retention_days,
                identity_file=self.config.ssh_identity_file,
            )
            if not ok:
                logger.warning("Discourse backup pull failed: %s", errors)
                continue
            if errors:
                logger.warning("Discourse backup pull collector errors: %s", errors)

            if data.get("pulled") or data.get("pruned"):
                parts = []
                if data.get("pulled"):
                    parts.append(f"pulled: {', '.join(data['pulled'])}")
                if data.get("pruned"):
                    parts.append(f"pruned (past retention): {', '.join(data['pruned'])}")
                await self._notify(f"Discourse backup archive: {'; '.join(parts)}.")

            age_hours = data.get("newest_remote_age_hours")
            if age_hours is None:
                continue
            is_bad = age_hours > self.config.discourse_backup_staleness_hours

            retried = False
            retry_detail = ""
            if is_bad:
                service = self.config.services.get("discourse")
                if service is not None:
                    retried = True
                    backup_ok, backup_detail = await asyncio.to_thread(
                        discourse_restore.create_safety_backup, service,
                        identity_file=self.config.ssh_identity_file,
                    )
                    if backup_ok:
                        ok2, data2, errors2 = await asyncio.to_thread(
                            discourse_backup_pull.trigger_discourse_backup_pull,
                            self.config.mgmt_host, self.config.mgmt_ssh_user,
                            retention_days=self.config.discourse_backup_retention_days,
                            identity_file=self.config.ssh_identity_file,
                        )
                        if ok2 and data2.get("newest_remote_age_hours") is not None:
                            data, age_hours = data2, data2["newest_remote_age_hours"]
                            is_bad = age_hours > self.config.discourse_backup_staleness_hours
                        else:
                            retry_detail = (
                                f"fresh backup triggered but the re-pull failed: "
                                f"{', '.join(errors2) if errors2 else '(unknown)'}"
                            )
                    else:
                        retry_detail = f"triggering a fresh backup failed: {backup_detail[-300:]}"

            if retried and not is_bad:
                self._create_finding(
                    "discourse_backup", "discourse_backup_age:auto_retry", "warning",
                    f"Discourse backup was stale -- triggered a fresh on-host backup, now current "
                    f"({age_hours:.1f}h old).",
                    {"newest_remote_file": data.get("newest_remote_file"), "age_hours": age_hours},
                )

            events = self.store.record_ops_health([{
                "source": "discourse_backup",
                "check_id": "discourse_backup_age",
                "status": "stale" if is_bad else "current",
                "detail": (
                    f"newest backup {data.get('newest_remote_file')}, "
                    f"{age_hours:.1f}h old (threshold {self.config.discourse_backup_staleness_hours:.0f}h)"
                ),
                "is_bad": is_bad,
            }])
            for ev in events:
                if ev["event"] == "alert":
                    detail = dict(ev)
                    if retried:
                        detail["auto_retry"] = retry_detail or "retry attempted, still stale"
                    self._create_finding(
                        "discourse_backup", ev.get("check_id"), "critical",
                        f"Discourse backup alert: {ev.get('detail')}"
                        + (f" (already tried a fresh backup -- {retry_detail})" if retried else ""),
                        detail,
                        notify_message=(
                            f"Discourse backup alert: {ev.get('detail')}"
                            + (
                                f"\nAlready triggered a fresh on-host backup attempt before escalating "
                                f"-- {retry_detail or 'that still did not produce a current one'}. "
                                f"This needs a real look."
                                if retried else ""
                            )
                        ),
                    )
                else:
                    self.store.resolve_finding_by_subject("discourse_backup", ev.get("check_id"))
                    if not retried:
                        await self._notify(f"Discourse backup recovered: {ev.get('detail')}.")


    _DISCOURSE_RESTORE_PENDING_KEY = "discourse_restore_pending"

    async def handle_discourse_backups(self) -> None:
        ok, backups, error = await asyncio.to_thread(
            discourse_restore.list_backups,
            self.config.mgmt_host, self.config.mgmt_ssh_user,
            identity_file=self.config.ssh_identity_file,
        )
        if not ok:
            await self._notify(f"!discourse-backups FAILED: {error}")
            return
        if not backups:
            await self._notify("!discourse-backups: no backups found in the mgmt1 archive yet.")
            return

        now = datetime.now(timezone.utc)
        lines = ["Discourse backups available to restore (newest first):"]
        for b in backups:
            ts = b.get("backup_timestamp")
            if ts:
                age_hours = (now - datetime.fromisoformat(ts)).total_seconds() / 3600
                age_note = f"{age_hours / 24:.1f}d" if age_hours >= 24 else f"{age_hours:.1f}h"
                loss_note = f"restoring to this loses ~{age_note} of recent activity"
            else:
                age_note, loss_note = "age unknown", "couldn't parse this filename's real timestamp"
            size_note = f", {b['size_bytes'] / 1_048_576:.0f} MB" if b.get("size_bytes") else ""
            lines.append(f"- {b['filename']} ({age_note} old{size_note}) -- {loss_note}")
        lines.append(
            "\nTo restore one: `!discourse-restore <filename>` -- it'll explain the "
            "data-loss window and ask for `!confirm-discourse-restore` before touching anything."
        )
        await self._notify("\n".join(lines))

    async def handle_discourse_restore(self, filename: str) -> None:
        service = self.config.services.get("discourse")
        if service is None:
            await self._notify("!discourse-restore: no 'discourse' service configured.")
            return
        if not discourse_restore.is_valid_backup_filename(filename):
            await self._notify(
                f"!discourse-restore: {filename!r} doesn't look like a real Discourse backup "
                f"filename -- check `!discourse-backups` for the exact name."
            )
            return

        ok, backups, error = await asyncio.to_thread(
            discourse_restore.list_backups,
            self.config.mgmt_host, self.config.mgmt_ssh_user,
            identity_file=self.config.ssh_identity_file,
        )
        if not ok:
            await self._notify(f"!discourse-restore: couldn't check the backup archive: {error}")
            return
        match = next((b for b in backups if b["filename"] == filename), None)
        if match is None:
            await self._notify(
                f"!discourse-restore: {filename!r} isn't in the mgmt1 archive -- "
                f"check `!discourse-backups` for the exact name."
            )
            return

        self.store.set_meta(self._DISCOURSE_RESTORE_PENDING_KEY, json.dumps({
            "filename": filename, "requested_at": datetime.now(timezone.utc).isoformat(),
        }))

        ts = match.get("backup_timestamp")
        if ts:
            age_hours = (datetime.now(timezone.utc) - datetime.fromisoformat(ts)).total_seconds() / 3600
            age_note = f"{age_hours / 24:.1f} days" if age_hours >= 24 else f"{age_hours:.1f} hours"
            loss_note = f"everything posted or changed in the last {age_note} would be gone after this."
        else:
            loss_note = "couldn't parse this backup's real timestamp -- treat the data-loss window as unknown."

        await self._notify(
            f"About to restore Discourse to {filename} -- {loss_note}\n\n"
            f"Before touching anything, this will take a fresh on-demand backup of the "
            f"CURRENT state and confirm it's landed on mgmt1, so this restore itself is "
            f"reversible if it turns out to be the wrong call -- it aborts with nothing "
            f"touched if that safety step fails. The forum will be unreachable for the "
            f"duration of the actual restore step (should be a few minutes, not verified "
            f"end-to-end against this exact setup yet).\n\n"
            f"Reply `!confirm-discourse-restore` to proceed, or `!abort-discourse-restore` to cancel."
        )

    async def handle_confirm_discourse_restore(self) -> None:
        pending = self.store.get_meta(self._DISCOURSE_RESTORE_PENDING_KEY)
        if not pending:
            await self._notify("No Discourse restore is currently awaiting confirmation.")
            return
        data = json.loads(pending)
        filename = data["filename"]
        service = self.config.services.get("discourse")
        if service is None:
            self.store.set_meta(self._DISCOURSE_RESTORE_PENDING_KEY, "")
            await self._notify("!confirm-discourse-restore: no 'discourse' service configured.")
            return

        await self._notify(
            f"Discourse restore to {filename}: starting -- taking a fresh safety backup "
            f"of the current state first..."
        )
        ok, out = await asyncio.to_thread(
            discourse_restore.create_safety_backup, service, identity_file=self.config.ssh_identity_file,
        )
        if not ok:
            self.store.set_meta(self._DISCOURSE_RESTORE_PENDING_KEY, "")
            await self._notify(
                f"Discourse restore ABORTED: the pre-restore safety backup failed, nothing "
                f"was touched. Output (tail):\n{out[-1500:]}"
            )
            return

        await self._notify("Safety backup created on the host -- pulling it to mgmt1 now...")
        pull_ok, pull_data, pull_errors = await asyncio.to_thread(
            discourse_backup_pull.trigger_discourse_backup_pull,
            self.config.mgmt_host, self.config.mgmt_ssh_user,
            retention_days=self.config.discourse_backup_retention_days,
            identity_file=self.config.ssh_identity_file,
        )
        if not pull_ok or not pull_data.get("pulled"):
            self.store.set_meta(self._DISCOURSE_RESTORE_PENDING_KEY, "")
            await self._notify(
                f"Discourse restore ABORTED: the safety backup was created on the host but "
                f"couldn't be confirmed pulled to mgmt1 ({pull_errors or 'no new file seen'}) -- "
                f"not proceeding without that safety net confirmed in place."
            )
            return
        safety_filenames = ", ".join(pull_data["pulled"])
        await self._notify(f"Safety backup(s) now on mgmt1: {safety_filenames}. Staging {filename} onto the host...")

        push_ok, push_detail = await asyncio.to_thread(
            discourse_restore.push_backup_to_host,
            filename, self.config.mgmt_host, self.config.mgmt_ssh_user,
            identity_file=self.config.ssh_identity_file,
        )
        if not push_ok:
            self.store.set_meta(self._DISCOURSE_RESTORE_PENDING_KEY, "")
            await self._notify(f"Discourse restore ABORTED: couldn't stage {filename} onto the host: {push_detail}")
            return

        await self._notify(f"{filename} is staged on the host ({push_detail}). Enabling restore mode...")
        ok, out = await asyncio.to_thread(
            discourse_restore.enable_restore, service, identity_file=self.config.ssh_identity_file,
        )
        if not ok:
            self.store.set_meta(self._DISCOURSE_RESTORE_PENDING_KEY, "")
            await self._notify(
                f"Discourse restore ABORTED: enable_restore failed, nothing else was touched. "
                f"Output (tail):\n{out[-1500:]}"
            )
            return

        await self._notify(f"Restore mode enabled -- running the actual restore from {filename} now (the slow step)...")
        restore_ok, restore_out = await asyncio.to_thread(
            discourse_restore.run_restore, service, filename, identity_file=self.config.ssh_identity_file,
        )
        disable_ok, disable_out = await asyncio.to_thread(
            discourse_restore.disable_restore, service, identity_file=self.config.ssh_identity_file,
        )
        self.store.set_meta(self._DISCOURSE_RESTORE_PENDING_KEY, "")

        health_ok, health_detail = await asyncio.to_thread(discourse_restore.check_health)

        lines = [f"Discourse restore to {filename}: {'SUCCEEDED' if restore_ok else 'FAILED'}."]
        if not restore_ok:
            lines.append(f"Restore output (tail):\n{restore_out[-1500:]}")
        lines.append(
            f"disable_restore: {'ok' if disable_ok else 'FAILED -- ' + disable_out[-500:]}"
        )
        lines.append(f"Post-restore health check: {health_detail}")
        lines.append(
            f"Pre-restore safety backup(s), on mgmt1 and the host, if this needs to be undone: "
            f"{safety_filenames}."
        )
        await self._notify("\n".join(lines))

    async def handle_abort_discourse_restore(self) -> None:
        if not self.store.get_meta(self._DISCOURSE_RESTORE_PENDING_KEY):
            await self._notify("No Discourse restore is currently pending.")
            return
        self.store.set_meta(self._DISCOURSE_RESTORE_PENDING_KEY, "")
        await self._notify("Discourse restore cancelled -- nothing was touched.")

    async def reconcile_orphaned_updates_on_startup(self) -> None:
        orphaned = await asyncio.to_thread(self.store.reconcile_orphaned_updates)
        for record in orphaned:
            service = self.config.services.get(record.service_name)
            if service is not None:
                await self._end_uptime_kuma_maintenance(service)
            await self._notify(
                f"Update #{record.id} ({record.service_name} -> {record.new_version}) was "
                f"orphaned by a previous bot restart while mid-pipeline (was stuck at "
                f"'{record.stage.value}') -- closed it out as a failure and ended its Kuma "
                f"maintenance window. Verify the service is actually fine, then "
                f"!mark-passed {record.id} if so."
            )

    async def reconcile_orphaned_findings_on_startup(self) -> None:
        orphaned = await asyncio.to_thread(self.store.list_stuck_investigations)
        for finding in orphaned:
            await self._notify(
                f"Finding #{finding['id']} ({finding['source']}/{finding['subject']}): its "
                f"investigation never finished before the last restart -- restarting it now."
            )
            asyncio.create_task(self._run_finding_investigation(finding["id"], finding))

    async def reconcile_cluster_maintenance_restore_on_startup(self) -> None:
        if self.store.get_meta(_CLUSTER_MAINT_AWAITING_RESTORE_KEY) != "true":
            return

        pending = json.loads(self.store.get_meta(_CLUSTER_MAINT_PENDING_KEY) or "[]")
        if not pending:
            self.store.set_meta(_CLUSTER_MAINT_AWAITING_RESTORE_KEY, "false")
            return

        await self._notify(
            "Resuming after a !maintenance-prep restart -- waiting on rbd-ns1/rbd-ns2/rbd-mgmt1 "
            "before bringing the rest of the fleet back up."
        )

        last_notice = time.monotonic()
        while True:
            ns_ok, ns_detail = await asyncio.to_thread(cluster_maintenance.check_ns_healthy)
            mgmt_ok = await asyncio.to_thread(
                cluster_maintenance.check_mgmt1_reachable,
                self.config.mgmt_host, self.config.mgmt_ssh_user,
                identity_file=self.config.ssh_identity_file,
            )
            if ns_ok and mgmt_ok:
                break
            if time.monotonic() - last_notice >= 600:
                await self._notify(
                    f"Still waiting on rbd-ns1/rbd-ns2/rbd-mgmt1 ({ns_detail}, "
                    f"mgmt1 {'reachable' if mgmt_ok else 'not reachable'})..."
                )
                last_notice = time.monotonic()
            await asyncio.sleep(30)

        vms = list(pending)
        vm_list_str = ", ".join(f"{v['name']} ({v['vmid']})" for v in vms)
        await self._notify(
            f"rbd-ns1/rbd-ns2/rbd-mgmt1 confirmed healthy -- starting {len(vms)} VM/CT(s): {vm_list_str}..."
        )

        result = await asyncio.to_thread(cluster_maintenance.start_all, self.proxmox, vms)

        vmid_to_service = {s.vmid: s for s in self.config.services.values()}
        for vm in vms:
            service = vmid_to_service.get(vm["vmid"])
            if service is not None:
                await self._end_uptime_kuma_maintenance(service)

        checked = [
            (vm, vmid_to_service[vm["vmid"]]) for vm in result["started"] if vm["vmid"] in vmid_to_service
        ]
        service_results = await asyncio.gather(
            *[self._verify_service_health_after_restore(service) for _, service in checked]
        )
        healthy_services = [service.name for (_, service), (ok, _) in zip(checked, service_results) if ok]
        unhealthy_lines = [
            f"{service.name} ({vm['name']}, VMID {vm['vmid']}): {detail}"
            for (vm, service), (ok, detail) in zip(checked, service_results) if not ok
        ]

        self.store.set_meta(_CLUSTER_MAINT_AWAITING_RESTORE_KEY, "false")
        self.store.set_meta(_CLUSTER_MAINT_PENDING_KEY, "[]")

        lines = [f"Cluster restore done: {len(result['started'])}/{len(vms)} started and confirmed running."]
        if result["failed"]:
            failed_str = ", ".join(f"{v['name']} ({v['vmid']})" for v in result["failed"])
            lines.append(f"Did not reach 'running' within the timeout: {failed_str}")
        if result["errors"]:
            lines.append("Errors: " + "; ".join(result["errors"]))
        if healthy_services:
            lines.append(f"Services confirmed healthy: {', '.join(healthy_services)}")
        if unhealthy_lines:
            lines.append("Services NOT confirmed healthy (check these manually): " + "; ".join(unhealthy_lines))
        await self._notify("\n".join(lines))

    async def _verify_service_health_after_restore(self, service) -> tuple[bool, str]:
        came_back, wait_detail = await asyncio.to_thread(
            executor.wait_for_reboot, service, down_timeout=5.0,
            identity_file=self.config.ssh_identity_file,
            mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
        )
        if not came_back:
            return False, f"not reachable over SSH after starting -- {wait_detail}"
        return await asyncio.to_thread(
            executor.watch_logs, service,
            duration_seconds=self.config.log_watch_duration,
            poll_interval=self.config.log_watch_poll_interval,
            identity_file=self.config.ssh_identity_file,
            mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
        )

    async def run_kuma_maintenance_reconcile_loop(self, interval_seconds: float) -> None:
        while True:
            await self._sleep_until_due("kuma_maintenance_reconcile", interval_seconds)
            active_service_names = {r.service_name for r in self.store.list_active()}
            held = json.loads(self.store.get_meta(_UPTIMEROBOT_PAUSED_KEY) or "{}")
            for stale in sorted({v["service"] for v in held.values() if "resumed" not in v} - active_service_names):
                await self._set_uptimerobot_paused(stale, False)
                if not any(v.get("service") == stale and "resumed" not in v
                           for v in json.loads(self.store.get_meta(_UPTIMEROBOT_PAUSED_KEY) or "{}").values()):
                    await self._notify(f"UptimeRobot monitors for {stale} were left paused with no "
                                       f"in-progress update -- started them again automatically.")
            if not self.config.uptime_kuma_base_url:
                continue
            for service_name, service in self.config.services.items():
                if service.uptime_kuma is None or service_name in active_service_names:
                    continue
                is_active = await asyncio.to_thread(
                    uptime_kuma.is_maintenance_active,
                    self.config.uptime_kuma_base_url, self.config.uptime_kuma_username,
                    self.config.uptime_kuma_password, service.uptime_kuma.maintenance_id,
                )
                if is_active:
                    await self._end_uptime_kuma_maintenance(service)
                    await self._notify(
                        f"Kuma maintenance for {service_name} was stuck active with no "
                        f"in-progress update -- ended it automatically (likely a stale window "
                        f"from a prior failed end_maintenance call)."
                    )

    async def _auto_redeploy_cloudflared(
        self, service_name: str, portainer_config: PortainerConfig, finding_id: int | None,
    ) -> str:
        ok, detail = await asyncio.to_thread(
            portainer.update_stack, portainer_config, self.config.portainer_token,
        )
        if not ok:
            if finding_id is not None:
                self.store.set_investigation_report(finding_id, f"Auto-redeploy attempt failed: {detail}")
            return (
                f"  Auto-redeploy attempted (Portainer stack {portainer_config.stack_name!r}): "
                f"FAILED -- {detail}\n"
            )

        for _ in range(6):
            await asyncio.sleep(15)
            health, _errors = await asyncio.to_thread(
                cloudflare_traffic.collect_tunnel_health,
                self.config.cloudflare_api_token, self.config.cloudflare_account_id,
                {service_name: self.config.cloudflare_tunnel_ids[service_name]},
            )
            versions = health.get(service_name, {}).get("versions") or []
            if versions:
                report = (
                    f"  Auto-redeploy (Portainer stack {portainer_config.stack_name!r}): "
                    f"now running {versions}\n"
                )
                if finding_id is not None:
                    self.store.set_investigation_report(finding_id, report.strip())
                return report
        report = (
            f"  Auto-redeploy triggered (Portainer stack {portainer_config.stack_name!r}), but "
            f"the connector didn't report a version within 90s -- check manually.\n"
        )
        if finding_id is not None:
            self.store.set_investigation_report(finding_id, report.strip())
        return report

    async def run_cloudflare_traffic_loop(self, interval_seconds: float) -> None:
        while True:
            await self._sleep_until_due("cloudflare_traffic", interval_seconds)
            zones = [z for z in self.config.cloudflare_traffic_zones if z.api_token and z.zone_id]
            if not zones:
                continue

            until_dt = datetime.now(timezone.utc)
            traffic: dict = {}
            security_events: dict = {}
            known_path_health: dict = {}
            tunnel_health: dict = {}
            tunnel_errors: list[str] = []

            for zone in zones:
                last_until_raw = self.store.get_meta(f"cloudflare_traffic_last_until:{zone.zone_id}")
                since_dt = (
                    datetime.fromisoformat(last_until_raw) if last_until_raw
                    else until_dt - timedelta(seconds=interval_seconds)
                )

                zone_traffic, traffic_err = await asyncio.to_thread(
                    cloudflare_traffic.collect_hostname_traffic,
                    zone.api_token, zone.zone_id, zone.hostnames,
                    since_dt.isoformat(), until_dt.isoformat(),
                )
                if traffic_err:
                    logger.warning("cloudflare traffic collection failed (zone %s): %s", zone.zone_id, traffic_err)
                else:
                    traffic.update(zone_traffic)

                zone_security, security_err = await asyncio.to_thread(
                    cloudflare_traffic.collect_security_events,
                    zone.api_token, zone.zone_id, zone.hostnames,
                    since_dt.isoformat(), until_dt.isoformat(),
                )
                if security_err:
                    logger.warning(
                        "cloudflare security events collection failed (zone %s): %s", zone.zone_id, security_err,
                    )
                else:
                    security_events.update(zone_security)

                for host, paths in cloudflare_traffic._KNOWN_PATHS_BY_HOST.items():
                    if host not in zone.hostnames:
                        continue
                    host_paths, path_err = await asyncio.to_thread(
                        cloudflare_traffic.collect_known_path_health,
                        zone.api_token, zone.zone_id, host, paths,
                        since_dt.isoformat(), until_dt.isoformat(),
                    )
                    if path_err:
                        logger.warning("cloudflare known-path collection failed for %s: %s", host, path_err)
                        continue
                    known_path_health[host] = host_paths

                self.store.set_meta(f"cloudflare_traffic_last_until:{zone.zone_id}", until_dt.isoformat())

            latest_cloudflared_version: str | None = None
            if self.config.cloudflare_tunnel_ids:
                tunnel_health, tunnel_errors = await asyncio.to_thread(
                    cloudflare_traffic.collect_tunnel_health,
                    self.config.cloudflare_api_token, self.config.cloudflare_account_id,
                    self.config.cloudflare_tunnel_ids,
                )
                if tunnel_errors:
                    logger.warning("cloudflare tunnel health collector errors: %s", tunnel_errors)
                latest_cloudflared_version, cf_version_err = await asyncio.to_thread(
                    cloudflare_traffic.get_latest_cloudflared_version,
                )
                if cf_version_err:
                    logger.warning("cloudflared latest-version lookup failed: %s", cf_version_err)

            since_floor = until_dt - timedelta(seconds=interval_seconds)
            recent_activity: dict[str, bool] = {}
            for service_name in set(cloudflare_traffic._HOSTNAME_TO_SERVICE.values()):
                records = self.store.list_by_service(service_name)
                recent_activity[service_name] = _had_overlapping_update_activity(records, since_floor, until_dt)

            checks = cloudflare_traffic.build_checks(
                traffic, tunnel_health, known_path_health, security_events, recent_activity,
                latest_cloudflared_version,
            )
            if not checks:
                continue

            events = self.store.record_ops_health(checks)
            for ev in events:
                check_id = ev.get("check_id", "")
                is_tunnel_check = check_id.startswith(("cf_tunnel_health:", "cf_cloudflared_version:"))
                label = "Cloudflare tunnel" if is_tunnel_check else "Cloudflare traffic"
                if ev["event"] == "alert":
                    summary = f"{label} alert: {check_id} -- {ev.get('status')}"
                    finding_id, trailer = self._create_finding(
                        "cloudflare_traffic", check_id, "warning", summary, ev,
                    )
                    redeploy_note = ""
                    if check_id.startswith("cf_cloudflared_version:"):
                        svc_name = check_id.split(":", 1)[1]
                        svc = self.config.services.get(svc_name)
                        if svc and svc.cf_tunnel_portainer:
                            redeploy_note = await self._auto_redeploy_cloudflared(
                                svc_name, svc.cf_tunnel_portainer, finding_id,
                            )
                    await self._notify(
                        f"{label} alert:\n"
                        f"  Check:  {check_id}\n"
                        f"  Status: {ev.get('status')}\n"
                        f"  Detail: {ev.get('detail')}\n"
                        f"{redeploy_note}"
                        f"{trailer}"
                    )
                else:
                    self.store.resolve_finding_by_subject("cloudflare_traffic", ev.get("check_id"))
                    await self._notify(f"{label} recovered: {ev.get('detail')}.")

    async def handle_bot_message(self, sender: str, content: dict) -> None:
        now = datetime.now(timezone.utc)
        hb = bot_coordination.parse_heartbeat(content, sender, self.config.coordination_pass_bot_user_id, now)
        if hb is not None:
            await self._handle_pass_bot_heartbeat(hb, now)
            return
        decl = bot_coordination.parse_declaration(
            content, sender, self.config.coordination_pass_bot_user_id, now,
        )
        if decl is None:
            if bot_coordination.CONTENT_KEY in content:
                logger.warning("ignored bot-to-bot message from %s (untrusted sender or bad shape)", sender)
            return
        if self.store.record_bot_declaration(decl, sender):
            logger.info("pass-bot declared %s of %r in %s", decl["action"], decl["rule"]["displayName"], decl["mailbox"])

    def _bot_status_snapshot(self) -> dict:
        window = None
        cfg = self.config.scheduled_maintenance
        if cfg.enabled and cfg.services:
            now = datetime.now(ZoneInfo(self.config.local_timezone))
            start = _next_window_start(now, cfg.weekday, cfg.start_hour, cfg.window_hours)
            week = f"{start.isocalendar()[0]}-W{start.isocalendar()[1]:02d}"
            approval = (self.store.get_meta("sched_maint_approval") or "") \
                if self.store.get_meta("sched_maint_week") == week else ""
            window = {"start": start.isoformat(), "services": list(cfg.services), "approval": approval}
        findings = self.store.list_findings(limit=1000)
        return bot_coordination.status_snapshot(self.store.list_active(), findings, window,
                                                datetime.now(timezone.utc))

    async def _mgmt1_agent_status(self) -> dict | None:
        try:
            return await asyncio.to_thread(
                mgmt1_agent.check_agent, self.config.mgmt_host, self.config.mgmt_ssh_user,
                identity_file=self.config.ssh_identity_file,
            )
        except Exception:
            logger.exception("mgmt1 agent status check failed")
            return None

    async def _relay_agent_refusal(self, service) -> str | None:
        if not service.relay_through_mgmt or not self.config.mgmt_host:
            return None
        status = await self._mgmt1_agent_status()
        if status is None or status["state"] not in mgmt1_agent.BAD_STATES:
            return None
        return (
            f"{mgmt1_agent.describe(status)}. {service.name} is only reachable through "
            f"mgmt1's relay, so nothing was started (no maintenance window, backup, or "
            f"change). To fix: {mgmt1_agent.FIX_HINT}"
        )

    async def _refuse_job_if_relay_agent_empty(self, update_id: int, service, label: str) -> bool:
        reason = await self._relay_agent_refusal(service)
        if reason is None:
            return False
        self.store.set_stage(update_id, Stage.ABORTED, f"refused: {reason}")
        await self._notify(f"{label} #{update_id} ({service.name}) NOT started: {reason}, then run it again.")
        return True

    async def run_mgmt1_agent_watch_loop(self, interval_seconds: float) -> None:
        while True:
            try:
                status = await self._mgmt1_agent_status()
                if status is not None and status["state"] in (mgmt1_agent.BAD_STATES | {"loaded"}):
                    bad = status["state"] in mgmt1_agent.BAD_STATES
                    prev = self.store.get_meta("mgmt1_agent_state")
                    was_bad = prev in mgmt1_agent.BAD_STATES
                    if bad and not was_bad:
                        relay = sorted(n for n, s in self.config.services.items() if s.relay_through_mgmt)
                        summary = (
                            f"{mgmt1_agent.describe(status)}. Until it's loaded, jobs for relay-only "
                            f"services ({', '.join(relay) or 'none'}) will be refused, and mgmt1's "
                            f"collectors/investigations that SSH onward will fail."
                        )
                        _, trailer = self._create_finding(
                            "mgmt1", "ssh_agent", "warning", summary, dict(status),
                        )
                        await self._notify(f"{summary}\nTo fix: {mgmt1_agent.FIX_HINT}.\n{trailer}")
                    elif not bad and was_bad:
                        self.store.resolve_finding_by_subject("mgmt1", "ssh_agent")
                        await self._notify("mgmt1's SSH agent has a key loaded again -- relay-dependent jobs can run.")
                    if prev != status["state"]:
                        self.store.set_meta("mgmt1_agent_state", status["state"])
            except Exception:
                logger.exception("mgmt1 agent watch failed")
            await asyncio.sleep(interval_seconds)

    async def run_bot_status_loop(self, interval_seconds: float) -> None:
        while True:
            try:
                if self.matrix is not None and self.config.coordination_room_id:
                    snap = self._bot_status_snapshot()
                    digest = hashlib.sha256(json.dumps(snap, sort_keys=True).encode()).hexdigest()
                    now = datetime.now(timezone.utc)
                    last = self.store.get_meta("bot_status_last_post")
                    stale = last is None or now - datetime.fromisoformat(last) >= bot_coordination.STATUS_REFRESH
                    if stale or digest != self.store.get_meta("bot_status_last_hash"):
                        await self.matrix.send_bot_message(bot_coordination.status_notice(snap, now))
                        self.store.set_meta("bot_status_last_hash", digest)
                        self.store.set_meta("bot_status_last_post", now.isoformat())
            except Exception as exc:
                logger.warning("bot status snapshot failed: %s", exc)
            await asyncio.sleep(interval_seconds)

    async def _handle_pass_bot_heartbeat(self, hb: dict, now: datetime) -> None:
        last = self.store.get_meta("passbot_last_heartbeat")
        if last and hb["at"] <= datetime.fromisoformat(last):
            return
        if now - hb["at"] > hb["interval"] * 2:
            return
        self.store.set_meta("passbot_last_heartbeat", hb["at"].isoformat())
        self.store.set_meta("passbot_heartbeat_interval_s", str(int(hb["interval"].total_seconds())))
        checks = bot_coordination.heartbeat_ops_checks(hb)
        overdue = bot_coordination.heartbeat_overdue(hb["at"], hb["interval"], now)
        await self._pass_bot_health_events(checks + ([overdue] if overdue else []))

    _GRAPH_OUTAGE_CHECK_IDS = {"passbot:graph_mail", "passbot:mail_rules"}

    async def _pass_bot_health_events(self, checks: list[dict]) -> None:
        for ev in self.store.record_ops_health(checks):
            if ev["event"] == "alert":
                summary = f"pass-bot health: {ev['check_id']} -- {ev.get('detail')}"
                detail = dict(ev)
                severity = "warning"
                if ev["check_id"] in self._GRAPH_OUTAGE_CHECK_IDS and self.config.o365_outage_watch_enabled:
                    try:
                        advisory = await asyncio.to_thread(
                            o365_outage_watch.check_o365_outage,
                            client=self.anthropic_client, model=self.config.llm_model,
                            trigger_detail=ev.get("detail") or "",
                        )
                        detail["o365_outage_advisory"] = {
                            "has_active_outage": advisory.has_active_outage,
                            "affected_workloads": advisory.affected_workloads,
                            "status": advisory.status,
                            "source_url": advisory.source_url,
                            "summary": advisory.summary,
                        }
                        if advisory.has_active_outage:
                            summary += (
                                f" -- looks like a Microsoft-side outage ({advisory.status}): "
                                f"{advisory.summary} ({advisory.source_url or 'no source url'})"
                            )
                        else:
                            severity = "critical"
                            summary += " -- no current Microsoft outage found; looks like a real local issue"
                    except Exception:
                        logger.exception("o365_outage_watch: research call failed for %s", ev["check_id"])
                finding_id, trailer = self._create_finding(
                    "pass_bot", ev["check_id"], severity, summary, detail,
                )
                await self._notify(f"{summary}\n{trailer}")
            else:
                self.store.resolve_finding_by_subject("pass_bot", ev["check_id"])
                await self._notify(f"pass-bot health recovered: {ev['check_id']} ({ev.get('detail')}).")

    async def run_pass_bot_heartbeat_watch_loop(self, interval_seconds: float) -> None:
        while True:
            await asyncio.sleep(interval_seconds)
            try:
                if any(r.service_name in ("pass-bot", "matrix") for r in self.store.list_active()
                       if r.stage.value not in ("staged_pending_approval", "awaiting_backup_decision",
                                                "awaiting_reboot_decision")):
                    continue
                last = self.store.get_meta("passbot_last_heartbeat")
                interval = timedelta(seconds=float(self.store.get_meta("passbot_heartbeat_interval_s") or 1800))
                check = bot_coordination.heartbeat_overdue(
                    datetime.fromisoformat(last) if last else None, interval, datetime.now(timezone.utc),
                )
                if check is not None:
                    await self._pass_bot_health_events([check])
            except Exception as exc:
                logger.warning("pass-bot heartbeat watch failed: %s", exc)

    _GRAPH_SIGNIN_MAX_LOOKBACK_HOURS = 24.0
    _GRAPH_SIGNIN_MAX_BACKOFF_HOURS = 6.0

    async def run_graph_monitor_loop(self, interval_seconds: float) -> None:
        while True:
            await self._sleep_until_due("graph_monitor", interval_seconds)
            if not (self.config.graph_client_id and self.config.graph_client_secret and self.config.graph_tenant_id):
                continue
            if not self.config.graph_mailbox_user_ids:
                continue

            token, token_err = await asyncio.to_thread(
                graph_monitor._get_token,
                self.config.graph_client_id, self.config.graph_client_secret, self.config.graph_tenant_id,
            )
            if token_err:
                logger.warning("graph monitor token acquisition failed: %s", token_err)
                continue

            rules_by_user, rule_errors = await asyncio.to_thread(
                graph_monitor.collect_inbox_rules, token, self.config.graph_mailbox_user_ids,
            )
            if rule_errors:
                logger.warning("graph monitor inbox-rule collection errors: %s", rule_errors)

            for user_id, rules in rules_by_user.items():
                previous = self.store.mailbox_rule_bodies(user_id)
                new_rules, modified_rules, deleted_rules = self.store.record_mailbox_rule_sightings(user_id, rules)
                now = datetime.now(timezone.utc)
                declarations = self.store.live_bot_declarations(user_id, now.isoformat())
                reordered: list[str] = []
                for kind, verb, changed in (("new", "New inbox rule on", new_rules),
                                            ("modified", "Inbox rule modified on", modified_rules),
                                            ("deleted", "Inbox rule deleted on", deleted_rules)):
                    for rule in changed:
                        verdict, note = bot_coordination.classify_rule_change(
                            kind, user_id, rule, previous.get(rule.get("id")), declarations,
                            self.config.coordination_pass_bot_mailboxes, now,
                        )
                        if verdict == "order":
                            reordered.append(f"{rule.get('displayName')!r} ({note})")
                            continue
                        if verdict == "expected":
                            await self._notify(
                                f"Inbox rule change (expected, declared by pass-bot): {verb.split(' on')[0].lower()} "
                                f"{rule.get('displayName')!r} on {user_id} -- {note}"
                            )
                            continue
                        summary = f"{verb} {user_id}: {rule.get('displayName')!r}"
                        if self.config.coordination_room_id:
                            summary += f" -- {note}"
                        finding_id, trailer = self._create_finding(
                            "graph_monitor", f"mailbox_rule:{user_id}:{rule.get('id')}", "warning", summary, rule,
                        )
                        await self._notify(f"{summary}\n{trailer}")
                if reordered:
                    await self._notify(
                        f"Inbox rules renumbered on {user_id} (order only, contents unchanged): " + "; ".join(reordered)
                    )

            until_dt = datetime.now(timezone.utc)
            backoff_until_raw = self.store.get_meta("graph_signin_backoff_until")
            backoff_until = datetime.fromisoformat(backoff_until_raw) if backoff_until_raw else None
            if backoff_until is not None and until_dt < backoff_until:
                logger.info(
                    "graph monitor sign-in collection still backing off (Graph throttling/timeouts) "
                    "until %s -- skipping this cycle", backoff_until.isoformat(),
                )
                continue

            last_watermark = self.store.get_meta("graph_signin_last_watermark")
            since_dt = (
                datetime.fromisoformat(last_watermark) if last_watermark
                else until_dt - timedelta(seconds=interval_seconds)
            )
            earliest_allowed = until_dt - timedelta(hours=self._GRAPH_SIGNIN_MAX_LOOKBACK_HOURS)
            clamped = since_dt < earliest_allowed
            if clamped:
                since_dt = earliest_allowed
            since_iso = since_dt.isoformat()

            events, events_err = await asyncio.to_thread(graph_monitor.collect_signin_events, token, since_iso)
            if events_err:
                fail_streak = int(self.store.get_meta("graph_signin_fail_streak") or "0") + 1
                self.store.set_meta("graph_signin_fail_streak", str(fail_streak))
                cooldown_hours = min(
                    self._GRAPH_SIGNIN_MAX_BACKOFF_HOURS,
                    (interval_seconds / 3600) * (2 ** (fail_streak - 1)),
                )
                new_backoff_until = until_dt + timedelta(hours=cooldown_hours)
                self.store.set_meta("graph_signin_backoff_until", new_backoff_until.isoformat())
                logger.warning(
                    "graph monitor sign-in collection failed (%d consecutive): %s -- backing off until %s",
                    fail_streak, events_err, new_backoff_until.isoformat(),
                )
            else:
                self.store.set_meta("graph_signin_fail_streak", "0")
                self.store.set_meta("graph_signin_backoff_until", "")
                if clamped:
                    await self._notify(
                        f"Graph sign-in monitor: resumed after an extended failure -- the lookback window "
                        f"was capped at {self._GRAPH_SIGNIN_MAX_LOOKBACK_HOURS:.0f}h, so any sign-in events "
                        f"before {since_iso} were skipped."
                    )
                flagged = graph_monitor.flag_signin_events(events)
                for item in flagged:
                    if item["severity"] == "info":
                        await self._notify(f"Sign-in activity (informational): {item['summary']}")
                        continue
                    finding_id, trailer = self._create_finding(
                        "graph_monitor", f"signin:{item['category']}:{item['summary']}", "warning",
                        item["summary"], item["event"],
                    )
                    await self._notify(f"Sign-in anomaly ({item['category']}): {item['summary']}\n{trailer}")

                if self.config.graph_admin_user_principal_name and self.config.mgmt_host:
                    home_ip, wan_ip_err = await asyncio.to_thread(
                        fortigate_blocklist.trigger_get_wan_ip,
                        self.config.mgmt_host, self.config.mgmt_ssh_user,
                        fortigate_api_host=self.config.fortigate_api_host,
                        fortigate_token_file=self.config.fortigate_token_file,
                        identity_file=self.config.ssh_identity_file,
                    )
                    if wan_ip_err:
                        logger.warning("graph monitor couldn't resolve home WAN IP: %s", wan_ip_err)
                    admin_flagged = graph_monitor.flag_admin_signin_events(
                        events, self.config.graph_admin_user_principal_name, home_ip,
                    )
                    for item in admin_flagged:
                        when = item["event"].get("createdDateTime") or ""
                        nearby = self.store.get_wg_connections_near(when, 600) if when else []
                        if nearby:
                            peers = ", ".join(c.get("label") or c["pubkey"][:12] for c in nearby)
                            wg_note = f"WireGuard peer(s) connected within 10 min of this sign-in: {peers} (context only, not proof)."
                        else:
                            wg_note = "No WireGuard peer connected within 10 min of this sign-in either."
                        summary = f"{item['summary']} -- {wg_note}"
                        finding_id, trailer = self._create_finding(
                            "graph_monitor", f"admin_signin:{when}", "critical", summary, item["event"],
                        )
                        await self._notify(f"Admin sign-in alert: {summary}\n{trailer}")

                latest = max((e.get("createdDateTime") for e in events if e.get("createdDateTime")), default=None)
                self.store.set_meta("graph_signin_last_watermark", latest or until_dt.isoformat())

    async def run_kb_access_sync_loop(self, interval_seconds: float) -> None:
        while True:
            await self._sleep_until_due("kb_access_sync", interval_seconds)
            if not (self.config.cloudflare_access_api_token and self.config.kb_immich_base_url
                    and self.config.immich_users_api_key and self.config.kb_access_group_id):
                continue

            desired, immich_err = await asyncio.to_thread(
                kb_access_sync.collect_immich_emails,
                self.config.kb_immich_base_url, self.config.immich_users_api_key,
            )
            if desired is None:
                logger.warning("kb_access_sync: Immich user-list collection failed: %s", immich_err)
                continue

            current, cf_err = await asyncio.to_thread(
                kb_access_sync.get_group_emails,
                self.config.cloudflare_access_api_token, self.config.cloudflare_account_id,
                self.config.kb_access_group_id,
            )
            if current is None:
                logger.warning("kb_access_sync: Cloudflare Access group fetch failed: %s", cf_err)
                continue

            added, removed = kb_access_sync.diff_emails(current, desired)
            if not added and not removed:
                continue

            ok, set_err = await asyncio.to_thread(
                kb_access_sync.set_group_emails,
                self.config.cloudflare_access_api_token, self.config.cloudflare_account_id,
                self.config.kb_access_group_id, desired,
            )
            if not ok:
                logger.warning("kb_access_sync: Cloudflare Access group update failed: %s", set_err)
                continue

            parts = []
            if added:
                parts.append(f"added: {', '.join(added)}")
            if removed:
                parts.append(f"removed: {', '.join(removed)}")
            await self._notify(f"KB Immich-synced access group updated -- {'; '.join(parts)}.")

    async def run_kb_access_monitor_loop(self, interval_seconds: float) -> None:
        while True:
            await self._sleep_until_due("kb_access_monitor", interval_seconds)
            window_seconds = self.config.kb_access_monitor_window_hours * 3600
            until_dt = datetime.now(timezone.utc)

            if (self.config.cloudflare_access_api_token and self.config.cloudflare_account_id
                    and self.config.kb_matrix_teamspeak_app_id):
                last_watermark = self.store.get_meta("kb_access_logins_last_watermark")
                since_iso = last_watermark or (until_dt - timedelta(seconds=window_seconds)).isoformat()
                events, err = await asyncio.to_thread(
                    kb_access_monitor.collect_access_logins,
                    self.config.cloudflare_access_api_token, self.config.cloudflare_account_id,
                    self.config.kb_matrix_teamspeak_app_id, since_iso, until_dt.isoformat(),
                )
                if err:
                    logger.warning("kb_access_monitor: Access log collection failed: %s", err)
                else:
                    count = len(events)
                    if count > self.config.kb_new_logins_warn_threshold:
                        emails = sorted({e.get("user_email") for e in events if e.get("user_email")})
                        summary = (
                            f"{count} KB login(s) on the matrix/teamspeak restricted path since the last "
                            f"check (threshold {self.config.kb_new_logins_warn_threshold}) -- "
                            f"{len(emails)} distinct email(s)"
                        )
                        finding_id, trailer = self._create_finding(
                            "kb_access_monitor", f"logins:{until_dt.isoformat()}", "warning", summary,
                            {"count": count, "emails": emails},
                        )
                        await self._notify(
                            f"{summary}\n{trailer}\nIf this looks like abuse: !kb-restrict, "
                            f"!kb-rotate-token, or !block-ip <ip> for a specific source."
                        )
                    latest = max(
                        (e.get("created_at") for e in events if e.get("created_at")), default=None,
                    )
                    self.store.set_meta("kb_access_logins_last_watermark", latest or until_dt.isoformat())

            if (self.config.matrix_admin_access_token and self.config.kb_admin_room_id
                    and self.config.kb_admin_bot_user_id):
                usernames, err = await asyncio.to_thread(
                    kb_access_monitor.collect_all_matrix_usernames,
                    self.config.matrix_homeserver, self.config.matrix_admin_access_token,
                    self.config.kb_admin_room_id, self.config.kb_admin_bot_user_id,
                )
                if usernames is None:
                    logger.warning("kb_access_monitor: Matrix user-list collection failed: %s", err)
                else:
                    known_raw = self.store.get_meta("kb_matrix_known_usernames")
                    known = set(json.loads(known_raw)) if known_raw else None
                    current = set(usernames)
                    if known is not None:
                        new_users = sorted(current - known)
                        if len(new_users) > self.config.kb_new_registrations_warn_threshold:
                            summary = (
                                f"{len(new_users)} new Matrix registration(s) since the last check "
                                f"(threshold {self.config.kb_new_registrations_warn_threshold}): "
                                f"{', '.join(new_users)}"
                            )
                            finding_id, trailer = self._create_finding(
                                "kb_access_monitor", f"registrations:{until_dt.isoformat()}", "warning", summary,
                                {"users": new_users},
                            )
                            await self._notify(
                                f"{summary}\n{trailer}\nThe published Matrix registration token may be "
                                f"leaking -- consider !kb-rotate-token."
                            )
                    self.store.set_meta("kb_matrix_known_usernames", json.dumps(sorted(current)))

            if (self.config.kb_registration_token_max_uses > 0
                    and self.config.matrix_admin_access_token and self.config.kb_admin_room_id
                    and self.config.kb_admin_bot_user_id):
                active_token = self._kb_active_registration_token()
                if active_token:
                    remaining, err = await asyncio.to_thread(
                        kb_access_monitor.collect_active_token_uses_remaining,
                        self.config.matrix_homeserver, self.config.matrix_admin_access_token,
                        self.config.kb_admin_room_id, self.config.kb_admin_bot_user_id, active_token,
                    )
                    if remaining is None:
                        if err:
                            logger.warning("kb_access_monitor: token-uses-remaining check failed: %s", err)
                    elif remaining <= self.config.kb_registration_token_rotate_at_remaining:
                        new_token, rotate_err = await asyncio.to_thread(
                            kb_lockdown.rotate_registration_token,
                            self.config.matrix_homeserver, self.config.matrix_admin_access_token,
                            self.config.kb_admin_room_id, self.config.kb_admin_bot_user_id, active_token,
                            issue_flag=f"--max-uses {self.config.kb_registration_token_max_uses}",
                        )
                        if not new_token:
                            logger.warning("kb_access_monitor: auto-rotation failed: %s", rotate_err)
                        else:
                            status = await self._kb_finish_rotation(new_token, trigger_label="auto")
                            await self._notify(
                                f"KB Matrix registration token auto-rotated (had {remaining} use(s) left) "
                                f"-- new token issued with --max-uses {self.config.kb_registration_token_max_uses}. "
                                f"{status}"
                            )

    async def run_librenms_monitor_loop(self, interval_seconds: float) -> None:
        while True:
            await self._sleep_until_due("librenms_monitor", interval_seconds)
            if not (self.config.librenms_api_host and self.config.librenms_api_token):
                continue

            devices, devices_err = await asyncio.to_thread(
                librenms_monitor.collect_devices, self.config.librenms_api_host, self.config.librenms_api_token,
            )
            if devices_err:
                logger.warning("librenms monitor device collection failed: %s", devices_err)
                continue

            ports_by_device: dict[int, list[dict]] = {}
            for d in devices:
                if d.get("hostname") not in librenms_monitor.PORT_TRACKED_HOSTNAMES:
                    continue
                ports, ports_err = await asyncio.to_thread(
                    librenms_monitor.collect_ports,
                    self.config.librenms_api_host, self.config.librenms_api_token, d["device_id"],
                )
                if ports_err:
                    logger.warning("librenms monitor port collection failed: %s", ports_err)
                    continue
                ports_by_device[d["device_id"]] = ports

            checks = librenms_monitor.build_checks(devices, ports_by_device)
            if not checks:
                continue

            events = self.store.record_ops_health(checks)
            for ev in events:
                check_id = ev.get("check_id") or ""
                if ev["event"] == "alert":
                    severity = "critical" if check_id.startswith("librenms_device:") else "warning"
                    summary = f"LibreNMS alert: {ev.get('detail')}"
                    self._create_finding(
                        "librenms_monitor", check_id, severity, summary, ev,
                        notify_message=f"LibreNMS alert:\n  {ev.get('detail')}",
                    )
                else:
                    self.store.resolve_finding_by_subject("librenms_monitor", check_id)

    async def run_external_reachability_loop(self, interval_seconds: float) -> None:
        while True:
            await self._sleep_until_due("external_reachability", interval_seconds)
            hostnames = [h for zone in self.config.cloudflare_traffic_zones for h in zone.hostnames]
            if not hostnames or not self.config.uptimerobot_api_key:
                continue

            monitors, error = await asyncio.to_thread(
                external_reachability.collect_uptimerobot_status, self.config.uptimerobot_api_key,
            )
            if error:
                logger.warning("external reachability poll failed: %s", error)
                continue

            held = json.loads(self.store.get_meta(_UPTIMEROBOT_PAUSED_KEY) or "{}")
            for hostname, v in list(held.items()):
                if "resumed" not in v:
                    continue
                statuses = {str(m.get("status", "")).upper() for m in monitors if m.get("id") in v["monitor_ids"]}
                settled = statuses and not statuses & {"STARTED", "PAUSED"}
                too_long = datetime.now(timezone.utc) - datetime.fromisoformat(v["resumed"]) > timedelta(minutes=30)
                if settled or too_long:
                    held.pop(hostname)
            self.store.set_meta(_UPTIMEROBOT_PAUSED_KEY, json.dumps(held))
            paused_by_us = set(held)
            checks = external_reachability.build_checks(monitors, [h for h in hostnames if h not in paused_by_us])
            events = self.store.record_ops_health(checks)

            reachability = reachability_correlation.correlate(self.store.list_ops_health())
            reachability_by_service = {r["service"]: r for r in reachability}
            external_only_down_count = sum(
                1 for r in reachability if r["classification"] == "external_only_down"
            )

            for ev in events:
                check_id = ev.get("check_id") or ""
                if ev["event"] == "alert":
                    severity = "critical" if ev.get("status") == "down" else "warning"
                    hostname = check_id.split(":", 1)[1] if ":" in check_id else ""
                    service = cloudflare_traffic._HOSTNAME_TO_SERVICE.get(hostname)
                    extra_note = ""
                    r = reachability_by_service.get(service) if service else None
                    if r and r["classification"] == "external_only_down":
                        if external_only_down_count >= 3:
                            extra_note = (
                                f" Kuma shows this healthy internally, and {external_only_down_count} "
                                f"other service(s) show the same pattern right now -- this looks like a "
                                f"possible ISP/upstream issue, not a per-service problem."
                            )
                        else:
                            extra_note = (
                                " Kuma shows this healthy internally -- likely a tunnel/DNS/WAF issue "
                                "for this hostname specifically, not the service itself."
                            )
                    self._create_finding(
                        "external_reachability", check_id, severity,
                        (ev.get("detail") or check_id) + extra_note, ev,
                        notify_message=f"\U0001f310 {ev.get('detail')}{extra_note}",
                    )
                else:
                    self.store.resolve_finding_by_subject("external_reachability", check_id)

            was_active = self.store.get_meta("reachability_isp_outage_active") == "1"
            already_open = "fleet" in self.store.open_finding_subjects("reachability_correlation")
            is_active = external_only_down_count >= 3
            if is_active and not was_active and not already_open:
                affected = sorted(
                    r["service"] for r in reachability if r["classification"] == "external_only_down"
                )
                finding_id = self.store.create_finding(
                    "reachability_correlation", "fleet", "critical",
                    f"{external_only_down_count} services ({', '.join(affected)}) are reachable "
                    f"internally (Kuma) but not externally (UptimeRobot) at the same time -- this "
                    f"looks like a possible ISP/upstream outage, not isolated per-service problems.",
                )
                await self._notify(
                    f"\U0001f6a8 Possible ISP/upstream outage: {external_only_down_count} services "
                    f"({', '.join(affected)}) are up internally but unreachable externally at the "
                    f"same time. Finding #{finding_id} tracks this."
                )
                self.store.set_meta("reachability_isp_outage_active", "1")
            elif not is_active and (was_active or already_open):
                self.store.resolve_finding_by_subject("reachability_correlation", "fleet")
                self.store.set_meta("reachability_isp_outage_active", "")

    async def run_kuma_crash_monitor_loop(self, interval_seconds: float) -> None:
        while True:
            await self._sleep_until_due("kuma_crash_monitor", interval_seconds)
            if not self.config.uptime_kuma_base_url:
                continue

            statuses, err = await asyncio.to_thread(
                kuma_crash_monitor.collect_monitor_statuses,
                self.config.uptime_kuma_base_url, self.config.uptime_kuma_username,
                self.config.uptime_kuma_password,
            )
            if err:
                continue

            checks = kuma_crash_monitor.build_checks(statuses)
            if not checks:
                continue

            events = self.store.record_ops_health(checks)
            deferred = json.loads(self.store.get_meta(_KUMA_DEFERRED_KEY) or "{}")
            down_now = {c["check_id"] for c in checks if c["is_bad"]}
            seen_now = {c["check_id"] for c in checks}
            for check_id in list(deferred):
                if check_id in seen_now and check_id not in down_now:
                    deferred.pop(check_id)
            for check_id, held in list(deferred.items()):
                if check_id not in down_now or any(e.get("check_id") == check_id for e in events):
                    continue
                service = self.config.services.get(held["service"])
                if service is None:
                    deferred.pop(check_id)
                    continue
                if await self._kuma_hold_for_self_update(check_id, held["monitor"], held["service"],
                                                         service, deferred, held.get("since")):
                    continue
                deferred.pop(check_id)
                await self._kuma_auto_restart(check_id, held["monitor"], service, held.get("event") or {})
            self.store.set_meta(_KUMA_DEFERRED_KEY, json.dumps(deferred))

            for ev in events:
                check_id = ev.get("check_id") or ""
                monitor_name = (ev.get("raw_detail") or {}).get("name", check_id)

                if ev["event"] != "alert":
                    self.store.resolve_finding_by_subject("kuma_monitor", check_id)
                    continue

                service_name = kuma_crash_monitor.KUMA_MONITOR_TO_SERVICE.get(monitor_name.lower())
                service = self.config.services.get(service_name) if service_name else None
                if service is None:
                    now_local = datetime.now(ZoneInfo(self.config.local_timezone))
                    if kuma_crash_monitor.in_scheduled_self_update_window(monitor_name, now_local):
                        self._create_finding(
                            "kuma_monitor", check_id, "warning",
                            f"{monitor_name} was down -- inside its known nightly self-update "
                            f"window, not paging", ev,
                        )
                        continue
                    backup_note = ""
                    proxmox_ctx = await self._resolve_kuma_monitor_proxmox_context(monitor_name)
                    if proxmox_ctx and proxmox_ctx["currently_locked_for_backup"]:
                        backup_note = (
                            f" -- a Proxmox backup is currently running for this VM (VMID "
                            f"{proxmox_ctx['vmid']}); likely cause. Was this a manual backup, "
                            f"or the regular scheduled job?"
                        )
                    finding_id, trailer = self._create_finding(
                        "kuma_monitor", check_id, "critical",
                        f"{monitor_name} is down (no auto-restart configured for this monitor)"
                        f"{backup_note}", ev,
                    )
                    await self._notify(f"{monitor_name} is down{backup_note}:\n{trailer}")
                    continue

                if await self._kuma_hold_for_self_update(check_id, monitor_name, service_name, service,
                                                         deferred, None, event=ev):
                    self.store.set_meta(_KUMA_DEFERRED_KEY, json.dumps(deferred))
                    continue
                await self._kuma_auto_restart(check_id, monitor_name, service, ev)

    async def _kuma_hold_for_self_update(self, check_id: str, monitor_name: str, service_name: str,
                                         service, deferred: dict, since: str | None,
                                         event: dict | None = None) -> bool:
        spec = kuma_crash_monitor.SELF_UPDATING.get(service_name)
        if spec is None:
            return False
        started = datetime.fromisoformat(since) if since else datetime.now(timezone.utc)
        if datetime.now(timezone.utc) - started > timedelta(minutes=kuma_crash_monitor.SELF_UPDATE_MAX_WAIT_MINUTES):
            logger.warning("kuma crash monitor: %s still updating after %d min, restarting anyway",
                           monitor_name, kuma_crash_monitor.SELF_UPDATE_MAX_WAIT_MINUTES)
            return False
        container, programs = spec
        status = await asyncio.to_thread(
            executor.supervisor_status, service, container,
            identity_file=self.config.ssh_identity_file,
            mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
        )
        busy = kuma_crash_monitor.running_programs(status, programs)
        if not busy:
            return False
        if check_id not in deferred:
            logger.info("kuma crash monitor: %s is down while %s runs, not restarting",
                        monitor_name, ", ".join(busy))
        held = deferred.get(check_id) or {"service": service_name, "monitor": monitor_name,
                                          "since": started.isoformat()}
        if event is not None:
            held["event"] = json.loads(json.dumps(event, default=str))
        deferred[check_id] = held
        return True

    async def _kuma_auto_restart(self, check_id: str, monitor_name: str, service, ev: dict) -> None:
        pre_restart_logs = await asyncio.to_thread(
            executor.collect_recent_logs, service, lines=40,
            identity_file=self.config.ssh_identity_file,
            mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
        )
        detail = {**ev, "pre_restart_logs": pre_restart_logs[-4000:]}

        restart_ok, restart_detail = await asyncio.to_thread(
            executor.restart_containers, service,
            identity_file=self.config.ssh_identity_file,
            mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
        )
        if restart_ok:
            self._create_finding(
                "kuma_monitor", check_id, "warning",
                f"{monitor_name} was down -- auto-restarted: {restart_detail}", detail,
            )
            since = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
            recent_count = self.store.count_recent_findings("kuma_monitor", check_id, since)
            if recent_count >= 3:
                finding_id, trailer = self._create_finding(
                    "kuma_monitor", check_id, "critical",
                    f"{monitor_name} has crash-looped: auto-restarted {recent_count} times in the last 2h", detail,
                )
                await self._notify(
                    f"{monitor_name} has auto-restarted {recent_count} times in the last 2h -- "
                    f"the restarts are working but it keeps coming back, likely needs real "
                    f"investigation, not another restart:\n{trailer}"
                )
        else:
            finding_id, trailer = self._create_finding(
                "kuma_monitor", check_id, "critical",
                f"{monitor_name} is down, auto-restart failed: {restart_detail}", detail,
            )
            await self._notify(f"{monitor_name} is down, auto-restart failed:\n{trailer}")

    async def run_homeassistant_update_loop(self, interval_seconds: float) -> None:
        while True:
            await self._sleep_until_due("homeassistant_update", interval_seconds)
            if not (self.config.homeassistant_api_host and self.config.homeassistant_api_token):
                continue

            updates = await asyncio.to_thread(
                homeassistant.list_available_updates,
                self.config.homeassistant_api_host, self.config.homeassistant_api_token,
            )
            if updates is None:
                logger.warning("homeassistant update check: couldn't reach the API")
                continue
            if not updates:
                continue

            updates.sort(key=lambda u: "operating_system" in u.entity_id.lower())

            results = []
            for u in updates:
                is_os = "operating_system" in u.entity_id.lower()
                ok, detail = await asyncio.to_thread(
                    homeassistant.install_update,
                    self.config.homeassistant_api_host, self.config.homeassistant_api_token, u.entity_id,
                    backup=u.supports_backup,
                )
                if not ok:
                    results.append(f"{u.title}: FAILED to start -- {detail}")
                    self._create_finding(
                        "homeassistant_update", u.entity_id, "critical",
                        f"{u.title} update failed to start: {detail}",
                    )
                    continue

                if is_os:
                    await asyncio.sleep(15)
                    back_up = await asyncio.to_thread(
                        homeassistant.wait_for_api,
                        self.config.homeassistant_api_host, self.config.homeassistant_api_token,
                        600,
                    )
                    if not back_up:
                        results.append(f"{u.title}: install started but HA never came back")
                        self._create_finding(
                            "homeassistant_update", u.entity_id, "critical",
                            f"{u.title} update started but HA never came back online",
                        )
                        continue
                else:
                    await asyncio.to_thread(
                        homeassistant.wait_for_install,
                        self.config.homeassistant_api_host, self.config.homeassistant_api_token, u.entity_id,
                        600 if u.supports_backup else 300,
                        target_version=u.latest_version or None,
                    )

                final =await asyncio.to_thread(
                    homeassistant.get_entity_state,
                    self.config.homeassistant_api_host, self.config.homeassistant_api_token, u.entity_id,
                )
                final_version = (final or {}).get("attributes", {}).get("installed_version")
                if final_version == u.latest_version:
                    results.append(f"{u.title}: {u.installed_version} -> {u.latest_version}")
                else:
                    results.append(f"{u.title}: install triggered but not yet confirmed at {u.latest_version}")
                    self._create_finding(
                        "homeassistant_update", u.entity_id, "critical",
                        f"{u.title} update triggered but installed_version never reached {u.latest_version}",
                        {
                            "entity_id": u.entity_id,
                            "installed_version_before": u.installed_version,
                            "latest_version": u.latest_version,
                            "installed_version_after": final_version,
                        },
                    )

            await self._notify("Home Assistant auto-update:\n" + "\n".join(f"- {r}" for r in results))

    async def run_teamspeak_version_check_loop(self, interval_seconds: float) -> None:
        service = self.config.services.get("teamspeak")
        if service is None:
            return
        while True:
            await self._sleep_until_due("teamspeak_version_check", interval_seconds)

            installed = await asyncio.to_thread(teamspeak.get_installed_version, service.ssh_host)
            latest = await asyncio.to_thread(teamspeak.get_latest_version)
            if installed is None or latest is None:
                logger.warning(
                    "teamspeak version check failed: installed=%s latest=%s", installed, latest,
                )
                continue
            if installed == latest:
                continue

            entry_id = f"teamspeak_version:{installed}->{latest}"
            if self.store.get_by_diun_entry(entry_id) is not None:
                continue

            update_id = self.store.create_update(
                service_name="teamspeak", image="teamspeak-native",
                current_version=installed, new_version=latest,
                diun_entry_id=entry_id,
            )
            asyncio.create_task(self._research_and_stage(update_id, "teamspeak"))

    async def run_ollama_version_check_loop(self, interval_seconds: float) -> None:
        service = self.config.services.get("ollama")
        if service is None:
            return
        while True:
            await self._sleep_until_due("ollama_version_check", interval_seconds)

            installed = await asyncio.to_thread(
                ollama.get_installed_version,
                self.config.mgmt_host, self.config.mgmt_ssh_user,
                ollama_ssh_host=service.ssh_host, ollama_ssh_user=service.ssh_user,
                identity_file=self.config.ssh_identity_file,
            )
            latest = await asyncio.to_thread(ollama.get_latest_version)
            if installed is None or latest is None:
                logger.warning("ollama version check failed: installed=%s latest=%s", installed, latest)
                continue
            if installed == latest:
                continue

            entry_id = f"ollama_version:{installed}->{latest}"
            if self.store.get_by_diun_entry(entry_id) is not None:
                continue

            update_id = self.store.create_update(
                service_name="ollama", image="ollama-native",
                current_version=installed, new_version=latest,
                diun_entry_id=entry_id,
            )
            asyncio.create_task(self._research_and_stage(update_id, "ollama"))

    async def run_enshrouded_version_check_loop(self, interval_seconds: float) -> None:
        service = self.config.services.get("enshrouded")
        if service is None:
            return
        while True:
            await self._sleep_until_due("enshrouded_version_check", interval_seconds)

            current = await asyncio.to_thread(
                executor.read_remote_file, service, "/opt/enshrouded/enshrouded/current_version",
                identity_file=self.config.ssh_identity_file,
                mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
            )
            if current is None:
                logger.warning("enshrouded version check: couldn't read current_version")
                continue

            last = self.store.get_meta("enshrouded_last_version")
            self.store.set_meta("enshrouded_last_version", current)
            if last is not None and last != current:
                await self._notify(
                    f"Enshrouded self-updated (via its own UPDATE_CRON, no action needed): "
                    f"build {last} -> {current}"
                )

    async def run_caddy_rebuild_loop(self, interval_seconds: float) -> None:
        while True:
            await self._sleep_until_due("caddy_rebuild", interval_seconds)
            try:
                current_digest = await asyncio.to_thread(caddy_rebuild.get_upstream_digest)
            except Exception as exc:
                logger.warning("caddy rebuild: could not fetch upstream digest: %s", exc)
                continue

            for target in self.config.caddy_rebuild_targets:
                last_digest = self.store.get_caddy_build_digest(target.name)
                if last_digest is None:
                    self.store.set_caddy_build_digest(target.name, current_digest)
                    continue
                if last_digest == current_digest:
                    continue

                service = self.config.services.get(target.name)

                await self._notify(
                    f"Caddy rebuild: upstream caddy:builder changed -- rebuilding {target.name}'s "
                    f"reverse proxy automatically..."
                )
                if service is not None:
                    await self._begin_uptime_kuma_maintenance(service, "Caddy rebuild")
                try:
                    success, detail, rolled_back = await asyncio.to_thread(
                        caddy_rebuild.rebuild_target, target,
                        identity_file=self.config.ssh_identity_file,
                        portainer_token=self.config.portainer_token,
                    )
                finally:
                    if service is not None:
                        await self._end_uptime_kuma_maintenance(service)
                if success:
                    self.store.set_caddy_build_digest(target.name, current_digest)
                    flag = "rebuilt successfully" if not rolled_back else "rebuild failed, automatically reverted"
                    await self._notify(f"Caddy rebuild ({target.name}): {flag}.\n{detail}")
                else:
                    await self._notify(
                        f"Caddy rebuild ({target.name}) FAILED and needs a human now:\n{detail}"
                    )

    async def _run_investigation(
        self, update_id: int, record: UpdateRecord, *, auto_execute_repair: bool = False,
    ) -> None:
        service = self.config.services[record.service_name]
        supports_rollback = bool(service.compose_dir) and service.registry is None
        supports_mass_digest_rollback = (
            bool(service.compose_dir) and service.registry is not None
            and not service.portainer and not service.occ_container
        )
        supports_immich_digest_rollback = bool(service.portainer) and service.registry is not None
        supports_nextcloud_recovery = (
            bool(service.compose_dir) and service.registry is not None
            and bool(service.occ_container) and not service.portainer
        )
        ok, output = await asyncio.to_thread(
            investigate.trigger_investigation,
            self.config.mgmt_host, self.config.mgmt_ssh_user,
            service_name=record.service_name,
            current_version=record.current_version,
            new_version=record.new_version,
            error=record.error or "(no error recorded for this update)",
            self_ssh_host=self.config.self_ssh_host,
            self_ssh_user=self.config.self_ssh_user,
            self_install_dir=self.config.self_install_dir,
            supports_repair=bool(service.occ_container),
            supports_rollback=supports_rollback,
            supports_mass_digest_rollback=supports_mass_digest_rollback,
            supports_immich_digest_rollback=supports_immich_digest_rollback,
            supports_nextcloud_recovery=supports_nextcloud_recovery,
            identity_file=self.config.ssh_identity_file,
        )
        if not ok:
            await self._notify(f"Update #{update_id}: investigation failed to run -- {output.strip()}")
            return

        commands: list[str] = []
        repair_note = ""
        if service.occ_container:
            commands = _parse_repair_plan(output)
            if commands:
                self.store.set_repair_plan(update_id, commands)
                plan_lines = "\n".join(f"  $ occ {c}" for c in commands)
                repair_note = (
                    f"\n\nProposed repair plan -- attempting it automatically:\n{plan_lines}"
                    if auto_execute_repair else
                    f"\n\nProposed repair plan (run `!repair {update_id}` to execute exactly this, "
                    f"nothing else):\n{plan_lines}"
                )
        await self._notify(f"Update #{update_id} investigation report:\n{output.strip()}{repair_note}")

        if auto_execute_repair:
            if commands:
                await self._attempt_repair_and_verify(update_id, record, commands)
            elif record.kind == "container" and supports_rollback and _parse_rollback_safety(output):
                await self._attempt_rollback_and_verify(update_id, record)
            elif record.kind == "container" and supports_rollback:
                await self._notify(
                    f"Update #{update_id}: {record.service_name} could be rolled back, but the "
                    f"investigation couldn't confirm it's safe (possible database migration) -- "
                    f"needs a manual look. `!rollback {update_id}` if you're confident it's safe anyway."
                )
            elif record.kind == "container" and supports_mass_digest_rollback:
                last_digest = self.store.get_last_known_digest(record.service_name, record.image)
                verdict = _parse_mass_recovery(output)
                if not last_digest:
                    await self._notify(
                        f"Update #{update_id}: no prior successful digest is on record for "
                        f"{record.image} yet -- needs a manual look."
                    )
                elif verdict == "redeploy-only":
                    await self._attempt_mass_redeploy_and_verify(update_id, record, last_digest)
                elif verdict == "restore-and-redeploy":
                    await self._attempt_mass_restore_and_redeploy_and_verify(update_id, record, last_digest)
                elif verdict == "needs-vm-restore":
                    await self._notify(
                        f"Update #{update_id}: the investigation found this needs a full VM-level "
                        f"restore -- that stays a human call (Proxmox/PBS), not something this "
                        f"pipeline attempts. See the investigation report above for why."
                    )
                else:
                    await self._notify(
                        f"Update #{update_id}: no safe automated fix is available for "
                        f"{record.service_name} yet -- needs a manual look."
                    )
            elif record.kind == "container" and supports_immich_digest_rollback:
                pins, missing = [], []
                for tracked_image in service.images:
                    digest = self.store.get_last_known_digest(record.service_name, tracked_image)
                    (pins.append((tracked_image, digest)) if digest else missing.append(tracked_image))
                verdict = _parse_immich_recovery(output)
                if missing:
                    await self._notify(
                        f"Update #{update_id}: no prior successful digest on record yet for "
                        f"{', '.join(missing)} -- needs a manual look."
                    )
                elif verdict == "redeploy-safe":
                    await self._attempt_immich_redeploy_and_verify(update_id, record, pins)
                elif verdict == "restore-db-and-redeploy":
                    await self._attempt_immich_db_restore_and_verify(update_id, record, pins)
                else:
                    await self._notify(
                        f"Update #{update_id}: no safe automated fix is available for "
                        f"{record.service_name} yet -- needs a manual look."
                    )
            elif record.kind == "container" and supports_nextcloud_recovery:
                last_digest = self.store.get_last_known_digest(record.service_name, record.image)
                verdict = _parse_nextcloud_recovery(output)
                if not last_digest:
                    await self._notify(
                        f"Update #{update_id}: no prior successful digest is on record for "
                        f"{record.image} yet -- needs a manual look."
                    )
                elif verdict == "redeploy-safe":
                    await self._attempt_nextcloud_redeploy_and_verify(update_id, record, last_digest)
                elif verdict == "restore-db-and-redeploy":
                    await self._attempt_nextcloud_db_restore_and_verify(update_id, record, last_digest)
                else:
                    await self._notify(
                        f"Update #{update_id}: no safe automated fix is available for "
                        f"{record.service_name} yet -- needs a manual look."
                    )
            elif record.kind == "container" and record.service_name == "discourse":
                verdict = _parse_discourse_recovery(output)
                if verdict == "restore-recommended":
                    ok_list, backups, error = await asyncio.to_thread(
                        discourse_restore.list_backups,
                        self.config.mgmt_host, self.config.mgmt_ssh_user,
                        identity_file=self.config.ssh_identity_file,
                    )
                    if not ok_list or not backups:
                        await self._notify(
                            f"Update #{update_id}: investigation recommends a restore, but the backup "
                            f"archive couldn't be checked ({error or 'no backups found'}) -- "
                            f"needs a manual look. `!discourse-backups` to check by hand."
                        )
                    else:
                        await self.handle_discourse_restore(backups[0]["filename"])
                else:
                    await self._notify(
                        f"Update #{update_id}: no safe automated fix is available for "
                        f"{record.service_name} yet -- but a tested restore mechanism does exist: "
                        f"`!discourse-backups` to see what's recoverable, `!discourse-restore <file>` "
                        f"to stage one."
                    )
            else:
                await self._notify(
                    f"Update #{update_id}: no safe automated fix is available for "
                    f"{record.service_name} yet -- needs a manual look "
                    f"(`!repair` isn't wired up for this service)."
                )

    async def _attempt_rollback_and_verify(self, update_id: int, record: UpdateRecord) -> None:
        service = self.config.services[record.service_name]
        await self._notify(f"Update #{update_id}: attempting an automatic rollback to the pre-update version...")
        ok, detail = await asyncio.to_thread(
            executor.rollback_compose_file, service, update_id, identity_file=self.config.ssh_identity_file,
        )
        if not ok:
            await self._notify(
                f"Update #{update_id}: automatic rollback failed -- stepping back for a human.\n{detail}\n"
                f"`!rollback {update_id}` to retry by hand, or `!investigate {update_id}` to look deeper."
            )
            return

        healthy, log_detail = await asyncio.to_thread(
            executor.watch_logs, service,
            duration_seconds=self.config.log_watch_duration,
            poll_interval=self.config.log_watch_poll_interval,
            identity_file=self.config.ssh_identity_file,
            mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
        )
        if healthy:
            await self._notify(
                f"Update #{update_id}: automatic rollback completed, {record.service_name} is back on "
                f"{record.current_version} and looks healthy.\n{detail}"
            )
        else:
            await self._notify(
                f"Update #{update_id}: rolled back, but {record.service_name} still doesn't look "
                f"healthy ({log_detail}) -- stopping here rather than guessing further. "
                f"`!investigate {update_id}` for another look.\n{detail}"
            )

    async def _attempt_mass_redeploy_and_verify(
        self, update_id: int, record: UpdateRecord, digest: str,
    ) -> None:
        service = self.config.services[record.service_name]
        await self._notify(f"Update #{update_id}: redeploying {record.service_name} to its last known-good image...")
        ok, detail = await asyncio.to_thread(
            executor.redeploy_pinned_digest, service, record.image, digest,
            identity_file=self.config.ssh_identity_file,
        )
        if not ok:
            await self._notify(f"Update #{update_id}: automatic redeploy failed -- stepping back for a human.\n{detail}")
            return
        healthy, log_detail = await asyncio.to_thread(
            executor.watch_logs, service,
            duration_seconds=self.config.log_watch_duration,
            poll_interval=self.config.log_watch_poll_interval,
            identity_file=self.config.ssh_identity_file,
            mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
        )
        note = "looks healthy again" if healthy else f"still doesn't look healthy ({log_detail})"
        await self._notify(
            f"Update #{update_id}: redeployed to the last known-good image, {record.service_name} {note}.\n{detail}"
            + ("" if healthy else f"\n`!investigate {update_id}` for another look.")
        )

    async def _attempt_mass_restore_and_redeploy_and_verify(
        self, update_id: int, record: UpdateRecord, digest: str,
    ) -> None:
        service = self.config.services[record.service_name]
        await self._notify(
            f"Update #{update_id}: restoring {record.service_name}'s pre-migration library backup "
            f"and redeploying its last known-good image..."
        )
        ok, detail = await asyncio.to_thread(
            executor.restore_library_backup_and_redeploy, service, record.image, digest,
            identity_file=self.config.ssh_identity_file,
        )
        if not ok:
            await self._notify(
                f"Update #{update_id}: automatic restore-and-redeploy failed -- stepping back for a "
                f"human (the container may currently be stopped, check manually).\n{detail}"
            )
            return
        healthy, log_detail = await asyncio.to_thread(
            executor.watch_logs, service,
            duration_seconds=self.config.log_watch_duration,
            poll_interval=self.config.log_watch_poll_interval,
            identity_file=self.config.ssh_identity_file,
            mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
        )
        note = "looks healthy again" if healthy else f"still doesn't look healthy ({log_detail})"
        await self._notify(
            f"Update #{update_id}: restored the pre-migration library backup and redeployed the "
            f"last known-good image, {record.service_name} {note}.\n{detail}"
            + ("" if healthy else f"\n`!investigate {update_id}` for another look -- a full VM-level "
                                  f"restore may be the next real option if this doesn't resolve it.")
        )

    async def _attempt_immich_redeploy_and_verify(
        self, update_id: int, record: UpdateRecord, pins: list[tuple[str, str]],
    ) -> None:
        service = self.config.services[record.service_name]
        await self._notify(f"Update #{update_id}: redeploying {record.service_name} to its last known-good images...")
        ok, detail = await asyncio.to_thread(
            portainer.redeploy_pinned_digests, service.portainer, self.config.portainer_token, pins,
        )
        if not ok:
            await self._notify(f"Update #{update_id}: automatic redeploy failed -- stepping back for a human.\n{detail}")
            return
        healthy, log_detail = await asyncio.to_thread(
            executor.watch_logs, service,
            duration_seconds=self.config.log_watch_duration,
            poll_interval=self.config.log_watch_poll_interval,
            identity_file=self.config.ssh_identity_file,
            mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
        )
        note = "looks healthy again" if healthy else f"still doesn't look healthy ({log_detail})"
        await self._notify(
            f"Update #{update_id}: redeployed to the last known-good images, {record.service_name} {note}.\n{detail}"
            + ("" if healthy else f"\n`!investigate {update_id}` for another look.")
        )

    async def _attempt_immich_db_restore_and_verify(
        self, update_id: int, record: UpdateRecord, pins: list[tuple[str, str]],
    ) -> None:
        service = self.config.services[record.service_name]
        await self._notify(
            f"Update #{update_id}: restoring {record.service_name}'s database from its most recent "
            f"backup-database dump and redeploying its last known-good images..."
        )
        ok, detail = await asyncio.to_thread(
            executor.restore_immich_database, service, identity_file=self.config.ssh_identity_file,
        )
        if not ok:
            await self._notify(
                f"Update #{update_id}: automatic database restore failed -- stepping back for a human "
                f"(app containers may currently be stopped, check manually).\n{detail}"
            )
            return
        redeploy_ok, redeploy_detail = await asyncio.to_thread(
            portainer.redeploy_pinned_digests, service.portainer, self.config.portainer_token, pins,
        )
        if not redeploy_ok:
            await self._notify(
                f"Update #{update_id}: database restored ({detail}), but redeploying the last "
                f"known-good images failed -- stepping back for a human.\n{redeploy_detail}"
            )
            return
        healthy, log_detail = await asyncio.to_thread(
            executor.watch_logs, service,
            duration_seconds=self.config.log_watch_duration,
            poll_interval=self.config.log_watch_poll_interval,
            identity_file=self.config.ssh_identity_file,
            mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
        )
        note = "looks healthy again" if healthy else f"still doesn't look healthy ({log_detail})"
        await self._notify(
            f"Update #{update_id}: restored the database and redeployed the last known-good images, "
            f"{record.service_name} {note}.\n{detail}\n{redeploy_detail}"
            + ("" if healthy else f"\n`!investigate {update_id}` for another look.")
        )

    async def _attempt_nextcloud_redeploy_and_verify(
        self, update_id: int, record: UpdateRecord, digest: str,
    ) -> None:
        service = self.config.services[record.service_name]
        await self._notify(f"Update #{update_id}: redeploying {record.service_name} to its last known-good image...")
        ok, detail = await asyncio.to_thread(
            executor.redeploy_pinned_digest, service, record.image, digest,
            identity_file=self.config.ssh_identity_file,
        )
        if not ok:
            await self._notify(f"Update #{update_id}: automatic redeploy failed -- stepping back for a human.\n{detail}")
            return
        healthy, log_detail = await asyncio.to_thread(
            executor.watch_logs, service,
            duration_seconds=self.config.log_watch_duration,
            poll_interval=self.config.log_watch_poll_interval,
            identity_file=self.config.ssh_identity_file,
            mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
        )
        note = "looks healthy again" if healthy else f"still doesn't look healthy ({log_detail})"
        await self._notify(
            f"Update #{update_id}: redeployed to the last known-good image, {record.service_name} {note}.\n{detail}"
            + ("" if healthy else f"\n`!investigate {update_id}` for another look.")
        )

    async def _attempt_nextcloud_db_restore_and_verify(
        self, update_id: int, record: UpdateRecord, digest: str,
    ) -> None:
        service = self.config.services[record.service_name]
        await self._notify(
            f"Update #{update_id}: restoring {record.service_name}'s database from its most recent "
            f"backup and redeploying its last known-good image..."
        )
        ok, detail = await asyncio.to_thread(
            executor.restore_nextcloud_database, service, identity_file=self.config.ssh_identity_file,
        )
        if not ok:
            await self._notify(
                f"Update #{update_id}: automatic database restore failed -- stepping back for a human "
                f"(app containers may currently be stopped, check manually).\n{detail}"
            )
            return
        redeploy_ok, redeploy_detail = await asyncio.to_thread(
            executor.redeploy_pinned_digest, service, record.image, digest,
            identity_file=self.config.ssh_identity_file,
        )
        if not redeploy_ok:
            await self._notify(
                f"Update #{update_id}: database restored ({detail}), but redeploying the last "
                f"known-good image failed -- stepping back for a human.\n{redeploy_detail}"
            )
            return
        healthy, log_detail = await asyncio.to_thread(
            executor.watch_logs, service,
            duration_seconds=self.config.log_watch_duration,
            poll_interval=self.config.log_watch_poll_interval,
            identity_file=self.config.ssh_identity_file,
            mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
        )
        note = "looks healthy again" if healthy else f"still doesn't look healthy ({log_detail})"
        await self._notify(
            f"Update #{update_id}: restored the database and redeployed the last known-good image, "
            f"{record.service_name} {note}.\n{detail}\n{redeploy_detail}"
            + ("" if healthy else f"\n`!investigate {update_id}` for another look.")
        )

    async def _attempt_repair_and_verify(
        self, update_id: int, record: UpdateRecord, commands: list[str],
    ) -> None:
        service = self.config.services[record.service_name]
        await self._notify(f"Update #{update_id}: attempting the proposed repair plan automatically...")
        ok, output_lines = await asyncio.to_thread(
            executor.run_repair_plan, service, commands, identity_file=self.config.ssh_identity_file,
        )
        joined = "\n\n".join(output_lines)
        if not ok:
            await self._notify(
                f"Update #{update_id}: automated repair attempt STOPPED (a command failed) -- "
                f"stepping back for a human.\n{joined}\n`!repair {update_id}` to retry by hand, "
                f"or `!investigate {update_id}` to look deeper."
            )
            return

        healthy, detail = await asyncio.to_thread(
            executor.watch_logs, service,
            duration_seconds=self.config.log_watch_duration,
            poll_interval=self.config.log_watch_poll_interval,
            identity_file=self.config.ssh_identity_file,
            mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
        )
        if healthy:
            await self._notify(
                f"Update #{update_id}: automated repair completed, {record.service_name} looks "
                f"healthy again.\n{joined}"
            )
        else:
            await self._notify(
                f"Update #{update_id}: ran the repair plan, but {record.service_name} still doesn't "
                f"look healthy ({detail}) -- stopping here rather than guessing further. Automated "
                f"snapshot/VM-restore isn't built yet; `!rollback {update_id}` if this is a "
                f"pinned-tag Compose service, otherwise a manual PBS/Kopia restore.\n{joined}"
            )

    async def _auto_investigate_and_repair(self, update_id: int) -> None:
        if not self.config.mgmt_host:
            return
        record = self.store.get(update_id)
        if record is None:
            return
        await self._run_investigation(update_id, record, auto_execute_repair=True)


    def _find_pending_app_update(self, service_name: str) -> UpdateRecord | None:
        candidates = [
            r for r in self.store.list_by_stage(Stage.STAGED_PENDING_APPROVAL)
            if r.service_name == service_name
        ]
        return max(candidates, key=lambda r: r.id) if candidates else None

    async def _auto_approve_staged_update_if_eligible(
        self, service_name: str, *, max_risk_levels: tuple[str, ...], notify_prefix: str,
    ) -> tuple[str, UpdateRecord | None]:
        pending = self._find_pending_app_update(service_name)
        if pending is None:
            return "none", None
        if pending.risk_level not in max_risk_levels or pending.breaking_changes:
            return "needs_human", pending

        await self._notify(
            f"{notify_prefix}: auto-approving staged update #{pending.id} "
            f"({pending.current_version} -> {pending.new_version}, {pending.risk_level} risk)..."
        )
        self._pipelines_started.add(pending.id)
        self.store.set_approved(pending.id, "auto")
        self.store.set_stage(pending.id, Stage.APPROVED)
        await self._run_pipeline(pending.id, service_name, non_interactive_backup=True)
        finished = self.store.get(pending.id)
        if finished.stage != Stage.DONE_SUCCESS:
            raise RuntimeError(
                f"auto-approved update #{pending.id} did not complete successfully "
                f"(stage: {finished.stage.value})"
            )
        return "ran", finished

    async def _send_maintenance_summary_and_request_approval(
        self, service_names: list[str], window_start: datetime,
    ) -> None:
        lines = [
            f"Scheduled maintenance window opens {window_start.strftime('%a %Y-%m-%d %H:%M')} -- "
            f"here's what's pending:"
        ]
        for service_name in service_names:
            service = self.config.services.get(service_name)
            if service is None:
                lines.append(f"- {service_name}: not a known service (check config)")
                continue
            packages = await asyncio.to_thread(
                executor.list_upgradable_packages, service, identity_file=self.config.ssh_identity_file,
                mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
            )
            pending_packages = [
                line for line in packages.splitlines()
                if line.strip() and not line.lower().startswith("listing")
            ]
            reboot_pending = await asyncio.to_thread(
                executor.reboot_required, service, identity_file=self.config.ssh_identity_file,
                mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
            )
            staged = self._find_pending_app_update(service_name)
            if staged is None:
                staged_note = "no app update staged"
            elif staged.risk_level == "low" and not staged.breaking_changes:
                staged_note = (
                    f"app update staged ({staged.current_version} -> {staged.new_version}, "
                    f"low risk -- will auto-run)"
                )
            else:
                staged_note = (
                    f"app update #{staged.id} staged ({staged.current_version} -> {staged.new_version}, "
                    f"risk: {staged.risk_level}) -- still needs your own `!approve {staged.id}`, won't auto-run"
                )
            lines.append(
                f"- {service_name}: {len(pending_packages)} OS package(s) pending, "
                f"reboot {'REQUIRED' if reboot_pending else 'not needed'}, {staged_note}"
            )
        cfg = self.config.scheduled_maintenance
        lines.append(
            f"\nReply `!confirm-maintenance` to proceed, or `!skip-maintenance` to skip this week "
            f"(a reminder repeats every {cfg.reminder_interval_hours}h until the window opens; "
            f"no reply by then also skips it)."
        )
        await self._notify("\n".join(lines))

    async def handle_confirm_maintenance(self) -> None:
        if self.store.get_meta("sched_maint_approval") != "pending":
            await self._notify("No scheduled maintenance is currently awaiting approval.")
            return
        self.store.set_meta("sched_maint_approval", "approved")
        await self._notify("Scheduled maintenance approved -- will run when the window opens.")

    async def handle_skip_maintenance(self) -> None:
        if self.store.get_meta("sched_maint_approval") not in ("pending", "approved"):
            await self._notify("No scheduled maintenance is currently scheduled to skip.")
            return
        self.store.set_meta("sched_maint_approval", "declined")
        await self._notify("This week's scheduled maintenance has been skipped.")

    async def handle_maintenance_prep(self) -> None:
        if self.store.get_meta(_CLUSTER_MAINT_AWAITING_RESTORE_KEY) == "true":
            await self._notify(
                "A previous !maintenance-prep is still awaiting its restore "
                "(this bot hasn't gone through a startup since) -- not starting a second one."
            )
            return

        vms = await asyncio.to_thread(cluster_maintenance.compute_in_scope_vms, self.proxmox)
        if not vms:
            await self._notify("Nothing currently running is in scope -- nothing to do.")
            return

        backup_warnings = await asyncio.to_thread(
            cluster_maintenance.check_backup_freshness, self.pbs, self.config.pbs_datastore, vms,
        )

        self.store.set_meta(_CLUSTER_MAINT_PENDING_KEY, json.dumps(vms))

        vm_list_str = ", ".join(f"{v['name']} ({v['vmid']})" for v in vms)
        await self._notify(f"Shutting down {len(vms)} VM/CT(s) for maintenance prep: {vm_list_str}...")

        vmid_to_service = {s.vmid: s for s in self.config.services.values()}
        for vm in vms:
            service = vmid_to_service.get(vm["vmid"])
            if service is not None:
                await self._begin_uptime_kuma_maintenance(service, "cluster maintenance prep")

        result = await asyncio.to_thread(cluster_maintenance.shutdown_all, self.proxmox, vms)
        self.store.set_meta(_CLUSTER_MAINT_AWAITING_RESTORE_KEY, "true")

        lines = [f"Maintenance prep done: {len(result['stopped'])}/{len(vms)} shut down cleanly."]
        if result["still_running"]:
            stuck_str = ", ".join(f"{v['name']} ({v['vmid']})" for v in result["still_running"])
            lines.append(
                f"Still running (did not shut down within the timeout -- NOT forced, left running): {stuck_str}"
            )
        if result["errors"]:
            lines.append("Errors: " + "; ".join(result["errors"]))
        if backup_warnings:
            lines.append("Backup-age warnings (informational only): " + "; ".join(backup_warnings))
        lines.append(
            "Safe to shut down rbd-ns1/rbd-ns2/rbd-mgmt1 and this bot's own VM yourself now, "
            "then proceed with the Proxmox host / DSM maintenance. Restore is automatic on this "
            "bot's next startup, once rbd-ns1/rbd-ns2/rbd-mgmt1 are confirmed healthy."
        )
        await self._notify("\n".join(lines))

    async def handle_maintenance(self, service_name: str) -> None:
        if service_name not in self.config.services:
            await self._notify(
                f"No service named {service_name!r} -- known services: "
                f"{', '.join(self.config.services)}"
            )
            return
        await self._run_scheduled_maintenance_for_service(service_name)

    async def _run_scheduled_maintenance_for_service(self, service_name: str) -> None:
        service = self.config.services[service_name]
        cfg = self.config.scheduled_maintenance

        update_id = self.store.create_update(
            service_name=service_name,
            image="scheduled-maintenance",
            current_version="n/a",
            new_version="n/a",
            diun_entry_id=f"sched_maint:{service_name}:{int(time.time())}",
            kind="scheduled_maintenance",
        )
        await self._notify(f"Scheduled maintenance #{update_id}: starting for {service_name}...")
        if await self._refuse_job_if_relay_agent_empty(update_id, service, "Scheduled maintenance"):
            return

        try:
            await self._begin_uptime_kuma_maintenance(service, "scheduled maintenance")

            await self._run_proxmox_backup_gate(
                update_id, service.vmid, label=service_name,
                interactive=False, auto_skip_threshold_hours=cfg.backup_max_age_hours,
            )

            self.store.set_stage(update_id, Stage.UPDATING)
            packages = await asyncio.to_thread(
                executor.list_upgradable_packages, service, identity_file=self.config.ssh_identity_file,
                mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
            )
            pending_packages = [
                line for line in packages.splitlines()
                if line.strip() and not line.lower().startswith("listing")
            ]
            if pending_packages:
                await self._notify(
                    f"Scheduled maintenance #{update_id}: applying {len(pending_packages)} "
                    f"OS package update(s)..."
                )
                ok, output = await asyncio.to_thread(
                    executor.apply_os_patch, service, identity_file=self.config.ssh_identity_file,
                    mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
                )
                if not ok:
                    raise RuntimeError(f"OS patch failed: {output}")
            else:
                await self._notify(f"Scheduled maintenance #{update_id}: no OS packages pending.")

            if await asyncio.to_thread(
                executor.reboot_required, service, identity_file=self.config.ssh_identity_file,
                mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
            ):
                sessions = await asyncio.to_thread(
                    executor.active_sessions, service, identity_file=self.config.ssh_identity_file,
                    mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
                )
                if sessions.strip() != "(no active sessions)":
                    await self._notify(
                        f"Scheduled maintenance #{update_id}: a reboot is required, but {service_name} "
                        f"has an active logged-in session right now -- skipping the reboot this run "
                        f"rather than rebooting out from under someone. Sessions:\n{sessions}\n"
                        f"Run `!reboot {service_name}` by hand once it's clear."
                    )
                else:
                    ok, detail = await self._reboot_and_verify(update_id, service_name)
                    if not ok:
                        raise RuntimeError(detail)
                    await self._notify(f"Scheduled maintenance #{update_id}: reboot complete. {detail}")
            else:
                await self._notify(f"Scheduled maintenance #{update_id}: no reboot required.")

            status, pending = await self._auto_approve_staged_update_if_eligible(
                service_name, max_risk_levels=("low",),
                notify_prefix=f"Scheduled maintenance #{update_id}",
            )
            if status == "none":
                await self._notify(f"Scheduled maintenance #{update_id}: no app update staged for {service_name}.")
            elif status == "needs_human":
                await self._notify(
                    f"Scheduled maintenance #{update_id}: {service_name} has a staged update "
                    f"#{pending.id} (risk: {pending.risk_level}) that still needs a human "
                    f"`!approve {pending.id}` -- not auto-running it."
                )

            self.store.set_stage(update_id, Stage.DONE_SUCCESS, "scheduled maintenance completed")
            await self._notify(f"Scheduled maintenance #{update_id} ({service_name}): all clear.")
        except Exception as exc:
            logger.exception("scheduled maintenance failed for %s (update %s)", service_name, update_id)
            self.store.set_error(update_id, str(exc))
            self.store.set_stage(update_id, Stage.DONE_FAILED, str(exc))
            await self._notify(
                f"Scheduled maintenance #{update_id} ({service_name}) FAILED: {exc}\n"
                f"Stopping this service's maintenance here -- investigating automatically now, and "
                f"attempting a fix if a safe one is proposed. `!rollback {update_id}` is still "
                f"available if a compose-based app update was the failing stage."
            )
            asyncio.create_task(self._auto_investigate_and_repair(update_id))
        finally:
            await self._end_uptime_kuma_maintenance(service)

    async def _run_kernel_cve_remediation(self, service_name: str, finding_id: int) -> None:
        service = self.config.services[service_name]
        update_id = self.store.create_update(
            service_name=service_name,
            image="kernel-cve-patch",
            current_version="n/a",
            new_version="n/a",
            diun_entry_id=f"kernel_cve:{service_name}:{int(time.time())}",
            kind="kernel_cve_patch",
        )
        if await self._refuse_job_if_relay_agent_empty(update_id, service, "Kernel CVE patch"):
            return
        try:
            await self._begin_uptime_kuma_maintenance(service, "kernel CVE patch")

            await self._run_proxmox_backup_gate(
                update_id, service.vmid, label=service_name,
                interactive=False, auto_skip_threshold_hours=self.config.kernel_cve_watch.backup_max_age_hours,
            )

            self.store.set_stage(update_id, Stage.UPDATING)
            await self._notify(f"Kernel CVE patch #{update_id}: applying OS packages on {service_name}...")
            ok, output = await asyncio.to_thread(
                executor.apply_os_patch, service, identity_file=self.config.ssh_identity_file,
                mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
            )
            if not ok:
                raise RuntimeError(f"apt-get upgrade failed: {output}")

            if not await asyncio.to_thread(
                executor.reboot_required, service, identity_file=self.config.ssh_identity_file,
                mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
            ):
                self.store.set_stage(update_id, Stage.DONE_SUCCESS, "kernel patch applied, no reboot needed")
                await self._notify(f"Kernel CVE patch #{update_id} ({service_name}): patched, no reboot required.")
                return

            if service_name == "wg-vpn":
                self.store.set_stage(update_id, Stage.DONE_SUCCESS, "patched, reboot deliberately left manual")
                await self._notify(
                    f"Kernel CVE patch #{update_id} ({service_name}): patched, reboot required -- "
                    f"rebooting wg-vpn interrupts remote access, so this one's deliberately NOT "
                    f"automatic. Run `!reboot wg-vpn` yourself when convenient; finding #{finding_id} "
                    f"stays open until then."
                )
                return

            sessions = await asyncio.to_thread(
                executor.active_sessions, service, identity_file=self.config.ssh_identity_file,
                mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
            )
            if sessions.strip() != "(no active sessions)":
                self.store.set_stage(update_id, Stage.DONE_SUCCESS, "patched, reboot deferred (active session)")
                await self._notify(
                    f"Kernel CVE patch #{update_id} ({service_name}): patched, but {service_name} has an "
                    f"active logged-in session right now -- skipping the reboot rather than forcing it. "
                    f"Sessions:\n{sessions}\nRun `!reboot {service_name}` once it's clear; "
                    f"finding #{finding_id} stays open until then."
                )
                return

            ok, detail = await self._reboot_and_verify(update_id, service_name)
            if not ok:
                raise RuntimeError(detail)
            self.store.set_stage(update_id, Stage.DONE_SUCCESS, "kernel CVE patch + reboot completed")
            await self._notify(f"Kernel CVE patch #{update_id} ({service_name}): reboot complete. {detail}")
        except Exception as exc:
            logger.exception("kernel CVE remediation failed for %s (update %s)", service_name, update_id)
            self.store.set_error(update_id, str(exc))
            self.store.set_stage(update_id, Stage.DONE_FAILED, str(exc))
            await self._notify(
                f"Kernel CVE patch #{update_id} ({service_name}) FAILED: {exc}\n"
                f"Finding #{finding_id} stays open -- investigating automatically now, and "
                f"attempting a fix if a safe one is proposed."
            )
            asyncio.create_task(self._auto_investigate_and_repair(update_id))
        finally:
            await self._end_uptime_kuma_maintenance(service)

    async def run_scheduled_maintenance_loop(self, poll_interval_seconds: float) -> None:
        cfg = self.config.scheduled_maintenance
        while True:
            await asyncio.sleep(poll_interval_seconds)
            now = datetime.now(ZoneInfo(self.config.local_timezone))
            window_start = _next_window_start(now, cfg.weekday, cfg.start_hour, cfg.window_hours)
            window_end = window_start + timedelta(hours=cfg.window_hours)
            window_week = f"{window_start.isocalendar()[0]}-W{window_start.isocalendar()[1]:02d}"

            if self.store.get_meta("sched_maint_week") != window_week:
                self.store.set_meta("sched_maint_week", window_week)
                self.store.set_meta("sched_maint_approval", "")
                self.store.set_meta("sched_maint_last_reminder_ts", "")

            summary_due_at = window_start - timedelta(hours=cfg.summary_hours_before)
            if now < summary_due_at:
                continue

            approval = self.store.get_meta("sched_maint_approval") or ""

            if approval == "":
                await self._send_maintenance_summary_and_request_approval(cfg.services, window_start)
                self.store.set_meta("sched_maint_approval", "pending")
                self.store.set_meta("sched_maint_last_reminder_ts", now.isoformat())
                continue

            if approval == "pending":
                if now >= window_start:
                    await self._notify(
                        "Scheduled maintenance: no approval received before the window opened -- "
                        "skipping this week's run."
                    )
                    self.store.set_meta("sched_maint_approval", "declined")
                    continue
                last_reminder_raw = self.store.get_meta("sched_maint_last_reminder_ts")
                last_reminder = datetime.fromisoformat(last_reminder_raw) if last_reminder_raw else now
                if (now - last_reminder).total_seconds() / 3600 < cfg.reminder_interval_hours:
                    continue
                await self._notify(
                    f"Reminder: scheduled maintenance is still waiting on `!confirm-maintenance` "
                    f"(window opens {window_start.strftime('%a %H:%M')}), or `!skip-maintenance` "
                    f"to decline this week."
                )
                self.store.set_meta("sched_maint_last_reminder_ts", now.isoformat())
                continue

            if approval == "declined":
                continue

            if not (window_start <= now < window_end):
                continue

            ok, fg_data, _ = await asyncio.to_thread(
                firewall_traffic.trigger_firewall_traffic_collect,
                self.config.mgmt_host, self.config.mgmt_ssh_user,
                fortigate_api_host=self.config.fortigate_api_host,
                fortigate_token_file=self.config.fortigate_token_file,
                identity_file=self.config.ssh_identity_file,
            )
            if ok and _total_exposed_sessions(fg_data) > cfg.fg_session_threshold:
                continue

            for service_name in cfg.services:
                if self.store.get_meta(f"sched_maint_last_run:{service_name}") == window_week:
                    continue
                await self._run_scheduled_maintenance_for_service(service_name)
                self.store.set_meta(f"sched_maint_last_run:{service_name}", window_week)

    async def run_nightly_auto_apply_loop(self, poll_interval_seconds: float) -> None:
        cfg = self.config.nightly_auto_apply
        while True:
            await asyncio.sleep(poll_interval_seconds)
            if not (0 <= cfg.start_hour <= 23):
                logger.warning(
                    "nightly_auto_apply.enabled is true but start_hour=%s is out of range -- "
                    "skipping until config.yaml sets a real 0-23 hour", cfg.start_hour,
                )
                continue
            now = datetime.now(ZoneInfo(self.config.local_timezone))
            window_start = _next_daily_window_start(now, cfg.start_hour, cfg.window_hours)
            window_end = window_start + timedelta(hours=cfg.window_hours)
            if not (window_start <= now < window_end):
                continue

            ok, fg_data, _ = await asyncio.to_thread(
                firewall_traffic.trigger_firewall_traffic_collect,
                self.config.mgmt_host, self.config.mgmt_ssh_user,
                fortigate_api_host=self.config.fortigate_api_host,
                fortigate_token_file=self.config.fortigate_token_file,
                identity_file=self.config.ssh_identity_file,
            )
            if ok and _total_exposed_sessions(fg_data) > cfg.fg_session_threshold:
                continue

            night_key = window_start.date().isoformat()
            for service_name in cfg.services:
                meta_key = f"nightly_auto_apply_last_run:{service_name}"
                if self.store.get_meta(meta_key) == night_key:
                    continue
                try:
                    await self._auto_approve_staged_update_if_eligible(
                        service_name, max_risk_levels=("low",),
                        notify_prefix=f"Nightly auto-apply ({service_name})",
                    )
                except Exception:
                    logger.exception("nightly auto-apply failed for %s", service_name)
                finally:
                    self.store.set_meta(meta_key, night_key)

            for service_name in self.config.services:
                pending_key = f"emergency_patch_pending:{service_name}"
                finding_id_raw = self.store.get_meta(pending_key)
                if not finding_id_raw:
                    continue
                finding_id = int(finding_id_raw)
                try:
                    status, _ = await self._auto_approve_staged_update_if_eligible(
                        service_name, max_risk_levels=("low",),
                        notify_prefix=f"Emergency patch, deferred ({service_name})",
                    )
                except Exception:
                    logger.exception("deferred emergency patch failed for %s", service_name)
                    continue
                self.store.set_meta(pending_key, "")
                if status == "ran":
                    await self.handle_restore_access(finding_id)

    async def run_approval_poll_loop(self, interval: float = 5.0) -> None:
        while True:
            for record in self.store.list_by_stage(Stage.APPROVED):
                if record.id in self._pipelines_started:
                    continue
                self._pipelines_started.add(record.id)
                asyncio.create_task(self._run_pipeline(record.id, record.service_name))
            await asyncio.sleep(interval)

    async def _is_low_impact_now(self, service, service_name: str) -> bool:
        cfg = self.config.nightly_auto_apply
        if cfg.enabled and 0 <= cfg.start_hour <= 23:
            now = datetime.now(ZoneInfo(self.config.local_timezone))
            window_start = _next_daily_window_start(now, cfg.start_hour, cfg.window_hours)
            window_end = window_start + timedelta(hours=cfg.window_hours)
            if window_start <= now < window_end:
                return True
        sessions = await asyncio.to_thread(
            executor.active_sessions, service, identity_file=self.config.ssh_identity_file,
            mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
        )
        return sessions.strip() == "(no active sessions)"

    async def _handle_emergency_containment(
        self, update_id: int, service_name: str, record: UpdateRecord, assessment, superseded_note: str,
    ) -> None:
        econfig = self.config.emergency_containment
        service = self.config.services[service_name]

        try:
            decision = await asyncio.to_thread(
                security_research.research_containment_action,
                client=self.anthropic_client, model=self.config.llm_model,
                service_name=service_name, vulnerability_summary=assessment.summary,
                allowed_domains=econfig.advisory_domains.get(service_name, []),
            )
        except Exception as exc:
            logger.exception("emergency containment research failed for update %s", update_id)
            decision = security_research.ContainmentDecision(
                action="stop_service", source_url="", source_is_official=False,
                summary=f"Research step itself failed ({exc}) -- defaulting to full containment.",
            )

        use_tunnel = decision.action == "stop_tunnel" and service.cf_tunnel is not None
        if use_tunnel:
            ok, detail = await asyncio.to_thread(
                executor.stop_cf_tunnel, service, identity_file=self.config.ssh_identity_file,
                mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
            )
            action_taken = "stop_tunnel"
        else:
            ok, detail = await asyncio.to_thread(
                executor.stop_service, service, identity_file=self.config.ssh_identity_file,
                mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
            )
            action_taken = "stop_service"

        finding_id = self.store.create_finding(
            source="security_containment", subject=service_name, severity="critical",
            summary=f"Emergency containment for {service_name}: {decision.summary}",
            detail={
                "update_id": update_id, "service_name": service_name, "action_taken": action_taken,
                "containment_ok": ok, "containment_detail": detail,
                "research_source_url": decision.source_url,
                "research_source_is_official": decision.source_is_official,
            },
        )

        scope = "external access only (tunnel)" if action_taken == "stop_tunnel" else "the WHOLE service (internal access affected too)"
        containment_line = (
            f"Cut {scope}: {detail}" if ok
            else f"Tried to cut {scope} but it FAILED: {detail} -- may still be exposed, check manually."
        )
        await self._notify(
            f"\U0001f6a8 EMERGENCY: {service_name} {record.current_version} -> {record.new_version} -- "
            f"{assessment.summary}\n"
            f"Research: {decision.summary} (source: {decision.source_url or 'none found'}, "
            f"official: {decision.source_is_official})\n"
            f"{containment_line}\n"
            f"Finding #{finding_id} tracks this -- `!restore-access {finding_id}` to undo early."
            f"{superseded_note}"
        )

        if assessment.risk_level != "low" or assessment.breaking_changes:
            await self._notify(
                f"⚠ Update #{update_id} ({service_name}) still needs a human `!approve {update_id}` "
                f"(risk: {assessment.risk_level}) -- containment is holding in the meantime, no override."
            )
            return

        if await self._is_low_impact_now(service, service_name):
            try:
                status, _ = await self._auto_approve_staged_update_if_eligible(
                    service_name, max_risk_levels=("low",), notify_prefix=f"Emergency patch ({service_name})",
                )
            except Exception:
                logger.exception("emergency patch failed for update %s", update_id)
                return
            if status == "ran":
                await self.handle_restore_access(finding_id)
            return

        if self.config.nightly_auto_apply.enabled:
            self.store.set_meta(f"emergency_patch_pending:{service_name}", str(finding_id))
            await self._notify(
                f"Update #{update_id} ({service_name}) is low-risk but it's currently active hours -- "
                f"deferring the real patch to tonight's auto-apply window instead of forcing it now. "
                f"Containment stays in place until then."
            )
        else:
            await self._notify(
                f"Update #{update_id} ({service_name}) is low-risk, but it's currently active hours and no "
                f"nightly auto-apply window is configured -- still needs a human `!approve {update_id}`. "
                f"Containment is holding in the meantime."
            )


    async def _research_and_stage(self, update_id: int, service_name: str) -> None:
        self.store.set_stage(update_id, Stage.RESEARCHING)
        record = self.store.get(update_id)
        service = self.config.services[service_name]

        try:
            notes, notes_url = ("", "")
            if service.release_source:
                since_ts = self.store.get_last_success_timestamp(service_name)
                deployed_commit = None
                if service.release_source.type == "discourse_commits":
                    deployed_commit = await asyncio.to_thread(
                        executor.get_discourse_git_commit, service,
                        identity_file=self.config.ssh_identity_file,
                    )
                notes, notes_url = await asyncio.to_thread(
                    release_notes.fetch_release_notes,
                    service.release_source, record.current_version, record.new_version,
                    since_timestamp=since_ts,
                    deployed_commit=deployed_commit,
                )

            assessment = await asyncio.to_thread(
                classifier.classify,
                client=self.anthropic_client,
                model=self.config.llm_model,
                service_name=service_name,
                image=record.image,
                current_version=record.current_version,
                new_version=record.new_version,
                release_notes=notes,
            )
        except Exception as exc:
            logger.exception("research failed for update %s", update_id)
            self.store.set_error(update_id, str(exc))
            self.store.set_stage(update_id, Stage.DONE_FAILED, f"research failed: {exc}")
            await self._notify(f"Update #{update_id} ({service_name}) research failed: {exc}")
            return

        self.store.set_risk_assessment(update_id, assessment, notes_url)
        self.store.set_stage(update_id, Stage.STAGED_PENDING_APPROVAL)

        superseded_ids = self.store.mark_superseded_pending(service_name, update_id, record.new_version)
        superseded_note = (
            f"\nAlso superseded {len(superseded_ids)} earlier pending {service_name} approval(s) "
            f"that are now moot: {', '.join(f'#{i}' for i in superseded_ids)}"
            if superseded_ids else ""
        )

        econfig = self.config.emergency_containment
        if (
            assessment.security_severity == "emergency"
            and econfig.enabled
            and service_name in econfig.services
        ):
            await self._handle_emergency_containment(update_id, service_name, record, assessment, superseded_note)
            return

        cfg = self.config.nightly_auto_apply
        if cfg.security_fast_track and assessment.security_severity != "none" and service_name in cfg.services:
            try:
                status, _ = await self._auto_approve_staged_update_if_eligible(
                    service_name, max_risk_levels=("low",), notify_prefix="Security fast-track",
                )
            except Exception:
                logger.exception("security fast-track failed for update %s", update_id)
                return
            if status == "ran":
                return

        breaking = "BREAKING CHANGES" if assessment.breaking_changes else "no breaking changes found"
        urgent_prefix = (
            "⚠ SECURITY (emergency) -- " if assessment.security_severity == "emergency"
            else "⚠ SECURITY -- " if assessment.security_severity == "important"
            else ""
        )
        await self._notify(
            f"{urgent_prefix}Update #{update_id} staged: {service_name} {record.current_version} -> {record.new_version}\n"
            f"Risk: {assessment.risk_level} ({breaking})\n"
            f"{assessment.summary}\n"
            f"Reply `!approve {update_id}` to proceed, `!abort {update_id}` to dismiss, "
            f"or `!status {update_id}` for details."
            f"{superseded_note}"
        )

    async def _run_proxmox_backup_gate(
        self, update_id: int, vmid: int, *, label: str, context_note: str = "",
        interactive: bool = True, auto_skip_threshold_hours: float | None = None,
    ) -> None:
        node = await asyncio.to_thread(self.proxmox.node_for_vmid, vmid)
        vm_type = await asyncio.to_thread(self.proxmox.vm_type_for_vmid, vmid)
        pbs_backup_type = "ct" if vm_type == "lxc" else "vm"
        last = await asyncio.to_thread(
            self.pbs.last_vm_snapshot, self.config.pbs_datastore, vmid, pbs_backup_type,
        )
        age_hours: float | None = None
        if last is None:
            backup_age_note = "No backup found for this VM in PBS's snapshot history."
        else:
            age_hours = (time.time() - last["backup-time"]) / 3600
            finished = datetime.fromtimestamp(
                last["backup-time"], tz=ZoneInfo(self.config.local_timezone),
            ).strftime("%Y-%m-%d %H:%M %Z")
            verification = last.get("verification")
            status = "verified" if verification and verification.get("state") == "ok" else "unverified"
            backup_age_note = f"Last Proxmox backup: {age_hours:.1f}h ago ({finished}, {status})."

        if interactive:
            self.store.begin_backup_decision(update_id)
            await self._notify(
                f"Update #{update_id}: about to run a Proxmox backup of {label} "
                f"(VMID {vmid}) before updating.\n"
                f"{backup_age_note}"
                + (f"\n{context_note}" if context_note else "")
                + f"\nReply `!confirm-backup {update_id}` to run it, or `!skip-backup {update_id}` "
                f"to skip straight to the update. Defaults to running it if unanswered for 30 minutes."
            )
            decision = await self._await_backup_decision(update_id)
        else:
            skip = age_hours is not None and age_hours < auto_skip_threshold_hours
            decision = "skip" if skip else "confirm"
            self.store.set_backup_decision(update_id, decision)
            await self._notify(
                f"Update #{update_id}: {label} (VMID {vmid}) -- {backup_age_note} "
                + (
                    f"Backup is fresh enough (< {auto_skip_threshold_hours}h) -- skipping."
                    if skip else
                    f"Running a fresh backup (>= {auto_skip_threshold_hours}h old, or none found)."
                )
            )

        if decision == "skip":
            if interactive:
                await self._notify(f"Update #{update_id}: skipping the Proxmox backup as requested.")
            return

        self.store.set_stage(update_id, Stage.BACKING_UP_PROXMOX)

        if await asyncio.to_thread(self.proxmox.vm_locked_for_backup, node, vmid, vm_type):
            await self._notify(
                f"Update #{update_id}: {label} (VMID {vmid}) is currently "
                f"locked for an in-progress backup -- waiting for it to finish before "
                f"starting this one..."
            )
            await asyncio.to_thread(
                self.proxmox.wait_for_vm_unlocked, node, vmid,
                vm_type=vm_type, poll_interval=15, timeout=1800,
            )

        await self._notify(
            f"Update #{update_id}: starting Proxmox backup of {label} (VMID {vmid})..."
        )
        proxmox_backup_ok = False
        for attempt in (1, 2):
            upid = await asyncio.to_thread(
                self.proxmox.trigger_backup, node, vmid, "rbd-pbs-wd-usb"
            )
            proxmox_backup_ok = await asyncio.to_thread(self.proxmox.wait_for_task, node, upid)
            if proxmox_backup_ok or attempt == 2:
                break
            await self._notify(
                f"Update #{update_id}: Proxmox backup task {upid} failed -- retrying once..."
            )
            await asyncio.sleep(30)
        if not proxmox_backup_ok:
            raise RuntimeError(f"Proxmox backup task {upid} failed (after one retry)")

    async def _run_pipeline(
        self, update_id: int, service_name: str, *, non_interactive_backup: bool = False,
    ) -> None:
        service = self.config.services[service_name]
        record = self.store.get(update_id)

        refusal = await self._relay_agent_refusal(service)
        if refusal is not None:
            self.store.set_stage(update_id, Stage.STAGED_PENDING_APPROVAL, f"refused: {refusal}")
            self._pipelines_started.discard(update_id)
            await self._notify(
                f"Update #{update_id} ({service_name}) NOT started: {refusal}, then "
                f"`!approve {update_id}` again."
            )
            return

        try:
            await self._begin_uptime_kuma_maintenance(service, "update")

            if service_name == "discourse":
                await self._notify(f"Update #{update_id}: taking a fresh Discourse backup before proceeding...")
                ok, out = await asyncio.to_thread(
                    discourse_restore.create_safety_backup, service, identity_file=self.config.ssh_identity_file,
                )
                if not ok:
                    raise RuntimeError(f"pre-update Discourse backup failed: {out[-1500:]}")
                pull_ok, pull_data, pull_errors = await asyncio.to_thread(
                    discourse_backup_pull.trigger_discourse_backup_pull,
                    self.config.mgmt_host, self.config.mgmt_ssh_user,
                    retention_days=self.config.discourse_backup_retention_days,
                    identity_file=self.config.ssh_identity_file,
                )
                if not pull_ok or not pull_data.get("pulled"):
                    raise RuntimeError(
                        f"pre-update Discourse backup was created but couldn't be confirmed "
                        f"pulled to mgmt1: {pull_errors or 'no new file seen'}"
                    )

            await self._run_proxmox_backup_gate(
                update_id, service.vmid, label=service_name,
                interactive=not non_interactive_backup,
                auto_skip_threshold_hours=(
                    self.config.scheduled_maintenance.backup_max_age_hours
                    if non_interactive_backup else None
                ),
            )

            if service.kopia.enabled:
                if isinstance(service.db_backup, NextcloudDbBackupConfig):
                    await self._notify(f"Update #{update_id}: triggering a fresh database backup...")
                    ok, detail = await asyncio.to_thread(
                        executor.trigger_nextcloud_db_backup, service,
                        identity_file=self.config.ssh_identity_file,
                    )
                    if not ok:
                        raise RuntimeError(f"database backup failed: {detail}")
                elif service.db_backup:
                    if not self.config.immich_api_key:
                        raise RuntimeError(f"{service_name} has db_backup configured but IMMICH_API_KEY isn't set")
                    await self._notify(f"Update #{update_id}: triggering a fresh database backup...")
                    ok, detail = await asyncio.to_thread(
                        immich_backup.trigger_db_backup,
                        service.db_backup.base_url, self.config.immich_api_key,
                    )
                    if not ok:
                        raise RuntimeError(f"database backup trigger failed: {detail}")
                    ok, detail = await asyncio.to_thread(
                        immich_backup.wait_for_fresh_backup,
                        service.ssh_host, service.ssh_user, service.db_backup.backup_dir,
                        identity_file=self.config.ssh_identity_file,
                    )
                    if not ok:
                        raise RuntimeError(f"waiting for the fresh database backup failed: {detail}")

                self.store.set_stage(update_id, Stage.BACKING_UP_KOPIA)
                await self._notify(f"Update #{update_id}: running Kopia snapshot...")
                kopia_ok, kopia_detail = False, ""
                for attempt in (1, 2):
                    kopia_ok, kopia_detail = await asyncio.to_thread(
                        kopia.run_kopia_snapshot,
                        service.kopia.ssh_host, service.ssh_user, service.kopia.systemd_service,
                        identity_file=self.config.ssh_identity_file,
                    )
                    if kopia_ok or attempt == 2:
                        break
                    await self._notify(
                        f"Update #{update_id}: Kopia snapshot failed ({kopia_detail}) -- retrying once..."
                    )
                    await asyncio.sleep(30)
                if not kopia_ok:
                    raise RuntimeError(f"Kopia snapshot failed (after one retry): {kopia_detail}")

            self.store.set_stage(update_id, Stage.UPDATING)

            if service.compose_dir:
                ok, detail = await asyncio.to_thread(
                    executor.backup_compose_file, service, update_id,
                    identity_file=self.config.ssh_identity_file,
                )
                if not ok:
                    raise RuntimeError(f"compose file backup failed: {detail}")

                ok, detail = await asyncio.to_thread(
                    executor.backup_env_file, service, update_id,
                    identity_file=self.config.ssh_identity_file,
                )
                if not ok:
                    raise RuntimeError(f".env backup failed: {detail}")
            elif service.portainer:
                ok, detail = await asyncio.to_thread(
                    portainer.backup_stack_env, service.portainer, self.config.portainer_token, update_id,
                )
                if not ok:
                    raise RuntimeError(f"stack Env backup failed: {detail}")

            discourse_pre_commit = (
                await asyncio.to_thread(executor.get_discourse_git_commit, service, identity_file=self.config.ssh_identity_file)
                if service.launcher else None
            )

            dep_baseline_id = ""
            if service.wait_for_container_health:
                dep_baseline_id = await asyncio.to_thread(
                    executor.get_container_id, service, service.wait_for_container_health,
                    identity_file=self.config.ssh_identity_file,
                    mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
                )

            await self._notify(f"Update #{update_id}: applying version bump...")
            ok, detail = await asyncio.to_thread(
                executor.apply_update, service, record.image, record.new_version,
                identity_file=self.config.ssh_identity_file,
                portainer_token=self.config.portainer_token,
                mgmt_host=self.config.mgmt_host,
                mgmt_ssh_user=self.config.mgmt_ssh_user,
            )
            if not ok:
                raise RuntimeError(f"version bump failed: {detail}")

            if service.wait_for_container_health:
                dep_ok, dep_detail = await asyncio.to_thread(
                    executor.wait_for_container_health, service, service.wait_for_container_health,
                    baseline_id=dep_baseline_id,
                    identity_file=self.config.ssh_identity_file,
                    mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
                )
                if not dep_ok:
                    raise RuntimeError(f"dependency health check failed: {dep_detail}")

            if service.registry is not None and (service.compose_dir or service.portainer):
                for tracked_image in (service.images or [record.image]):
                    deployed_digest = await asyncio.to_thread(
                        executor.read_deployed_digest, service, tracked_image,
                        identity_file=self.config.ssh_identity_file,
                        mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
                    )
                    if not deployed_digest:
                        continue
                    is_own_image = tracked_image == record.image
                    prior_digest = record.digest if is_own_image else self.store.get_last_known_digest(
                        service_name, tracked_image,
                    )
                    if deployed_digest == prior_digest:
                        continue
                    effective_registry = service.registry_overrides.get(tracked_image) or service.registry
                    github_repo = (
                        service.release_source.repo
                        if service.release_source and service.release_source.type == "github"
                        else None
                    )
                    try:
                        resolved_version = await asyncio.to_thread(
                            tag_resolver.resolve_tag, effective_registry,
                            record.new_version if is_own_image else "latest",
                            deployed_digest, github_releases_repo=github_repo,
                        )
                    except Exception:
                        logger.exception("post-apply tag re-resolution failed for %s (%s)", service_name, tracked_image)
                        resolved_version = None

                    if is_own_image:
                        corrected_version = resolved_version or record.new_version
                        self.store.correct_applied_target(
                            update_id, new_version=corrected_version, digest=deployed_digest,
                        )
                        await self._notify(
                            f"Update #{update_id}: staged target was {record.new_version} "
                            f"(digest {record.digest}), but the floating tag had moved on by "
                            f"the time this ran -- corrected the record to what's actually "
                            f"deployed ({corrected_version}, digest {deployed_digest})."
                        )
                        record = self.store.get(update_id)
                    else:
                        corrected_version = resolved_version or tracked_image
                        resolved_ids = self.store.resolve_stale_sibling_updates(
                            service_name, tracked_image, deployed_digest, update_id,
                        )
                        if resolved_ids:
                            await self._notify(
                                f"Update #{update_id}: this stack redeploy also carried "
                                f"{tracked_image} to {corrected_version} (digest {deployed_digest}) "
                                f"before it was independently staged -- resolved "
                                f"{', '.join(f'#{i}' for i in resolved_ids)} as already applied."
                            )
                        else:
                            backfilled_id = self.store.backfill_sibling_digest(
                                service_name, tracked_image, corrected_version, deployed_digest, update_id,
                            )
                            if backfilled_id:
                                await self._notify(
                                    f"Update #{update_id}: this stack redeploy also carried "
                                    f"{tracked_image} to {corrected_version} (digest {deployed_digest}) -- "
                                    f"recorded as #{backfilled_id} so future comparisons see the real state."
                                )

            self.store.set_stage(update_id, Stage.LOG_WATCH)
            await self._notify(
                f"Update #{update_id}: watching logs for {self.config.log_watch_duration}s..."
            )
            healthy, detail = await asyncio.to_thread(
                executor.watch_logs, service,
                duration_seconds=self.config.log_watch_duration,
                poll_interval=self.config.log_watch_poll_interval,
                identity_file=self.config.ssh_identity_file,
                mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
            )
            if not healthy:
                await self._notify(
                    f"Update #{update_id}: log-watch caught a problem ({detail}) -- "
                    f"attempting one restart before giving up..."
                )
                restart_ok, restart_detail = await asyncio.to_thread(
                    executor.restart_containers, service,
                    identity_file=self.config.ssh_identity_file,
                    mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
                )
                if restart_ok:
                    healthy, detail = await asyncio.to_thread(
                        executor.watch_logs, service,
                        duration_seconds=self.config.log_watch_duration,
                        poll_interval=self.config.log_watch_poll_interval,
                        identity_file=self.config.ssh_identity_file,
                        mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
                    )
                if not restart_ok or not healthy:
                    raise RuntimeError(
                        f"post-update log watch failed: {detail} "
                        f"(a restart was already attempted and didn't resolve it)"
                    )

            log_health_note = ""
            if service.log_watch_containers:
                log_text = await asyncio.to_thread(
                    executor.collect_recent_logs, service,
                    identity_file=self.config.ssh_identity_file,
                    mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
                )
                verdict, health_summary = await asyncio.to_thread(
                    classifier.assess_log_health,
                    client=self.anthropic_client,
                    model=self.config.llm_light_model or self.config.llm_model,
                    fallback_model=self.config.llm_model,
                    service_name=service_name,
                    current_version=record.current_version,
                    new_version=record.new_version,
                    log_output=log_text,
                )
                flag = "no concerns" if verdict == "clean" else "REVIEW RECOMMENDED"
                log_health_note = f"\nLog review ({flag}): {health_summary}"

            maintenance_note = ""
            if service.occ_container:
                maint_ok, maint_output = await asyncio.to_thread(
                    executor.run_repair_plan, service, ["maintenance:repair"],
                    identity_file=self.config.ssh_identity_file,
                )
                maintenance_note = (
                    f"\nPost-update maintenance: occ maintenance:repair "
                    f"{'ran cleanly' if maint_ok else 'FAILED -- see below'}."
                )
                if not maint_ok:
                    maintenance_note += "\n" + "\n\n".join(maint_output)

            discourse_commit_note = ""
            if service.launcher and discourse_pre_commit:
                discourse_post_commit = await asyncio.to_thread(
                    executor.get_discourse_git_commit, service, identity_file=self.config.ssh_identity_file,
                )
                if discourse_post_commit:
                    if discourse_post_commit != discourse_pre_commit:
                        discourse_commit_note = (
                            f"\nVerified: app code updated "
                            f"({discourse_pre_commit[:10]} -> {discourse_post_commit[:10]})."
                        )
                    else:
                        discourse_commit_note = (
                            f"\nWARNING: the git commit inside the container didn't change "
                            f"(still {discourse_post_commit[:10]}) -- this rebuild may not have "
                            f"actually pulled anything new, even though the service came up healthy. "
                            f"Worth a manual look."
                        )

            self.store.set_stage(update_id, Stage.DONE_SUCCESS, detail)
            superseded_ids = self.store.mark_superseded_failures(service_name, update_id)
            superseded_note = (
                f"\nAlso marked {len(superseded_ids)} earlier failed {service_name} attempt(s) as "
                f"superseded by this one: {', '.join(f'#{i}' for i in superseded_ids)}"
                if superseded_ids else ""
            )
            sibling_note = ""
            if service.portainer and len(service.images) > 1:
                sibling_ids = await asyncio.to_thread(
                    self.store.resolve_sibling_stack_updates,
                    service_name, record.new_version, update_id,
                )
                if sibling_ids:
                    sibling_note = (
                        f"\nAlso resolved {len(sibling_ids)} other pending {service_name} "
                        f"request(s) for this same release, already applied by this stack "
                        f"redeploy: {', '.join(f'#{i}' for i in sibling_ids)}"
                    )
            await self._notify(
                f"Update #{update_id} ({service_name}) completed successfully. "
                f"{detail}{log_health_note}{maintenance_note}{discourse_commit_note}"
                f"{superseded_note}{sibling_note}"
            )

        except Exception as exc:
            logger.exception("pipeline failed for update %s", update_id)
            self.store.set_error(update_id, str(exc))
            self.store.set_stage(update_id, Stage.DONE_FAILED, str(exc))
            rollback_note = (
                "The pre-update Proxmox backup should still be available for rollback via PBS."
                if self.store.get(update_id).backup_decision != "skip"
                else "No fresh Proxmox backup was taken for this update (you chose to skip it) -- "
                     "rollback would rely on whatever backup already existed."
            )
            command_note = ""
            if service.compose_dir:
                if service.registry is None:
                    command_note = (
                        f"\n{service_name} is eligible for automatic rollback -- will be attempted "
                        f"only if the investigation confirms it's safe (no sign of a database "
                        f"migration having run). `!rollback {update_id}` to do it manually right away."
                    )
                elif service.occ_container:
                    command_note = (
                        f"\n{service_name} floats on a registry-resolved tag -- a compose-level "
                        f"rollback won't revert the running image. This needs a PBS or Kopia restore."
                    )
                else:
                    command_note = (
                        f"\n{service_name} floats on a registry-resolved tag -- a compose-level "
                        f"rollback of the file alone won't revert the running image. An automatic "
                        f"redeploy to its last known-good image (and, if a migration ran, a restore "
                        f"of its own pre-migration data backup) will be attempted if the investigation "
                        f"confirms it's safe; a full VM-level restore stays a human call either way."
                    )
            elif service.portainer and service.registry is not None:
                command_note = (
                    f"\n{service_name} is Portainer-managed on a floating registry tag -- a "
                    f"digest-pinned redeploy of both tracked images (and, if a migration ran, a "
                    f"restore of the database from the fresh backup this pipeline already takes "
                    f"before every update) will be attempted if the investigation confirms it's safe."
                )
            investigate_note = "\nInvestigating automatically now, and attempting a fix if a safe one " \
                "is proposed." if self.config.mgmt_host else ""
            await self._notify(
                f"Update #{update_id} ({service_name}) FAILED: {exc}\n"
                f"{rollback_note}{command_note}{investigate_note}"
            )
            if self.config.mgmt_host:
                asyncio.create_task(self._auto_investigate_and_repair(update_id))
        finally:
            await self._end_uptime_kuma_maintenance(service)

            try:
                restored, restore_detail = False, ""
                if service.portainer:
                    restored, restore_detail = await asyncio.to_thread(
                        portainer.check_and_restore_stack_env,
                        service.portainer, self.config.portainer_token, update_id,
                    )
                elif service.compose_dir:
                    restored, restore_detail = await asyncio.to_thread(
                        executor.check_and_restore_env, service, update_id,
                        identity_file=self.config.ssh_identity_file,
                    )
                if restored:
                    await self._notify(f"Update #{update_id} ({service_name}): {restore_detail}")
            except Exception:
                logger.exception("env-wipe restore check failed for update %s", update_id)
            self._pipelines_started.discard(update_id)

    async def handle_patch(self, service_name: str) -> None:
        service = self.config.services.get(service_name)
        if service is None:
            await self._notify(
                f"No service named {service_name!r} -- known services: "
                f"{', '.join(self.config.services)}"
            )
            return

        update_id = self.store.create_update(
            service_name=service_name,
            image="os-packages",
            current_version="n/a",
            new_version="n/a",
            diun_entry_id=f"os_patch:{service_name}:{int(time.time())}",
            kind="os_patch",
        )
        await self._notify(f"Patch job #{update_id}: checking pending OS packages on {service_name}...")
        asyncio.create_task(self._run_os_patch_pipeline(update_id, service_name))

    async def _run_os_patch_pipeline(self, update_id: int, service_name: str) -> None:
        service = self.config.services[service_name]
        if await self._refuse_job_if_relay_agent_empty(update_id, service, "Patch job"):
            return
        try:
            await self._begin_uptime_kuma_maintenance(service, "OS patching")

            packages = await asyncio.to_thread(
                executor.list_upgradable_packages, service,
                identity_file=self.config.ssh_identity_file,
                mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
            )
            context_note = f"Pending packages on {service_name}:\n{packages}"
            await self._run_proxmox_backup_gate(
                update_id, service.vmid, label=service_name, context_note=context_note,
            )

            self.store.set_stage(update_id, Stage.UPDATING)
            await self._notify(f"Patch job #{update_id}: running apt-get upgrade on {service_name}...")
            ok, output = await asyncio.to_thread(
                executor.apply_os_patch, service, identity_file=self.config.ssh_identity_file,
                mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
            )
            if not ok:
                raise RuntimeError(f"apt-get upgrade failed: {output}")

            self.store.set_stage(update_id, Stage.DONE_SUCCESS, "os patch applied")
            await self._notify(
                f"Patch job #{update_id} ({service_name}) completed successfully.\n{output}"
            )

            if await asyncio.to_thread(
                executor.reboot_required, service, identity_file=self.config.ssh_identity_file,
                mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
            ):
                finding_id = self.store.create_finding(
                    "os_patch", service_name, "warning",
                    f"{service_name} has a pending reboot after patch job #{update_id} -- "
                    f"run `!reboot {service_name}` when convenient.",
                )
                await self._notify(
                    f"Patch job #{update_id} ({service_name}): reboot required. "
                    f"Run `!reboot {service_name}` when convenient; finding #{finding_id} "
                    f"stays open until then."
                )
        except Exception as exc:
            logger.exception("os-patch pipeline failed for update %s", update_id)
            self.store.set_error(update_id, str(exc))
            self.store.set_stage(update_id, Stage.DONE_FAILED, str(exc))
            await self._notify(
                f"Patch job #{update_id} ({service_name}) FAILED: {exc}\n"
                f"Investigating automatically now, and attempting a fix if a safe one is proposed."
            )
            asyncio.create_task(self._auto_investigate_and_repair(update_id))
        finally:
            await self._end_uptime_kuma_maintenance(service)

    async def handle_reboot(self, service_name: str) -> None:
        service = self.config.services.get(service_name)
        if service is None:
            await self._notify(
                f"No service named {service_name!r} -- known services: "
                f"{', '.join(self.config.services)}"
            )
            return

        update_id = self.store.create_update(
            service_name=service_name,
            image="reboot",
            current_version="n/a",
            new_version="n/a",
            diun_entry_id=f"reboot:{service_name}:{int(time.time())}",
            kind="reboot",
        )
        await self._notify(f"Reboot job #{update_id}: checking {service_name} before asking...")
        asyncio.create_task(self._run_reboot_pipeline(update_id, service_name))

    async def _reboot_and_verify(self, update_id: int, service_name: str) -> tuple[bool, str]:
        service = self.config.services[service_name]
        self.store.set_stage(update_id, Stage.REBOOTING)
        await self._notify(f"Reboot job #{update_id}: rebooting {service_name} now...")
        await asyncio.to_thread(
            executor.trigger_reboot, service, identity_file=self.config.ssh_identity_file,
            mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
        )
        came_back, wait_detail = await asyncio.to_thread(
            executor.wait_for_reboot, service, identity_file=self.config.ssh_identity_file,
            mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
        )
        if not came_back:
            return False, f"reboot verification failed: {wait_detail}"
        await self._notify(
            f"Reboot job #{update_id}: {wait_detail} -- host is back up, monitoring "
            f"startup to confirm all services and containers are started and running..."
        )

        self.store.set_stage(update_id, Stage.LOG_WATCH)
        healthy, log_detail = await asyncio.to_thread(
            executor.watch_logs, service,
            duration_seconds=self.config.log_watch_duration,
            poll_interval=self.config.log_watch_poll_interval,
            identity_file=self.config.ssh_identity_file,
            mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
        )
        if not healthy:
            await self._notify(
                f"Reboot job #{update_id}: log-watch caught a problem ({log_detail}) -- "
                f"attempting one restart before giving up..."
            )
            restart_ok, _ = await asyncio.to_thread(
                executor.restart_containers, service, identity_file=self.config.ssh_identity_file,
                mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
            )
            if restart_ok:
                healthy, log_detail = await asyncio.to_thread(
                    executor.watch_logs, service,
                    duration_seconds=self.config.log_watch_duration,
                    poll_interval=self.config.log_watch_poll_interval,
                    identity_file=self.config.ssh_identity_file,
                    mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
                )
            if not restart_ok or not healthy:
                return False, (
                    f"post-reboot log watch failed: {log_detail} "
                    f"(a restart was already attempted and didn't resolve it)"
                )

        log_health_note = ""
        if service.log_watch_containers:
            log_text = await asyncio.to_thread(
                executor.collect_recent_logs, service,
                identity_file=self.config.ssh_identity_file,
                mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
            )
            verdict, health_summary = await asyncio.to_thread(
                classifier.assess_reboot_health,
                client=self.anthropic_client,
                model=self.config.llm_light_model or self.config.llm_model,
                fallback_model=self.config.llm_model,
                service_name=service_name,
                log_output=log_text,
            )
            flag = "no concerns" if verdict == "clean" else "REVIEW RECOMMENDED"
            log_health_note = f"\nLog review ({flag}): {health_summary}"

        return True, f"{wait_detail}. Containers healthy: {log_detail}{log_health_note}"

    async def _run_reboot_pipeline(self, update_id: int, service_name: str) -> None:
        service = self.config.services[service_name]
        if await self._refuse_job_if_relay_agent_empty(update_id, service, "Reboot job"):
            return
        try:
            await self._begin_uptime_kuma_maintenance(service, "reboot")

            node = await asyncio.to_thread(self.proxmox.node_for_vmid, service.vmid)
            vm_type = await asyncio.to_thread(self.proxmox.vm_type_for_vmid, service.vmid)
            if await asyncio.to_thread(self.proxmox.vm_locked_for_backup, node, service.vmid, vm_type):
                await self._notify(
                    f"Reboot job #{update_id}: {service_name} (VMID {service.vmid}) is currently "
                    f"locked for an in-progress backup -- waiting for it to finish first..."
                )
                await asyncio.to_thread(
                    self.proxmox.wait_for_vm_unlocked, node, service.vmid,
                    vm_type=vm_type, poll_interval=15, timeout=1800,
                )

            still_pending = await asyncio.to_thread(
                executor.reboot_required, service, identity_file=self.config.ssh_identity_file,
                mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
            )
            reboot_note = (
                "Reboot required: still YES." if still_pending else
                "Heads up: this host doesn't currently report a pending reboot -- proceeding anyway "
                "since it was requested by name."
            )
            sessions = await asyncio.to_thread(
                executor.active_sessions, service, identity_file=self.config.ssh_identity_file,
                mgmt_host=self.config.mgmt_host, mgmt_ssh_user=self.config.mgmt_ssh_user,
            )

            job_activity_note = ""
            if isinstance(service.db_backup, immich_backup.ImmichDbBackupConfig) and self.config.immich_api_key:
                job_activity = await asyncio.to_thread(
                    immich_backup.get_job_activity,
                    service.db_backup.base_url, self.config.immich_api_key,
                )
                job_activity_note = f"\nJob queue activity:\n{job_activity}"

            occupancy_note = ""
            if service.systemd_service == "teamspeak" and self.config.teamspeak_query_login:
                occupancy = await asyncio.to_thread(
                    teamspeak.get_occupancy,
                    service.ssh_host, self.config.teamspeak_query_login,
                    self.config.teamspeak_query_password,
                )
                occupancy_note = f"\nVoice occupancy:\n{occupancy}"

            if service.name == "enshrouded" and self.config.fortigate_api_host:
                fw_ok, fw_data, _fw_errors = await asyncio.to_thread(
                    firewall_traffic.trigger_firewall_traffic_collect,
                    self.config.mgmt_host, self.config.mgmt_ssh_user,
                    fortigate_api_host=self.config.fortigate_api_host,
                    fortigate_token_file=self.config.fortigate_token_file,
                    identity_file=self.config.ssh_identity_file,
                )
                if fw_ok:
                    real_sessions = firewall_traffic.real_sessions_for_policy(
                        fw_data.get("exposed", []), 22,
                    )
                    if real_sessions is not None:
                        occupancy_note = (
                            f"\nReal (high-volume) game sessions right now: {len(real_sessions)}"
                        )

            self.store.begin_reboot_decision(update_id)
            await self._notify(
                f"Reboot job #{update_id}: about to reboot {service_name} (VMID {service.vmid}).\n"
                f"{reboot_note}\n"
                f"Active sessions on host:\n{sessions}"
                f"{job_activity_note}{occupancy_note}\n"
                f"Reply `!confirm-reboot {update_id}` to proceed, or `!abort {update_id}` to cancel. "
                f"Defaults to NOT rebooting if unanswered for 30 minutes."
            )
            decision = await self._await_reboot_decision(update_id)
            if decision != "confirm":
                await self._notify(f"Reboot job #{update_id}: cancelled, {service_name} was not rebooted.")
                if self.store.get(update_id).stage != Stage.ABORTED:
                    self.store.set_stage(update_id, Stage.ABORTED, "reboot not confirmed")
                return

            ok, detail = await self._reboot_and_verify(update_id, service_name)
            if not ok:
                raise RuntimeError(detail)

            self.store.set_stage(update_id, Stage.DONE_SUCCESS, "reboot completed")
            self.store.resolve_finding_by_subject("os_patch", service_name)
            await self._notify(
                f"Reboot job #{update_id} ({service_name}) completed successfully. {detail}"
            )
        except Exception as exc:
            logger.exception("reboot pipeline failed for update %s", update_id)
            self.store.set_error(update_id, str(exc))
            self.store.set_stage(update_id, Stage.DONE_FAILED, str(exc))
            await self._notify(
                f"Reboot job #{update_id} ({service_name}) FAILED: {exc}\n"
                f"Investigating automatically now, and attempting a fix if a safe one is proposed."
            )
            asyncio.create_task(self._auto_investigate_and_repair(update_id))
        finally:
            await self._end_uptime_kuma_maintenance(service)


    async def _await_backup_decision(self, update_id: int, *, poll_interval: float = 5.0,
                                      timeout: float = 1800.0) -> str:
        elapsed = 0.0
        while elapsed < timeout:
            record = self.store.get(update_id)
            if record.backup_decision:
                return record.backup_decision
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval
        await self._notify(
            f"Update #{update_id}: no backup decision received after {int(timeout)}s -- "
            f"defaulting to running the Proxmox backup."
        )
        return "confirm"

    async def _await_reboot_decision(self, update_id: int, *, poll_interval: float = 5.0,
                                      timeout: float = 1800.0) -> str:
        elapsed = 0.0
        while elapsed < timeout:
            record = self.store.get(update_id)
            if record.stage != Stage.AWAITING_REBOOT_DECISION:
                return "abort"
            if record.reboot_decision:
                return record.reboot_decision
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval
        await self._notify(
            f"Update #{update_id}: no reboot decision received after {int(timeout)}s -- "
            f"defaulting to NOT rebooting."
        )
        return "abort"

    async def _notify(self, text: str) -> None:
        logger.info(text)
        if self.matrix is not None:
            await self.matrix.notify(text)

    async def _notify_wedding(self, text: str) -> None:
        logger.info(text)
        if self.matrix is not None:
            await self.matrix.notify_wedding(text)

    async def _announce_maintenance(self, service, state: str, kind: str = "") -> None:
        if self.matrix is None or not self.config.coordination_room_id:
            return
        try:
            await self.matrix.send_bot_message(
                bot_coordination.maintenance_notice(service.name, state, kind, datetime.now(timezone.utc)),
            )
        except Exception as exc:
            logger.warning("couldn't announce maintenance %s for %s: %s", state, service.name, exc)

    async def _begin_uptime_kuma_maintenance(self, service, kind: str = "") -> None:
        await self._announce_maintenance(service, "begin", kind)
        try:
            await self._set_uptimerobot_paused(service.name, True)
        except Exception as exc:
            logger.warning("uptimerobot pause for %s failed: %s", service.name, exc)
        if service.uptime_kuma is None or not self.config.uptime_kuma_base_url:
            return
        ok, detail = await asyncio.to_thread(
            uptime_kuma.begin_maintenance,
            self.config.uptime_kuma_base_url, self.config.uptime_kuma_username,
            self.config.uptime_kuma_password, service.uptime_kuma.maintenance_id,
        )
        if not ok:
            logger.warning("uptime_kuma begin_maintenance failed for %s: %s", service.name, detail)

    async def _set_uptimerobot_paused(self, service_name: str, paused: bool) -> None:
        hostnames = self.config.uptimerobot_pause_hostnames.get(service_name) or []
        key = self.config.uptimerobot_write_api_key
        if not hostnames or not key:
            return
        held = json.loads(self.store.get_meta(_UPTIMEROBOT_PAUSED_KEY) or "{}")
        if paused:
            monitors, err = await asyncio.to_thread(external_reachability.collect_uptimerobot_status, key)
            if err:
                logger.warning("uptimerobot pause for %s skipped: %s", service_name, err)
                return
            for hostname in hostnames:
                ids = external_reachability.monitor_ids_for(monitors, hostname)
                if not ids:
                    logger.warning("uptimerobot pause: no monitor for %s", hostname)
                done = []
                for monitor_id in ids:
                    ok, detail = await asyncio.to_thread(external_reachability.set_monitor_paused, key, monitor_id, True)
                    if ok:
                        done.append(monitor_id)
                    else:
                        logger.warning("uptimerobot pause of %s (%s) failed: %s", hostname, monitor_id, detail)
                if done:
                    held[hostname] = {"service": service_name, "monitor_ids": done,
                                      "since": datetime.now(timezone.utc).isoformat()}
            logger.info("uptimerobot: paused %s for %s", ", ".join(h for h in hostnames if h in held), service_name)
        else:
            for hostname in [h for h, v in held.items() if v.get("service") == service_name and "resumed" not in v]:
                left = []
                for monitor_id in held[hostname]["monitor_ids"]:
                    ok, detail = await asyncio.to_thread(external_reachability.set_monitor_paused, key, monitor_id, False)
                    if not ok:
                        left.append(monitor_id)
                        logger.warning("uptimerobot start of %s (%s) failed: %s", hostname, monitor_id, detail)
                if left:
                    held[hostname]["monitor_ids"] = left
                else:
                    held[hostname]["resumed"] = datetime.now(timezone.utc).isoformat()
                    logger.info("uptimerobot: started %s again", hostname)
        self.store.set_meta(_UPTIMEROBOT_PAUSED_KEY, json.dumps(held))

    async def _end_uptime_kuma_maintenance(self, service) -> None:
        await self._announce_maintenance(service, "end")
        try:
            await self._set_uptimerobot_paused(service.name, False)
        except Exception as exc:
            logger.warning("uptimerobot start for %s failed: %s", service.name, exc)
        if service.uptime_kuma is None or not self.config.uptime_kuma_base_url:
            return
        ok, detail = await asyncio.to_thread(
            uptime_kuma.end_maintenance,
            self.config.uptime_kuma_base_url, self.config.uptime_kuma_username,
            self.config.uptime_kuma_password, service.uptime_kuma.maintenance_id,
        )
        if not ok:
            logger.warning("uptime_kuma end_maintenance failed for %s: %s", service.name, detail)


def _wifi_rf_channel_band(channel) -> str | None:
    try:
        ch = int(channel)
    except (TypeError, ValueError):
        return None
    if 1 <= ch <= 14:
        return "2g"
    if ch >= 36:
        return "5g"
    return None


def _compute_wifi_rf_crowding(neighbors: list[dict], own_ssid_prefix: str) -> list[dict]:
    prefix = own_ssid_prefix.lower()
    by_channel: dict[tuple[str, int], dict] = {}
    for n in neighbors:
        ssid = n.get("ssid") or ""
        if ssid.lower().startswith(prefix):
            continue
        band = _wifi_rf_channel_band(n.get("channel"))
        if band is None:
            continue
        channel = int(n["channel"])
        signal = n.get("signal")
        key = (band, channel)
        entry = by_channel.setdefault(
            key, {"band": band, "channel": channel, "neighbor_count": 0, "strongest_signal": None},
        )
        entry["neighbor_count"] += 1
        if signal is not None and (entry["strongest_signal"] is None or signal > entry["strongest_signal"]):
            entry["strongest_signal"] = signal
    return list(by_channel.values())


def _backup_checks_payload(ops_health: list[dict]) -> list[dict]:
    checks = []
    for c in ops_health:
        if not c["check_id"].startswith("backup:"):
            continue
        m = _BACKUP_AGO_RE.search(c.get("detail") or "")
        if not m:
            continue
        try:
            last_checked = datetime.fromisoformat(c["last_checked"])
        except (KeyError, ValueError, TypeError):
            continue
        completed_at = last_checked - timedelta(hours=float(m.group(1)))
        checks.append({"check_id": c["check_id"], "completed_at": completed_at.isoformat()})
    return checks


_NETWORK_PEAK_TOLERANCE_FRACTION = 0.25
_NETWORK_PEAK_TOLERANCE_FLOOR_MBPS = 50.0
_NETWORK_WINDOW_TOLERANCE_MINUTES = 90


def _network_trend_delta(
    network_trend: dict, baseline: dict,
) -> tuple[dict[str, str], list[str], dict]:
    notable: dict[str, str] = {}
    steady: list[str] = []
    new_baseline = dict(baseline)

    for label, data in network_trend.items():
        nights = data.get("nights") or []
        if data.get("error") or not nights:
            continue
        latest = nights[0]
        prior = baseline.get(label)
        reason: str | None = None
        if prior is None:
            reason = "first time seen -- establishing a baseline"
        else:
            in_tol = max(_NETWORK_PEAK_TOLERANCE_FLOOR_MBPS, _NETWORK_PEAK_TOLERANCE_FRACTION * prior["in_mbps"])
            out_tol = max(_NETWORK_PEAK_TOLERANCE_FLOOR_MBPS, _NETWORK_PEAK_TOLERANCE_FRACTION * prior["out_mbps"])
            if abs(latest["in_mbps"] - prior["in_mbps"]) > in_tol or abs(latest["out_mbps"] - prior["out_mbps"]) > out_tol:
                reason = (
                    f"peak shifted from ~{prior['in_mbps']:.0f}/{prior['out_mbps']:.0f}Mbps "
                    f"to {latest['in_mbps']:.0f}/{latest['out_mbps']:.0f}Mbps (in/out)"
                )
            else:
                latest_hhmm = latest["peak_time_utc"][11:16]
                prior_hhmm = prior.get("window_hhmm")
                if prior_hhmm:
                    lh, lm = (int(x) for x in latest_hhmm.split(":"))
                    ph, pm = (int(x) for x in prior_hhmm.split(":"))
                    if abs((lh * 60 + lm) - (ph * 60 + pm)) > _NETWORK_WINDOW_TOLERANCE_MINUTES:
                        reason = f"peak window shifted from {prior_hhmm}Z to {latest_hhmm}Z"
                if reason is None and bool(latest.get("likely_cause")) != bool(prior.get("cause")):
                    reason = (
                        "a likely cause is now identified where there wasn't one before"
                        if latest.get("likely_cause") else
                        "no longer correlates with any backup job the way it used to"
                    )
        if reason:
            notable[label] = reason
        else:
            steady.append(label)
        new_baseline[label] = {
            "in_mbps": latest["in_mbps"], "out_mbps": latest["out_mbps"],
            "window_hhmm": latest["peak_time_utc"][11:16], "cause": latest.get("likely_cause"),
        }
    return notable, steady, new_baseline


def _next_window_start(now: datetime, weekday: int, start_hour: int, window_hours: float = 0) -> datetime:
    candidate = now.replace(hour=start_hour, minute=0, second=0, microsecond=0)
    days_ahead = (weekday - now.weekday()) % 7
    candidate += timedelta(days=days_ahead)
    if candidate + timedelta(hours=window_hours) <= now:
        candidate += timedelta(days=7)
    return candidate


def _next_daily_window_start(now: datetime, start_hour: int, window_hours: float = 0) -> datetime:
    candidate = now.replace(hour=start_hour, minute=0, second=0, microsecond=0)
    if candidate + timedelta(hours=window_hours) <= now:
        candidate += timedelta(days=1)
    return candidate


def _total_exposed_sessions(data: dict) -> int:
    return sum(e.get("distinct_ip_count") or 0 for e in data.get("exposed", []))


_KUMA_DEFERRED_KEY = "kuma_crash_deferred"
_UPTIMEROBOT_PAUSED_KEY = "uptimerobot_paused"


def _had_overlapping_update_activity(
    records: list[UpdateRecord], since_dt: datetime, until_dt: datetime,
) -> bool:
    for r in records:
        if not r.created_at:
            continue
        started = datetime.fromisoformat(r.created_at)
        ended = datetime.fromisoformat(r.updated_at) if r.updated_at else started
        if started <= until_dt and ended >= since_dt:
            return True
    return False


def _format_status(record: UpdateRecord) -> str:
    if record.kind == "os_patch":
        lines = [
            f"Patch job #{record.id}: {record.service_name} (OS packages)",
            f"Stage: {record.stage.value}",
        ]
    elif record.kind == "reboot":
        lines = [
            f"Reboot job #{record.id}: {record.service_name}",
            f"Stage: {record.stage.value}",
        ]
    elif record.kind == "scheduled_maintenance":
        lines = [
            f"Scheduled maintenance #{record.id}: {record.service_name}",
            f"Stage: {record.stage.value}",
        ]
    else:
        lines = [
            f"Update #{record.id}: {record.service_name} {record.current_version} -> {record.new_version}",
            f"Stage: {record.stage.value}",
        ]
    if record.risk_level:
        lines.append(f"Risk: {record.risk_level} (breaking_changes={record.breaking_changes})")
    if record.risk_summary:
        lines.append(record.risk_summary)
    if record.error:
        lines.append(f"Error: {record.error}")
    if record.superseded_by:
        lines.append(f"Superseded by update #{record.superseded_by} (a later attempt for this service succeeded).")
    return "\n".join(lines)
