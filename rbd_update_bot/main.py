"""Entrypoint: runs the webhook server, Matrix bot and background loops."""
from __future__ import annotations

import asyncio
import logging

from aiohttp import web

from .config import load_config
from .dashboard import build_dashboard_app
from .db import Store
from .matrix_bot import MatrixBot
from .orchestrator import Orchestrator
from .webhook import build_app, match_service

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)


async def _supervise(loop_fn, *args) -> None:
    name = getattr(loop_fn, "__name__", repr(loop_fn))
    backoff = 60.0
    while True:
        started = asyncio.get_running_loop().time()
        try:
            await loop_fn(*args)
            logger.warning("background loop %s returned; restarting in %.0fs", name, backoff)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("background loop %s crashed; restarting in %.0fs", name, backoff)
        if asyncio.get_running_loop().time() - started > 3600:
            backoff = 60.0
        await asyncio.sleep(backoff)
        backoff = min(backoff * 2, 1800.0)


async def main() -> None:
    config = load_config()
    store = Store(config.db_path)
    orchestrator = Orchestrator(config, store)

    async def on_new_version(parsed: dict) -> None:
        service_name = match_service(parsed["image"], config.services)
        if service_name is None:
            logger.info("ignoring update for untracked image %s", parsed["image"])
            return
        await orchestrator.handle_diun_event(service_name, parsed)

    async def on_matrix_command(command: str, update_id: int, sender: str) -> None:
        await orchestrator.handle_command(command, update_id, approved_by=sender)

    async def on_outage_report(form: dict, client_ip: str) -> tuple[bool, str]:
        return await orchestrator.handle_outage_report(form, client_ip)

    async def on_wedding_access_request(form: dict, client_ip: str) -> tuple[bool, str]:
        return await orchestrator.handle_wedding_access_request(form, client_ip)

    matrix = MatrixBot(
        homeserver=config.matrix_homeserver,
        user_id=config.matrix_user_id,
        access_token=config.matrix_access_token,
        room_id=config.matrix_room_id,
        on_command=on_matrix_command,
        on_help=orchestrator.handle_help,
        on_check_updates=orchestrator.handle_check_updates,
        on_findings=orchestrator.handle_findings,
        on_pending=orchestrator.handle_pending,
        on_briefing=orchestrator.handle_briefing,
        on_security_scan=orchestrator.handle_security_scan,
        on_trust_device=orchestrator.handle_trust_device,
        on_trust_peer=orchestrator.handle_trust_peer,
        on_block_ip=orchestrator.handle_block_ip,
        on_unblock_ip=orchestrator.handle_unblock_ip,
        on_blocklist=orchestrator.handle_blocklist,
        on_kb_rotate_token=orchestrator.handle_kb_rotate_token,
        on_kb_restrict=orchestrator.handle_kb_restrict,
        on_kb_unrestrict=orchestrator.handle_kb_unrestrict,
        on_investigate_finding=orchestrator.handle_investigate_finding,
        on_restore_access=orchestrator.handle_restore_access,
        on_resolve_finding=orchestrator.handle_resolve_finding,
        on_accept_port=orchestrator.handle_accept_port,
        on_approve_access=orchestrator.handle_approve_access,
        on_deny_access=orchestrator.handle_deny_access,
        on_whitelist_requester=orchestrator.handle_whitelist_requester,
        on_unwhitelist_requester=orchestrator.handle_unwhitelist_requester,
        on_investigate_network=orchestrator.handle_investigate_network,
        on_investigate_cluster=orchestrator.handle_investigate_cluster,
        on_patch=orchestrator.handle_patch,
        on_reboot=orchestrator.handle_reboot,
        on_maintenance=orchestrator.handle_maintenance,
        on_confirm_maintenance=orchestrator.handle_confirm_maintenance,
        on_skip_maintenance=orchestrator.handle_skip_maintenance,
        on_maintenance_prep=orchestrator.handle_maintenance_prep,
        on_discourse_backups=orchestrator.handle_discourse_backups,
        on_discourse_restore=orchestrator.handle_discourse_restore,
        on_confirm_discourse_restore=orchestrator.handle_confirm_discourse_restore,
        on_abort_discourse_restore=orchestrator.handle_abort_discourse_restore,
        on_wifi_channels=orchestrator.handle_wifi_channels,
        on_llm_usage=orchestrator.handle_llm_usage,
        store=store,
        admin_user_ids=config.matrix_admin_user_ids,
        coordination_room_id=config.coordination_room_id,
        wedding_room_id=config.wedding_access_request_room_id,
        on_bot_message=orchestrator.handle_bot_message,
    )
    orchestrator.matrix = matrix

    await orchestrator.reconcile_orphaned_updates_on_startup()

    await orchestrator.reconcile_orphaned_findings_on_startup()

    asyncio.create_task(orchestrator.reconcile_cluster_maintenance_restore_on_startup())

    app = build_app(
        on_new_version, on_outage_report, on_wedding_access_request,
        webhook_shared_secret=config.webhook_shared_secret,
    )
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, config.webhook_host, config.webhook_port)
    await site.start()
    logger.info("webhook listening on %s:%s", config.webhook_host, config.webhook_port)

    dashboard_app = build_dashboard_app(store)
    dashboard_runner = web.AppRunner(dashboard_app)
    await dashboard_runner.setup()
    dashboard_site = web.TCPSite(dashboard_runner, "127.0.0.1", config.dashboard_port)
    await dashboard_site.start()
    logger.info("dashboard listening on 127.0.0.1:%s", config.dashboard_port)

    await matrix.join_coordination_room()
    await matrix.join_wedding_room()
    tasks = [
        matrix.run_forever(),
        _supervise(matrix.run_outbox_loop),
        _supervise(orchestrator.run_approval_poll_loop),
    ]
    if config.mgmt_host:
        tasks.append(_supervise(orchestrator.run_mgmt1_agent_watch_loop, 10 * 60))
    if config.coordination_room_id:
        tasks.append(_supervise(orchestrator.run_bot_status_loop, 15 * 60))
        if config.coordination_pass_bot_user_id:
            tasks.append(_supervise(orchestrator.run_pass_bot_heartbeat_watch_loop, 10 * 60))
    if config.security_scan_interval_hours > 0:
        interval_seconds = config.security_scan_interval_hours * 3600
        logger.info("scheduling !security-scan every %s hours", config.security_scan_interval_hours)
        tasks.append(_supervise(orchestrator.run_security_scan_loop, interval_seconds))
    if config.network_monitor_interval_minutes > 0:
        interval_seconds = config.network_monitor_interval_minutes * 60
        logger.info(
            "scheduling active network monitor every %s minutes",
            config.network_monitor_interval_minutes,
        )
        tasks.append(_supervise(orchestrator.run_network_monitor_loop, interval_seconds))
    if config.disk_health_interval_hours > 0:
        interval_seconds = config.disk_health_interval_hours * 3600
        logger.info(
            "scheduling disk health monitor every %s hours",
            config.disk_health_interval_hours,
        )
        tasks.append(_supervise(orchestrator.run_disk_health_loop, interval_seconds))
    if config.ops_health_interval_hours > 0:
        interval_seconds = config.ops_health_interval_hours * 3600
        logger.info(
            "scheduling ops health monitor every %s hours",
            config.ops_health_interval_hours,
        )
        tasks.append(_supervise(orchestrator.run_ops_health_loop, interval_seconds))
    if config.mgmt1_patch_interval_hours > 0:
        interval_seconds = config.mgmt1_patch_interval_hours * 3600
        logger.info(
            "scheduling mgmt1 OS-patch monitor every %s hours",
            config.mgmt1_patch_interval_hours,
        )
        tasks.append(_supervise(orchestrator.run_mgmt1_patch_loop, interval_seconds))
    if config.config_drift_interval_hours > 0:
        interval_seconds = config.config_drift_interval_hours * 3600
        logger.info(
            "scheduling config-drift archive every %s hours",
            config.config_drift_interval_hours,
        )
        tasks.append(_supervise(orchestrator.run_config_drift_loop, interval_seconds))
    if config.discourse_backup_pull_interval_hours > 0:
        interval_seconds = config.discourse_backup_pull_interval_hours * 3600
        logger.info(
            "scheduling Discourse backup pull every %s hours",
            config.discourse_backup_pull_interval_hours,
        )
        tasks.append(_supervise(orchestrator.run_discourse_backup_pull_loop, interval_seconds))
    if config.kuma_maintenance_reconcile_interval_hours > 0:
        interval_seconds = config.kuma_maintenance_reconcile_interval_hours * 3600
        logger.info(
            "scheduling Kuma maintenance reconcile every %s hours",
            config.kuma_maintenance_reconcile_interval_hours,
        )
        tasks.append(_supervise(orchestrator.run_kuma_maintenance_reconcile_loop, interval_seconds))
    if config.cloudflare_traffic_interval_hours > 0:
        interval_seconds = config.cloudflare_traffic_interval_hours * 3600
        logger.info(
            "scheduling Cloudflare traffic monitor every %s hours",
            config.cloudflare_traffic_interval_hours,
        )
        tasks.append(_supervise(orchestrator.run_cloudflare_traffic_loop, interval_seconds))
    if config.graph_monitor_interval_hours > 0:
        interval_seconds = config.graph_monitor_interval_hours * 3600
        logger.info(
            "scheduling Microsoft Graph monitor every %s hours",
            config.graph_monitor_interval_hours,
        )
        tasks.append(_supervise(orchestrator.run_graph_monitor_loop, interval_seconds))
    if config.librenms_monitor_interval_minutes > 0:
        interval_seconds = config.librenms_monitor_interval_minutes * 60
        logger.info(
            "scheduling LibreNMS monitor every %s minutes",
            config.librenms_monitor_interval_minutes,
        )
        tasks.append(_supervise(orchestrator.run_librenms_monitor_loop, interval_seconds))
    if config.homeassistant_check_interval_hours > 0:
        interval_seconds = config.homeassistant_check_interval_hours * 3600
        logger.info(
            "scheduling Home Assistant update check every %s hours",
            config.homeassistant_check_interval_hours,
        )
        tasks.append(_supervise(orchestrator.run_homeassistant_update_loop, interval_seconds))
    if config.external_reachability_interval_minutes > 0:
        interval_seconds = config.external_reachability_interval_minutes * 60
        logger.info(
            "scheduling external reachability monitor every %s minutes",
            config.external_reachability_interval_minutes,
        )
        tasks.append(_supervise(orchestrator.run_external_reachability_loop, interval_seconds))
    if config.kuma_crash_monitor_interval_minutes > 0:
        interval_seconds = config.kuma_crash_monitor_interval_minutes * 60
        logger.info(
            "scheduling fleet-wide tier-1 auto-restart (Kuma crash monitor) every %s minutes",
            config.kuma_crash_monitor_interval_minutes,
        )
        tasks.append(_supervise(orchestrator.run_kuma_crash_monitor_loop, interval_seconds))
    if config.kb_access_sync_interval_hours > 0:
        interval_seconds = config.kb_access_sync_interval_hours * 3600
        logger.info(
            "scheduling KB Immich-access-group sync every %s hours",
            config.kb_access_sync_interval_hours,
        )
        tasks.append(_supervise(orchestrator.run_kb_access_sync_loop, interval_seconds))
    if config.kb_access_monitor_interval_minutes > 0:
        interval_seconds = config.kb_access_monitor_interval_minutes * 60
        logger.info(
            "scheduling KB access abuse-detection monitor every %s minutes",
            config.kb_access_monitor_interval_minutes,
        )
        tasks.append(_supervise(orchestrator.run_kb_access_monitor_loop, interval_seconds))
    if config.wedding_access_request_expiry_check_interval_hours > 0:
        interval_seconds = config.wedding_access_request_expiry_check_interval_hours * 3600
        logger.info(
            "scheduling wedding-access-request grant expiry check every %s hours",
            config.wedding_access_request_expiry_check_interval_hours,
        )
        tasks.append(_supervise(orchestrator.run_access_grant_expiry_loop, interval_seconds))
    if config.daily_briefing_morning_hour >= 0 or config.daily_briefing_evening_hour >= 0:
        interval_seconds = config.daily_briefing_poll_interval_minutes * 60
        logger.info(
            "scheduling daily briefing (morning_hour=%s, evening_hour=%s)",
            config.daily_briefing_morning_hour, config.daily_briefing_evening_hour,
        )
        tasks.append(_supervise(orchestrator.run_daily_briefing_loop, interval_seconds))
    if config.teamspeak_version_check_interval_hours > 0:
        interval_seconds = config.teamspeak_version_check_interval_hours * 3600
        logger.info(
            "scheduling TeamSpeak version check every %s hours",
            config.teamspeak_version_check_interval_hours,
        )
        tasks.append(_supervise(orchestrator.run_teamspeak_version_check_loop, interval_seconds))
    if config.ollama_version_check_interval_hours > 0:
        interval_seconds = config.ollama_version_check_interval_hours * 3600
        logger.info(
            "scheduling Ollama version check every %s hours",
            config.ollama_version_check_interval_hours,
        )
        tasks.append(_supervise(orchestrator.run_ollama_version_check_loop, interval_seconds))
    if config.enshrouded_version_check_interval_hours > 0:
        interval_seconds = config.enshrouded_version_check_interval_hours * 3600
        logger.info(
            "scheduling Enshrouded version check every %s hours",
            config.enshrouded_version_check_interval_hours,
        )
        tasks.append(_supervise(orchestrator.run_enshrouded_version_check_loop, interval_seconds))
    if config.caddy_rebuild_interval_hours > 0:
        interval_seconds = config.caddy_rebuild_interval_hours * 3600
        logger.info(
            "scheduling Caddy auto-rebuild check every %s hours",
            config.caddy_rebuild_interval_hours,
        )
        tasks.append(_supervise(orchestrator.run_caddy_rebuild_loop, interval_seconds))
    if config.firewall_traffic_interval_minutes > 0:
        interval_seconds = config.firewall_traffic_interval_minutes * 60
        logger.info(
            "scheduling firewall traffic monitor every %s minutes",
            config.firewall_traffic_interval_minutes,
        )
        tasks.append(_supervise(orchestrator.run_firewall_traffic_loop, interval_seconds))
    if config.fortios_advisory_check_interval_hours > 0:
        interval_seconds = config.fortios_advisory_check_interval_hours * 3600
        logger.info(
            "scheduling FortiOS advisory check every %s hours",
            config.fortios_advisory_check_interval_hours,
        )
        tasks.append(_supervise(orchestrator.run_fortios_advisory_check_loop, interval_seconds))
    if config.scheduled_maintenance.enabled:
        interval_seconds = config.scheduled_maintenance.poll_minutes * 60
        logger.info(
            "scheduling weekly maintenance window check every %s minutes (services: %s)",
            config.scheduled_maintenance.poll_minutes, config.scheduled_maintenance.services,
        )
        tasks.append(_supervise(orchestrator.run_scheduled_maintenance_loop, interval_seconds))
    if config.nightly_auto_apply.enabled:
        interval_seconds = config.nightly_auto_apply.poll_minutes * 60
        logger.info(
            "scheduling nightly auto-apply window check every %s minutes (services: %s)",
            config.nightly_auto_apply.poll_minutes, config.nightly_auto_apply.services,
        )
        tasks.append(_supervise(orchestrator.run_nightly_auto_apply_loop, interval_seconds))
    if config.kernel_cve_watch.enabled:
        interval_seconds = config.kernel_cve_watch.interval_hours * 3600
        logger.info(
            "scheduling kernel CVE watch every %s hours (fleet-wide)",
            config.kernel_cve_watch.interval_hours,
        )
        tasks.append(_supervise(orchestrator.run_kernel_cve_watch_loop, interval_seconds))
    if config.docker_prune.enabled:
        interval_seconds = config.docker_prune.interval_hours * 3600
        logger.info(
            "scheduling fleet-wide docker image/build-cache prune every %s hours",
            config.docker_prune.interval_hours,
        )
        tasks.append(_supervise(orchestrator.run_docker_prune_loop, interval_seconds))
    if config.wifi_rf.enabled:
        interval_seconds = config.wifi_rf.interval_hours * 3600
        logger.info(
            "scheduling WiFi RF monitor every %s hours",
            config.wifi_rf.interval_hours,
        )
        tasks.append(_supervise(orchestrator.run_wifi_rf_monitor_loop, interval_seconds))
    await asyncio.gather(*tasks)


if __name__ == "__main__":
    asyncio.run(main())
