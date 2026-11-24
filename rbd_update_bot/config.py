"""Loads config.yaml and services.yaml (non-secret) plus secrets from the environment."""
from __future__ import annotations

import os
from dataclasses import dataclass, field

import yaml
from dotenv import load_dotenv

from .immich_backup import ImmichDbBackupConfig
from .portainer import PortainerConfig
from .release_notes import ReleaseSource
from .tag_resolver import RegistryConfig

load_dotenv()


@dataclass
class KopiaConfig:
    enabled: bool
    ssh_host: str | None = None
    systemd_service: str | None = None


@dataclass
class UptimeKumaConfig:
    maintenance_id: int


@dataclass
class ScheduledMaintenanceConfig:
    enabled: bool = False
    weekday: int = 5
    start_hour: int = 1
    window_hours: float = 5
    poll_minutes: float = 30
    summary_hours_before: float = 6.0
    reminder_interval_hours: float = 1.5
    backup_max_age_hours: float = 12.0
    fg_session_threshold: int = 10
    services: list[str] = field(default_factory=list)


@dataclass
class NightlyAutoApplyConfig:
    enabled: bool = False
    start_hour: int = -1
    window_hours: float = 4.0
    poll_minutes: float = 15
    backup_max_age_hours: float = 12.0
    fg_session_threshold: int = 10
    services: list[str] = field(default_factory=list)
    security_fast_track: bool = False


@dataclass
class EmergencyContainmentConfig:
    enabled: bool = False
    services: list[str] = field(default_factory=list)
    advisory_domains: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class KernelCVEWatchConfig:
    enabled: bool = False
    interval_hours: float = 24.0
    backup_max_age_hours: float = 12.0
    research_max_age_hours: float = 168.0


@dataclass
class DockerPruneConfig:
    enabled: bool = False
    interval_hours: float = 24.0
    notify_threshold_mb: float = 500.0


@dataclass
class WifiRfConfig:
    enabled: bool = False
    interval_hours: float = 0.25
    watched_macs: list[str] = field(default_factory=lambda: ["00:00:5e:00:53:01"])
    sustained_samples: int = 4
    inter_util_threshold: float = 20.0
    busy_util_threshold: float = 60.0
    retry_rate_threshold: float = 15.0
    retry_min_rx_pkts: int = 5000
    watched_rssi_threshold: float = -70.0
    own_ssid_prefix: str = "homelab"


@dataclass
class CloudflareZoneConfig:
    zone_id: str
    hostnames: list[str] = field(default_factory=list)
    api_token: str = ""


@dataclass
class CaddyRebuildTarget:
    name: str
    mechanism: str
    ssh_host: str
    ssh_user: str
    container_name: str
    health_url: str
    compose_dir: str | None = None
    compose_service: str | None = None
    build_context: str | None = None
    image_tag: str | None = None
    portainer: PortainerConfig | None = None


@dataclass
class CfTunnelConfig:
    kind: str
    name: str


@dataclass
class NextcloudDbBackupConfig:
    container: str


@dataclass
class ServiceConfig:
    name: str
    vmid: int
    ssh_host: str
    ssh_user: str
    images: list[str]
    release_source: ReleaseSource | None
    kopia: KopiaConfig
    log_watch_containers: list[str]
    compose_dir: str | None = None
    launcher: bool = False
    launcher_dir: str | None = None
    registry: RegistryConfig | None = None
    registry_overrides: dict[str, RegistryConfig] = field(default_factory=dict)
    wait_for_container_health: str = ""
    current_version: str | None = None
    portainer: PortainerConfig | None = None
    db_backup: ImmichDbBackupConfig | NextcloudDbBackupConfig | None = None
    occ_container: str | None = None
    uptime_kuma: UptimeKumaConfig | None = None
    systemd_service: str | None = None
    db_systemd_unit: str | None = None
    db_containers: list[str] = field(default_factory=list)
    internal_db_container: str | None = None
    internal_db_programs: list[str] = field(default_factory=list)
    relay_through_mgmt: bool = False
    cf_tunnel: CfTunnelConfig | None = None
    cf_tunnel_portainer: PortainerConfig | None = None


@dataclass
class Config:
    webhook_host: str
    webhook_port: int
    matrix_homeserver: str
    matrix_user_id: str
    matrix_room_id: str
    proxmox_api_host: str
    proxmox_verify_tls: bool
    pbs_api_host: str
    pbs_verify_tls: bool
    llm_model: str
    log_watch_duration: int
    log_watch_poll_interval: int
    db_path: str
    services: dict[str, ServiceConfig]
    monitoring_host: str = ""
    monitoring_ssh_user: str = ""
    llm_light_model: str = "claude-haiku-5-5"
    llm_local_fallback_model: str = ""
    uptime_kuma_base_url: str = ""
    uptime_kuma_username: str = ""
    uptime_kuma_password: str = ""
    mgmt_host: str = ""
    mgmt_ssh_user: str = ""
    self_ssh_host: str = ""
    self_ssh_user: str = ""
    self_install_dir: str = ""
    security_scan_interval_hours: float = 0
    security_scan_extra_hosts: list[dict] = field(default_factory=list)
    fortigate_api_host: str = ""
    fortigate_token_file: str = ""
    fortigate_write_token_file: str = ""
    github_repo: str = ""
    github_issue_token_file: str = ""
    omada_config_file: str = ""
    network_monitor_interval_minutes: float = 0
    disk_health_interval_hours: float = 0
    synology_config_file: str = ""
    ops_health_interval_hours: float = 0
    mgmt1_patch_interval_hours: float = 0
    config_drift_interval_hours: float = 0
    discourse_backup_pull_interval_hours: float = 0
    discourse_backup_retention_days: int = 90
    discourse_backup_staleness_hours: float = 216.0
    kuma_maintenance_reconcile_interval_hours: float = 0
    teamspeak_version_check_interval_hours: float = 0
    fortios_advisory_check_interval_hours: float = 0
    fortios_advisory_research_max_age_hours: float = 168.0
    ollama_version_check_interval_hours: float = 0
    enshrouded_version_check_interval_hours: float = 0
    tls_check_hostnames: list[str] = field(default_factory=list)
    firewall_traffic_interval_minutes: float = 0

    wireguard_ssh_host: str = ""
    wireguard_ssh_user: str = ""

    caddy_rebuild_interval_hours: float = 0
    caddy_rebuild_targets: list[CaddyRebuildTarget] = field(default_factory=list)

    scheduled_maintenance: ScheduledMaintenanceConfig = field(default_factory=ScheduledMaintenanceConfig)
    nightly_auto_apply: NightlyAutoApplyConfig = field(default_factory=NightlyAutoApplyConfig)
    emergency_containment: EmergencyContainmentConfig = field(default_factory=EmergencyContainmentConfig)
    kernel_cve_watch: KernelCVEWatchConfig = field(default_factory=KernelCVEWatchConfig)
    docker_prune: DockerPruneConfig = field(default_factory=DockerPruneConfig)
    wifi_rf: WifiRfConfig = field(default_factory=WifiRfConfig)

    dashboard_port: int = 8421

    webhook_shared_secret: str = ""
    matrix_admin_user_ids: list[str] = field(default_factory=list)

    local_timezone: str = "UTC"

    cloudflare_api_token: str = ""
    cloudflare_account_id: str = ""
    cloudflare_zone_id: str = ""
    cloudflare_traffic_hostnames: list[str] = field(default_factory=list)
    cloudflare_tunnel_ids: dict[str, str] = field(default_factory=dict)
    cloudflare_traffic_zones: list[CloudflareZoneConfig] = field(default_factory=list)
    cloudflare_traffic_interval_hours: float = 0

    anthropic_api_key: str = ""
    proxmox_token: str = ""
    pbs_token: str = ""
    matrix_access_token: str = ""
    ssh_identity_file: str = ""
    portainer_token: str = ""
    immich_api_key: str = ""
    teamspeak_query_login: str = ""
    teamspeak_query_password: str = ""

    pbs_datastore: str = "wd-usb"

    graph_mailbox_user_ids: list[str] = field(default_factory=list)
    graph_monitor_interval_hours: float = 0
    graph_client_id: str = ""
    graph_client_secret: str = ""
    graph_tenant_id: str = ""
    graph_admin_user_principal_name: str = ""

    o365_outage_watch_enabled: bool = False

    librenms_api_host: str = ""
    librenms_api_token: str = ""
    librenms_monitor_interval_minutes: float = 0

    homeassistant_api_host: str = ""
    homeassistant_api_token: str = ""
    homeassistant_check_interval_hours: float = 0

    external_reachability_interval_minutes: float = 0
    uptimerobot_api_key: str = ""
    uptimerobot_write_api_key: str = ""
    uptimerobot_pause_hostnames: dict[str, list[str]] = field(default_factory=dict)

    kuma_crash_monitor_interval_minutes: float = 0

    cloudflare_access_api_token: str = ""
    immich_users_api_key: str = ""
    kb_immich_base_url: str = ""
    kb_access_group_id: str = ""
    kb_access_sync_interval_hours: float = 0

    matrix_admin_access_token: str = ""
    kb_admin_room_id: str = ""
    kb_admin_bot_user_id: str = ""
    kb_matrix_teamspeak_app_id: str = ""
    kb_access_monitor_interval_minutes: float = 0
    kb_access_monitor_window_hours: float = 1.0
    kb_new_logins_warn_threshold: int = 10
    kb_new_registrations_warn_threshold: int = 3

    matrix_registration_token: str = ""
    kb_loose_policy_id: str = ""
    kb_strict_policy_id: str = ""
    kb_registration_token_max_uses: int = 0
    kb_registration_token_rotate_at_remaining: int = 1

    wedding_access_request_app_id: str = ""
    wedding_access_request_policy_id: str = ""
    wedding_access_request_grant_days: float = 30
    wedding_access_request_expiry_check_interval_hours: float = 0
    wedding_hub_db_path: str = "/opt/wedding-hub/wedding_hub.db"
    wedding_access_request_date: str = ""
    wedding_access_request_room_id: str = ""

    daily_briefing_morning_hour: int = -1
    daily_briefing_evening_hour: int = -1
    daily_briefing_poll_interval_minutes: float = 15
    coordination_room_id: str = ""
    coordination_pass_bot_user_id: str = ""
    coordination_pass_bot_mailboxes: list[str] = field(default_factory=list)


def load_config(config_path: str = "config.yaml", services_path: str = "services.yaml") -> Config:
    with open(config_path) as f:
        raw = yaml.safe_load(f)
    with open(services_path) as f:
        raw_services = yaml.safe_load(f)["services"]

    services: dict[str, ServiceConfig] = {}
    for name, s in raw_services.items():
        kopia_raw = s.get("kopia", {"enabled": False})
        source_raw = s.get("release_source")
        release_source = ReleaseSource(**source_raw) if source_raw else None
        registry_raw = s.get("registry")
        registry = RegistryConfig(**registry_raw) if registry_raw else None
        registry_overrides = {
            image: RegistryConfig(**cfg)
            for image, cfg in (s.get("registry_overrides") or {}).items()
        }
        portainer_raw = s.get("portainer")
        portainer = PortainerConfig(**portainer_raw) if portainer_raw else None
        db_backup_raw = s.get("db_backup")
        if not db_backup_raw:
            db_backup = None
        elif "container" in db_backup_raw:
            db_backup = NextcloudDbBackupConfig(**db_backup_raw)
        else:
            db_backup = ImmichDbBackupConfig(**db_backup_raw)
        uptime_kuma_raw = s.get("uptime_kuma")
        uptime_kuma = UptimeKumaConfig(**uptime_kuma_raw) if uptime_kuma_raw else None
        services[name] = ServiceConfig(
            name=name,
            vmid=s["vmid"],
            ssh_host=s["ssh_host"],
            ssh_user=s["ssh_user"],
            images=s.get("images", []),
            release_source=release_source,
            kopia=KopiaConfig(**kopia_raw),
            log_watch_containers=s.get("log_watch_containers", []),
            compose_dir=s.get("compose_dir"),
            launcher=s.get("launcher", False),
            launcher_dir=s.get("launcher_dir"),
            registry=registry,
            registry_overrides=registry_overrides,
            wait_for_container_health=s.get("wait_for_container_health", ""),
            current_version=s.get("current_version"),
            portainer=portainer,
            db_backup=db_backup,
            occ_container=s.get("occ_container"),
            uptime_kuma=uptime_kuma,
            systemd_service=s.get("systemd_service"),
            db_systemd_unit=s.get("db_systemd_unit"),
            db_containers=s.get("db_containers", []),
            internal_db_container=s.get("internal_db_container"),
            internal_db_programs=s.get("internal_db_programs", []),
            relay_through_mgmt=s.get("relay_through_mgmt", False),
            cf_tunnel=CfTunnelConfig(**s["cf_tunnel"]) if s.get("cf_tunnel") else None,
            cf_tunnel_portainer=(
                PortainerConfig(**s["cf_tunnel_portainer"]) if s.get("cf_tunnel_portainer") else None
            ),
        )

    cf_traffic_raw = raw.get("cloudflare_traffic", {})
    cf_shared_token = os.environ.get("CLOUDFLARE_API_TOKEN", "")
    cf_zones_raw = cf_traffic_raw.get("zones")
    if cf_zones_raw:
        cloudflare_traffic_zones = [
            CloudflareZoneConfig(
                zone_id=z["zone_id"], hostnames=z.get("hostnames", []),
                api_token=(
                    os.environ.get(z["api_token_env"], "") if z.get("api_token_env") else cf_shared_token
                ),
            )
            for z in cf_zones_raw
        ]
    else:
        legacy_zone_id = cf_traffic_raw.get("zone_id", "")
        cloudflare_traffic_zones = (
            [CloudflareZoneConfig(
                zone_id=legacy_zone_id, hostnames=cf_traffic_raw.get("hostnames", []),
                api_token=cf_shared_token,
            )]
            if legacy_zone_id else []
        )

    return Config(
        webhook_host=raw["webhook"]["host"],
        webhook_port=raw["webhook"]["port"],
        matrix_homeserver=raw["matrix"]["homeserver"],
        matrix_user_id=raw["matrix"]["user_id"],
        matrix_room_id=raw["matrix"]["room_id"],
        proxmox_api_host=raw["proxmox"]["api_host"],
        proxmox_verify_tls=raw["proxmox"].get("verify_tls", True),
        pbs_api_host=raw["pbs"]["api_host"],
        pbs_verify_tls=raw["pbs"].get("verify_tls", True),
        pbs_datastore=raw["pbs"].get("datastore", "wd-usb"),
        llm_model=raw["llm"]["model"],
        llm_light_model=raw["llm"].get("light_model", "claude-haiku-5-5"),
        llm_local_fallback_model=raw["llm"].get("local_fallback_model", ""),
        log_watch_duration=raw["log_watch"]["duration_seconds"],
        log_watch_poll_interval=raw["log_watch"]["poll_interval_seconds"],
        local_timezone=raw.get("local_timezone", "UTC"),
        db_path=raw["database"]["path"],
        services=services,
        monitoring_host=raw.get("monitoring", {}).get("host", ""),
        monitoring_ssh_user=raw.get("monitoring", {}).get("ssh_user", ""),
        uptime_kuma_base_url=raw.get("monitoring", {}).get("uptime_kuma_base_url", ""),
        mgmt_host=raw.get("mgmt", {}).get("host", ""),
        mgmt_ssh_user=raw.get("mgmt", {}).get("ssh_user", ""),
        self_ssh_host=raw.get("bot_host", {}).get("ssh_host", ""),
        self_ssh_user=raw.get("bot_host", {}).get("ssh_user", ""),
        self_install_dir=raw.get("bot_host", {}).get("install_dir", ""),
        security_scan_interval_hours=raw.get("security_scan", {}).get("interval_hours", 0),
        security_scan_extra_hosts=raw.get("security_scan", {}).get("extra_hosts", []),
        fortigate_api_host=raw.get("fortigate", {}).get("api_host", ""),
        fortigate_token_file=raw.get("fortigate", {}).get("token_file", ""),
        fortigate_write_token_file=raw.get("fortigate", {}).get("write_token_file", ""),
        github_repo=raw.get("github", {}).get("repo", ""),
        github_issue_token_file=raw.get("github", {}).get("issue_token_file", ""),
        omada_config_file=raw.get("omada", {}).get("config_file", ""),
        network_monitor_interval_minutes=raw.get("network_monitor", {}).get("interval_minutes", 0),
        disk_health_interval_hours=raw.get("disk_health", {}).get("interval_hours", 0),
        synology_config_file=raw.get("synology", {}).get("config_file", ""),
        ops_health_interval_hours=raw.get("ops_health", {}).get("interval_hours", 0),
        mgmt1_patch_interval_hours=raw.get("mgmt1_patch", {}).get("interval_hours", 0),
        config_drift_interval_hours=raw.get("config_drift", {}).get("interval_hours", 0),
        discourse_backup_pull_interval_hours=raw.get("discourse_backup_pull", {}).get("interval_hours", 0),
        discourse_backup_retention_days=raw.get("discourse_backup_pull", {}).get("retention_days", 90),
        discourse_backup_staleness_hours=raw.get("discourse_backup_pull", {}).get("staleness_hours", 216.0),
        kuma_maintenance_reconcile_interval_hours=raw.get("kuma_maintenance_reconcile", {}).get("interval_hours", 0),
        cloudflare_account_id=raw.get("cloudflare_traffic", {}).get("account_id", ""),
        cloudflare_zone_id=raw.get("cloudflare_traffic", {}).get("zone_id", ""),
        cloudflare_tunnel_ids=raw.get("cloudflare_traffic", {}).get("tunnel_ids", {}),
        cloudflare_traffic_hostnames=raw.get("cloudflare_traffic", {}).get("hostnames", []),
        cloudflare_traffic_zones=cloudflare_traffic_zones,
        cloudflare_traffic_interval_hours=raw.get("cloudflare_traffic", {}).get("interval_hours", 0),
        graph_mailbox_user_ids=raw.get("graph_monitor", {}).get("mailbox_user_ids", []),
        graph_monitor_interval_hours=raw.get("graph_monitor", {}).get("interval_hours", 0),
        graph_admin_user_principal_name=raw.get("graph_monitor", {}).get("admin_user_principal_name", ""),
        o365_outage_watch_enabled=raw.get("o365_outage_watch", {}).get("enabled", False),
        librenms_api_host=raw.get("librenms_monitor", {}).get("api_host", ""),
        librenms_monitor_interval_minutes=raw.get("librenms_monitor", {}).get("interval_minutes", 0),
        homeassistant_api_host=raw.get("homeassistant", {}).get("api_host", ""),
        homeassistant_check_interval_hours=raw.get("homeassistant", {}).get("interval_hours", 0),
        external_reachability_interval_minutes=raw.get("external_reachability", {}).get("interval_minutes", 0),
        uptimerobot_api_key=os.environ.get("UPTIMEROBOT_API_KEY", ""),
        uptimerobot_write_api_key=os.environ.get("UPTIMEROBOT_WRITE_API_KEY", ""),
        uptimerobot_pause_hostnames=raw.get("external_reachability", {}).get("pause_during_maintenance") or {},
        kuma_crash_monitor_interval_minutes=raw.get("kuma_crash_monitor", {}).get("interval_minutes", 0),
        kb_immich_base_url=raw.get("kb_access_sync", {}).get("immich_base_url", ""),
        kb_access_group_id=raw.get("kb_access_sync", {}).get("access_group_id", ""),
        kb_access_sync_interval_hours=raw.get("kb_access_sync", {}).get("interval_hours", 0),
        kb_matrix_teamspeak_app_id=raw.get("kb_access_monitor", {}).get("app_id", ""),
        kb_admin_room_id=raw.get("kb_access_monitor", {}).get("admin_room_id", ""),
        kb_admin_bot_user_id=raw.get("kb_access_monitor", {}).get("admin_bot_user_id", ""),
        kb_access_monitor_interval_minutes=raw.get("kb_access_monitor", {}).get("interval_minutes", 0),
        kb_access_monitor_window_hours=raw.get("kb_access_monitor", {}).get("window_hours", 1.0),
        kb_new_logins_warn_threshold=raw.get("kb_access_monitor", {}).get("new_logins_warn_threshold", 10),
        kb_new_registrations_warn_threshold=raw.get("kb_access_monitor", {}).get("new_registrations_warn_threshold", 3),
        kb_loose_policy_id=raw.get("kb_lockdown", {}).get("loose_policy_id", ""),
        kb_strict_policy_id=raw.get("kb_lockdown", {}).get("strict_policy_id", ""),
        kb_registration_token_max_uses=raw.get("kb_lockdown", {}).get("registration_token_max_uses", 0),
        kb_registration_token_rotate_at_remaining=raw.get("kb_lockdown", {}).get(
            "registration_token_rotate_at_remaining", 1,
        ),
        wedding_access_request_app_id=raw.get("wedding_access_request", {}).get("app_id", ""),
        wedding_access_request_policy_id=raw.get("wedding_access_request", {}).get("policy_id", ""),
        wedding_access_request_grant_days=raw.get("wedding_access_request", {}).get("grant_days", 30),
        wedding_access_request_expiry_check_interval_hours=raw.get("wedding_access_request", {}).get(
            "expiry_check_interval_hours", 0,
        ),
        wedding_hub_db_path=raw.get("wedding_access_request", {}).get(
            "hub_db_path", "/opt/wedding-hub/wedding_hub.db",
        ),
        wedding_access_request_room_id=raw.get("wedding_access_request", {}).get("room_id", ""),
        wedding_access_request_date=raw.get("wedding_access_request", {}).get("wedding_date", ""),
        daily_briefing_morning_hour=raw.get("daily_briefing", {}).get("morning_hour", -1),
        daily_briefing_evening_hour=raw.get("daily_briefing", {}).get("evening_hour", -1),
        daily_briefing_poll_interval_minutes=raw.get("daily_briefing", {}).get("poll_interval_minutes", 15),
        teamspeak_version_check_interval_hours=raw.get("teamspeak", {}).get("version_check_interval_hours", 0),
        fortios_advisory_check_interval_hours=raw.get("fortigate", {}).get("advisory_check_interval_hours", 0),
        fortios_advisory_research_max_age_hours=raw.get("fortigate", {}).get(
            "advisory_research_max_age_hours", 168.0),
        ollama_version_check_interval_hours=raw.get("ollama", {}).get("version_check_interval_hours", 0),
        enshrouded_version_check_interval_hours=raw.get("enshrouded", {}).get("version_check_interval_hours", 0),
        tls_check_hostnames=raw.get("ops_health", {}).get("tls_check_hostnames", []),
        firewall_traffic_interval_minutes=raw.get("firewall_traffic", {}).get("interval_minutes", 0),
        wireguard_ssh_host=raw.get("wireguard", {}).get("ssh_host", ""),
        wireguard_ssh_user=raw.get("wireguard", {}).get("ssh_user", ""),
        caddy_rebuild_interval_hours=raw.get("caddy_rebuild", {}).get("interval_hours", 0),
        caddy_rebuild_targets=[
            CaddyRebuildTarget(
                name=t["name"],
                mechanism=t["mechanism"],
                ssh_host=t["ssh_host"],
                ssh_user=t["ssh_user"],
                container_name=t["container_name"],
                health_url=t["health_url"],
                compose_dir=t.get("compose_dir"),
                compose_service=t.get("compose_service"),
                build_context=t.get("build_context"),
                image_tag=t.get("image_tag"),
                portainer=PortainerConfig(
                    base_url=t["portainer_base_url"], stack_name=t["portainer_stack_name"],
                ) if t.get("portainer_base_url") else None,
            )
            for t in raw.get("caddy_rebuild", {}).get("targets", [])
        ],
        scheduled_maintenance=ScheduledMaintenanceConfig(**raw["scheduled_maintenance"])
            if raw.get("scheduled_maintenance") else ScheduledMaintenanceConfig(),
        nightly_auto_apply=NightlyAutoApplyConfig(**raw["nightly_auto_apply"])
            if raw.get("nightly_auto_apply") else NightlyAutoApplyConfig(),
        emergency_containment=EmergencyContainmentConfig(**raw["emergency_containment"])
            if raw.get("emergency_containment") else EmergencyContainmentConfig(),
        kernel_cve_watch=KernelCVEWatchConfig(**raw["kernel_cve_watch"])
            if raw.get("kernel_cve_watch") else KernelCVEWatchConfig(),
        docker_prune=DockerPruneConfig(**raw["docker_prune"])
            if raw.get("docker_prune") else DockerPruneConfig(),
        wifi_rf=WifiRfConfig(**raw["wifi_rf"])
            if raw.get("wifi_rf") else WifiRfConfig(),
        dashboard_port=raw.get("dashboard", {}).get("port", 8421),
        webhook_shared_secret=os.environ.get("DIUN_WEBHOOK_SECRET", ""),
        matrix_admin_user_ids=raw.get("matrix", {}).get("admin_user_ids", []),
        anthropic_api_key=os.environ.get("ANTHROPIC_API_KEY", ""),
        proxmox_token=os.environ.get("PROXMOX_TOKEN", ""),
        pbs_token=os.environ.get("PBS_TOKEN", ""),
        matrix_access_token=os.environ.get("MATRIX_ACCESS_TOKEN", ""),
        ssh_identity_file=os.environ.get("SSH_IDENTITY_FILE", ""),
        portainer_token=os.environ.get("PORTAINER_TOKEN", ""),
        immich_api_key=os.environ.get("IMMICH_API_KEY", ""),
        teamspeak_query_login=os.environ.get("TEAMSPEAK_QUERY_LOGIN", ""),
        teamspeak_query_password=os.environ.get("TEAMSPEAK_QUERY_PASSWORD", ""),
        uptime_kuma_username=os.environ.get("UPTIME_KUMA_USERNAME", ""),
        uptime_kuma_password=os.environ.get("UPTIME_KUMA_PASSWORD", ""),
        cloudflare_api_token=os.environ.get("CLOUDFLARE_API_TOKEN", ""),
        graph_client_id=os.environ.get("MS_GRAPH_CLIENT_ID", ""),
        graph_client_secret=os.environ.get("MS_GRAPH_CLIENT_SECRET", ""),
        graph_tenant_id=os.environ.get("MS_GRAPH_TENANT_ID", ""),
        librenms_api_token=os.environ.get("LIBRENMS_API_TOKEN", ""),
        homeassistant_api_token=os.environ.get("HOMEASSISTANT_API_TOKEN", ""),
        cloudflare_access_api_token=os.environ.get("CLOUDFLARE_ACCESS_API_TOKEN", ""),
        immich_users_api_key=os.environ.get("IMMICH_USERS_API_KEY", ""),
        matrix_admin_access_token=os.environ.get("MATRIX_ADMIN_ACCESS_TOKEN", ""),
        matrix_registration_token=os.environ.get("MATRIX_REGISTRATION_TOKEN", ""),
        coordination_room_id=raw.get("coordination", {}).get("room_id", ""),
        coordination_pass_bot_user_id=raw.get("coordination", {}).get("pass_bot_user_id", ""),
        coordination_pass_bot_mailboxes=[m.lower() for m in raw.get("coordination", {}).get("pass_bot_mailboxes", [])],
    )
