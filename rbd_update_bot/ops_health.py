"""Backup age, disk space, TLS expiry and node resource checks."""
from __future__ import annotations

import json
import shutil
import socket
import ssl
import subprocess
from datetime import datetime, timezone

from . import executor
from .config import ServiceConfig
from .proxmox import PBSClient, ProxmoxClient

_BACKUP_STALE_HOURS = 30

_PBS_JOB_TYPES = ("garbage_collection", "verificationjob", "prunejob", "syncjob")

_PBS_JOB_MAX_AGE_HOURS = {"syncjob": 8 * 24 + 6}
_PBS_DAILY_JOB_MAX_AGE_HOURS = 36

_CERT_WARNING_DAYS = 14


def collect_backup_status(proxmox: ProxmoxClient, pbs: PBSClient | None) -> tuple[list[dict], list[str]]:
    checks: list[dict] = []
    errors: list[str] = []
    now = datetime.now(timezone.utc)

    try:
        nodes = proxmox.list_nodes()
    except Exception as exc:
        return checks, [f"proxmox backup-status: couldn't list cluster nodes: {exc}"]

    for node in nodes:
        try:
            tasks = proxmox.recent_vzdump_tasks(node, limit=5)
            if not tasks:
                checks.append({
                    "check_id": f"backup:proxmox:{node}", "source": "backup_status",
                    "status": "no vzdump task found", "detail": "no recent vzdump task at all",
                    "is_bad": True,
                })
                continue
            latest = max(tasks, key=lambda t: t.get("starttime", 0))
            age_hours = (now.timestamp() - latest.get("starttime", 0)) / 3600
            is_bad = latest.get("status") != "OK" or age_hours > _BACKUP_STALE_HOURS
            checks.append({
                "check_id": f"backup:proxmox:{node}", "source": "backup_status",
                "status": latest.get("status"),
                "detail": f"last vzdump {latest.get('status')} {age_hours:.1f}h ago",
                "is_bad": is_bad,
            })
        except Exception as exc:
            errors.append(f"proxmox backup-status ({node}): {exc}")

    if pbs is not None:
        try:
            for job_type in _PBS_JOB_TYPES:
                matching = [t for t in pbs.recent_tasks(limit=5, typefilter=job_type)
                            if t.get("worker_type") == job_type]
                if not matching:
                    continue
                running = [t for t in matching if not t.get("status")]
                finished = [t for t in matching if t.get("status")]
                running_latest = max(running, key=lambda t: t.get("starttime", 0)) if running else None
                run_age = ((now.timestamp() - running_latest.get("starttime", 0)) / 3600
                           if running_latest else 0.0)
                stuck = running_latest is not None and run_age > _BACKUP_STALE_HOURS

                if finished:
                    latest = max(finished, key=lambda t: t.get("starttime", 0))
                    age_hours = (now.timestamp() - latest.get("starttime", 0)) / 3600
                    max_age = _PBS_JOB_MAX_AGE_HOURS.get(job_type, _PBS_DAILY_JOB_MAX_AGE_HOURS)
                    overdue = age_hours > max_age and running_latest is None
                    is_bad = latest.get("status") != "OK" or stuck or overdue
                    detail = f"last {job_type} {latest.get('status')} {age_hours:.1f}h ago"
                    if overdue:
                        detail += f" (overdue -- expected at least every {max_age}h)"
                    status = latest.get("status")
                else:
                    is_bad = stuck
                    detail = f"{job_type} no finished task in sample"
                    status = "running"
                if running_latest is not None:
                    detail += f"; run in progress {run_age:.1f}h" + (" (stale, may be hung)" if stuck else "")
                checks.append({
                    "check_id": f"backup:pbs:{job_type}", "source": "backup_status",
                    "status": status,
                    "detail": detail,
                    "is_bad": is_bad,
                })
        except Exception as exc:
            errors.append(f"pbs backup-status: {exc}")

    return checks, errors


def trigger_synology_backup_collect(
    host: str,
    user: str,
    *,
    synology_config_file: str,
    identity_file: str = "",
    timeout: float = 60.0,
) -> tuple[bool, list[dict], list[str]]:
    payload = json.dumps({
        "mode": "hyperbackup_collect",
        "synology": {"config_file": synology_config_file},
    })
    ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes"]
    if identity_file:
        ssh_cmd += ["-i", identity_file]
    ssh_cmd += [f"{user}@{host}", "true"]
    proc = subprocess.run(ssh_cmd, input=payload, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        return False, [], [f"SSH/collection failed: {proc.stderr.strip() or proc.stdout.strip()}"]

    try:
        body = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return False, [], [f"bad JSON from collector: {proc.stdout.strip()[:500]}"]

    jobs = body.get("backups", [])
    checks = [
        {
            "check_id": f"backup:synology:{job.get('backup_id')}", "source": "backup_status",
            "status": job.get("status"),
            "detail": f"{job.get('name')}: last run {job.get('status')} ({job.get('last_end_time')})",
            "is_bad": job.get("status") != "done",
        }
        for job in jobs
    ]
    checks.extend(body.get("dsm_system", []))
    return True, checks, body.get("errors", [])


def collect_node_resources(proxmox: ProxmoxClient, pbs: PBSClient | None, *,
                            warning_pct: float = 85.0, memory_warning_pct: float = 85.0,
                            cpu_warning_pct: float = 90.0, datastore: str = "wd-usb") -> tuple[list[dict], list[str]]:
    checks: list[dict] = []
    errors: list[str] = []

    try:
        nodes = proxmox.list_nodes()
    except Exception as exc:
        return checks, [f"proxmox node-resources: couldn't list cluster nodes: {exc}"]

    for node in nodes:
        try:
            status = proxmox.node_status(node)

            rootfs = status.get("rootfs", {})
            total, used = rootfs.get("total"), rootfs.get("used")
            pct = (used / total * 100) if total else 0
            checks.append({
                "check_id": f"space:proxmox:{node}", "source": "disk_space",
                "status": f"{pct:.1f}% used", "detail": f"{used}/{total} bytes",
                "is_bad": pct >= warning_pct,
            })

            mem = status.get("memory", {})
            mem_total, mem_used = mem.get("total"), mem.get("used")
            mem_pct = (mem_used / mem_total * 100) if mem_total else 0
            loadavg = status.get("loadavg", [])
            checks.append({
                "check_id": f"memory:proxmox:{node}", "source": "node_resources",
                "status": f"{mem_pct:.1f}% used",
                "detail": f"{mem_used}/{mem_total} bytes, loadavg {', '.join(loadavg)}",
                "is_bad": mem_pct >= memory_warning_pct,
            })

            cpu_pct = (status.get("cpu") or 0) * 100
            checks.append({
                "check_id": f"cpu:proxmox:{node}", "source": "node_resources",
                "status": f"{cpu_pct:.1f}% used",
                "detail": f"instantaneous reading at poll time, loadavg {', '.join(loadavg)}",
                "is_bad": cpu_pct >= cpu_warning_pct,
            })
        except Exception as exc:
            errors.append(f"proxmox node-resources ({node}): {exc}")

    if pbs is not None:
        try:
            status = pbs.datastore_status(datastore)
            total, used = status.get("total"), status.get("used")
            pct = (used / total * 100) if total else 0
            checks.append({
                "check_id": f"space:pbs:{datastore}", "source": "disk_space",
                "status": f"{pct:.1f}% used", "detail": f"{used}/{total} bytes",
                "is_bad": pct >= warning_pct,
            })
        except Exception as exc:
            errors.append(f"pbs disk-space: {exc}")

    return checks, errors


def collect_local_disk(*, warning_pct: float = 85.0, path: str = "/") -> tuple[list[dict], list[str]]:
    try:
        usage = shutil.disk_usage(path)
    except OSError as exc:
        return [], [f"local disk ({path}): {exc}"]
    pct = usage.used / usage.total * 100 if usage.total else 0
    return [{
        "check_id": "space:local:rbd-update-bot", "source": "disk_space",
        "status": f"{pct:.1f}% used", "detail": f"{usage.used}/{usage.total} bytes on {path}",
        "is_bad": pct >= warning_pct,
    }], []


def collect_guest_resources(services: dict[str, ServiceConfig], *,
                             memory_warning_pct: float = 85.0, load_warning_ratio: float = 1.0,
                             disk_warning_pct: float = 85.0, identity_file: str = "",
                             mgmt_host: str = "", mgmt_ssh_user: str = "") -> tuple[list[dict], list[str]]:
    checks: list[dict] = []
    errors: list[str] = []

    for name, service in services.items():
        if not service.ssh_host:
            continue
        try:
            info = executor.guest_resource_info(
                service, identity_file=identity_file,
                mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
            )
        except Exception as exc:
            errors.append(f"guest-resources ({name}): {exc}")
            continue
        if info is None:
            errors.append(f"guest-resources ({name}): unreachable or unparseable response")
            continue

        mem_pct = (info["mem_used"] / info["mem_total"] * 100) if info["mem_total"] else 0
        checks.append({
            "check_id": f"memory:guest:{name}", "source": "guest_resources",
            "status": f"{mem_pct:.1f}% used", "detail": f"{info['mem_used']}/{info['mem_total']} bytes",
            "is_bad": mem_pct >= memory_warning_pct,
        })

        load_ratio = (info["load1"] / info["nproc"]) if info["nproc"] else 0
        checks.append({
            "check_id": f"cpu:guest:{name}", "source": "guest_resources",
            "status": f"load1 {info['load1']:.2f} / {info['nproc']} cores",
            "detail": "instantaneous reading at poll time",
            "is_bad": load_ratio >= load_warning_ratio,
        })

        checks.append({
            "check_id": f"space:guest:{name}", "source": "guest_resources",
            "status": f"{info['disk_pct']:.1f}% used", "detail": "root filesystem",
            "is_bad": info["disk_pct"] >= disk_warning_pct,
        })

        checks.append({
            "check_id": f"swap:guest:{name}", "source": "guest_resources",
            "status": "no swap configured" if info["swap_total"] == 0 else "swap configured",
            "detail": f"{info['swap_total']} bytes total",
            "is_bad": info["swap_total"] == 0,
        })

        if info["oom_readable"]:
            checks.append({
                "check_id": f"oom:guest:{name}", "source": "guest_incident",
                "status": f"{len(info['oom_lines'])} OOM-killer event(s)" if info["oom_lines"] else "none",
                "detail": "; ".join(info["oom_lines"]) if info["oom_lines"] else "no OOM events in lookback window",
                "is_bad": bool(info["oom_lines"]),
            })
        else:
            errors.append(f"guest-resources ({name}): couldn't read kernel log for OOM events")

        if info["db_unit"]:
            checks.append({
                "check_id": f"db:guest:{name}:{info['db_unit']}", "source": "guest_incident",
                "status": info["db_unit_state"] or "unknown",
                "detail": f"systemctl is-active {info['db_unit']}",
                "is_bad": info["db_unit_state"] != "active",
            })

    return checks, errors


def collect_db_container_health(services: dict[str, ServiceConfig], *,
                                  identity_file: str = "", mgmt_host: str = "",
                                  mgmt_ssh_user: str = "") -> tuple[list[dict], list[str]]:
    checks: list[dict] = []
    errors: list[str] = []

    for name, service in services.items():
        for container in service.db_containers:
            try:
                result = executor.postgres_container_ready(
                    service, container, identity_file=identity_file,
                    mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
                )
            except Exception as exc:
                errors.append(f"db-container ({name}/{container}): {exc}")
                continue
            if result is None:
                errors.append(f"db-container ({name}/{container}): couldn't reach the container at all")
                continue
            checks.append({
                "check_id": f"db:container:{name}:{container}", "source": "guest_incident",
                "status": result, "detail": f"pg_isready inside {container}",
                "is_bad": result != "accepting connections",
            })

        if service.internal_db_container and service.internal_db_programs:
            try:
                up = executor.sv_status_running(
                    service, service.internal_db_container, service.internal_db_programs,
                    identity_file=identity_file, mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
                )
            except Exception as exc:
                errors.append(f"db-container ({name} internal): {exc}")
                continue
            if up is None:
                errors.append(
                    f"db-container ({name} internal): couldn't query {service.internal_db_container} at all"
                )
                continue
            down = [p for p in service.internal_db_programs if p not in up]
            checks.append({
                "check_id": f"db:internal:{name}", "source": "guest_incident",
                "status": "all running" if not down else f"down: {', '.join(down)}",
                "detail": f"sv status inside {service.internal_db_container}: {service.internal_db_programs}",
                "is_bad": bool(down),
            })

    return checks, errors


def collect_auth_gates(services: dict[str, ServiceConfig], *, identity_file: str = "",
                       mgmt_host: str = "", mgmt_ssh_user: str = "") -> tuple[list[dict], list[str]]:
    checks: list[dict] = []
    errors: list[str] = []
    for name, service in services.items():
        if service.systemd_service != "ollama":
            continue
        codes = executor.ollama_auth_gate_probe(
            service, identity_file=identity_file, mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
        )
        if codes is None:
            errors.append(f"auth-gate ({name}): probe couldn't run")
            continue
        gate = codes[executor._OLLAMA_GATE_PORT]
        backend = codes[executor._OLLAMA_BACKEND_PORT]
        problems = []
        if gate != "401":
            problems.append(f":{executor._OLLAMA_GATE_PORT} answered {gate} without a key (expected 401)")
        if backend != "000":
            problems.append(f":{executor._OLLAMA_BACKEND_PORT} (Ollama itself) answered {backend} from the LAN "
                            f"(expected refused)")
        checks.append({
            "check_id": f"auth_gate:{name}", "source": "auth_gate",
            "status": "; ".join(problems) if problems else "enforcing",
            "detail": f"unauthenticated GET /api/tags via {service.ssh_host}: "
                      f":{executor._OLLAMA_GATE_PORT}={gate}, :{executor._OLLAMA_BACKEND_PORT}={backend}",
            "is_bad": bool(problems),
        })
    return checks, errors


def collect_capacity_trend(proxmox: ProxmoxClient, nodes: list[str], *,
                            warning_pct: float = 85.0, min_current_pct: float = 60.0,
                            lookahead_days: float = 14.0,
                            slope_window_days: float = 3.0) -> tuple[list[dict], list[str]]:
    checks: list[dict] = []
    errors: list[str] = []
    try:
        guests = proxmox.cluster_vm_resources()
    except Exception as exc:
        guests = []
        errors.append(f"proxmox capacity-trend: couldn't list guests: {exc}")
    gib = 1024 ** 3

    for node in nodes:
        try:
            samples = proxmox.node_rrd_data(node, "week")
        except Exception as exc:
            errors.append(f"proxmox capacity-trend ({node}): {exc}")
            continue

        points = [
            (s["time"], s["memused"] / s["memtotal"] * 100)
            for s in samples
            if s.get("time") is not None and s.get("memused") is not None and s.get("memtotal")
        ]
        if len(points) < 2:
            continue

        t0, pct0 = points[0]
        t1, pct1 = points[-1]
        days_elapsed = (t1 - t0) / 86400
        if days_elapsed <= 0:
            continue

        recent = [(t, v) for t, v in points if t >= t1 - slope_window_days * 86400]
        if len(recent) < 2:
            recent = points
        n = len(recent)
        mean_t = sum(t for t, _ in recent) / n
        mean_v = sum(v for _, v in recent) / n
        var_t = sum((t - mean_t) ** 2 for t, _ in recent)
        slope_pct_per_day = (
            sum((t - mean_t) * (v - mean_v) for t, v in recent) / var_t * 86400 if var_t else 0.0
        )
        slope_days = (recent[-1][0] - recent[0][0]) / 86400
        current_pct = pct1

        node_total = next((s["memtotal"] for s in reversed(samples) if s.get("memtotal")), None)
        node_guests = [g for g in guests if g.get("node") == node]
        alloc_running = sum(g.get("maxmem") or 0 for g in node_guests if g.get("status") == "running")
        alloc_stopped = sum(g.get("maxmem") or 0 for g in node_guests
                            if g.get("status") != "running" and not g.get("template"))
        alloc_note = ""
        if node_total and node_guests:
            alloc_note = (f"; running guests allocated {alloc_running / gib:.1f} of "
                          f"{node_total / gib:.1f} GiB")
            if alloc_stopped:
                alloc_note += f", stopped guests would add {alloc_stopped / gib:.1f} GiB"

        if slope_pct_per_day > 0 and min_current_pct <= current_pct < warning_pct:
            days_to_threshold = (warning_pct - current_pct) / slope_pct_per_day
        else:
            days_to_threshold = None

        is_bad = days_to_threshold is not None and days_to_threshold <= lookahead_days

        if slope_pct_per_day > 0:
            trend_desc = f"+{slope_pct_per_day:.2f}%/day over {slope_days:.1f}d"
            if days_to_threshold is not None:
                trend_desc += f" -- projected to cross {warning_pct:.0f}% in ~{days_to_threshold:.0f}d"
        else:
            trend_desc = f"flat/declining ({slope_pct_per_day:.2f}%/day) over {slope_days:.1f}d"

        checks.append({
            "check_id": f"capacity_trend:proxmox:{node}:memory", "source": "capacity_trend",
            "status": f"{current_pct:.1f}% now, {trend_desc}",
            "detail": f"week RRD: {pct0:.1f}% -> {current_pct:.1f}% over {days_elapsed:.1f}d{alloc_note}",
            "is_bad": is_bad,
        })

    return checks, errors


def _resolve_public_ip(hostname: str) -> str | None:
    try:
        result = subprocess.run(
            ["dig", "@1.1.1.1", hostname, "+short", "A"],
            capture_output=True, text=True, timeout=10,
        )
        ips = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return ips[0] if ips else None
    except Exception:
        return None


def _cert_days_remaining(hostname: str, ip: str | None, *, port: int = 443, timeout: float = 10.0) -> int:
    context = ssl.create_default_context()
    target = ip or hostname
    with socket.create_connection((target, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    return (not_after - datetime.now(timezone.utc)).days


def collect_cert_expiry(hostnames: list[str]) -> tuple[list[dict], list[str]]:
    checks: list[dict] = []
    errors: list[str] = []

    for hostname in hostnames:
        try:
            days = _cert_days_remaining(hostname, None)
            checks.append({
                "check_id": f"cert:{hostname}:internal", "source": "cert_expiry",
                "status": f"{days}d remaining", "detail": f"internal cert for {hostname}",
                "is_bad": days < _CERT_WARNING_DAYS,
            })
        except Exception as exc:
            errors.append(f"cert check ({hostname}, internal): {exc}")

        public_ip = _resolve_public_ip(hostname)
        if public_ip is None:
            errors.append(f"cert check ({hostname}, public): could not resolve via public DNS")
            continue
        try:
            days = _cert_days_remaining(hostname, public_ip)
            checks.append({
                "check_id": f"cert:{hostname}:public", "source": "cert_expiry",
                "status": f"{days}d remaining", "detail": f"public cert for {hostname} ({public_ip})",
                "is_bad": days < _CERT_WARNING_DAYS,
            })
        except Exception as exc:
            errors.append(f"cert check ({hostname}, public): {exc}")

    return checks, errors
