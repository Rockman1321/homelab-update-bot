"""Runs the version bump on a target VM over SSH and watches its logs afterward."""
from __future__ import annotations

import base64
import logging
import os
import re
import shlex
import subprocess
import time

from . import ollama as ollama_client
from . import portainer as portainer_client
from . import teamspeak
from .config import ServiceConfig

logger = logging.getLogger(__name__)

_ERROR_PATTERNS = ("FATAL", "PANIC", "Traceback (most recent call last)", "OOMKilled")

_SAFE_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9/_.-]*$")
_SAFE_TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")

COMPOSE_BACKUP_DIR = "compose-backups"

ENV_BACKUP_DIR = "env-backups"


def _ssh_run(host: str, user: str, command: str, *, identity_file: str = "",
             timeout: float = 1800.0) -> tuple[bool, str]:
    ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=3"]
    if identity_file:
        ssh_cmd += ["-i", identity_file]
    ssh_cmd += [f"{user}@{host}", command]
    try:
        proc = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, f"ssh timed out after {timeout:.0f}s"
    return proc.returncode == 0, (proc.stdout + proc.stderr)


def _ssh_relay_aware(service: ServiceConfig, command: str, *, identity_file: str = "",
                      timeout: float = 1800.0, mgmt_host: str = "", mgmt_ssh_user: str = "") -> tuple[bool, str]:
    if service.relay_through_mgmt:
        return ollama_client.relay_ssh_run(
            mgmt_host, mgmt_ssh_user,
            target_ssh_host=service.ssh_host, target_ssh_user=service.ssh_user,
            command=command, identity_file=identity_file, timeout=timeout,
        )
    return _ssh_run(service.ssh_host, service.ssh_user, command, identity_file=identity_file, timeout=timeout)


def read_remote_file(service: ServiceConfig, path: str, *, identity_file: str = "",
                      mgmt_host: str = "", mgmt_ssh_user: str = "") -> str | None:
    ok, out = _ssh_relay_aware(
        service, f"cat {path}", identity_file=identity_file,
        mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user, timeout=15,
    )
    return out.strip() if ok else None


def run_remote_command(service: ServiceConfig, command: str, *, identity_file: str = "",
                        mgmt_host: str = "", mgmt_ssh_user: str = "", timeout: float = 30.0) -> tuple[bool, str]:
    return _ssh_relay_aware(
        service, command, identity_file=identity_file,
        mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user, timeout=timeout,
    )


def _ssh_run_with_stdin(host: str, user: str, command: str, stdin_data: str, *,
                         identity_file: str = "", timeout: float = 60.0) -> tuple[bool, str]:
    ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new"]
    if identity_file:
        ssh_cmd += ["-i", identity_file]
    ssh_cmd += [f"{user}@{host}", command]
    try:
        proc = subprocess.run(ssh_cmd, input=stdin_data, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, f"ssh timed out after {timeout:.0f}s"
    return proc.returncode == 0, (proc.stdout + proc.stderr)


def backup_compose_file(service: ServiceConfig, update_id: int, *, identity_file: str = "") -> tuple[bool, str]:
    compose_file = f"{service.compose_dir}/docker-compose.yml"
    local_backup = f"{compose_file}.bak-{update_id}"

    ok, detail = _ssh_run(
        service.ssh_host, service.ssh_user, f"sudo cp {compose_file} {local_backup}",
        identity_file=identity_file,
    )
    if not ok:
        return False, f"local backup failed: {detail}"

    ok, content = _ssh_run(service.ssh_host, service.ssh_user, f"cat {compose_file}", identity_file=identity_file)
    if not ok:
        return False, f"could not read compose file for off-VM backup: {content}"

    os.makedirs(COMPOSE_BACKUP_DIR, exist_ok=True)
    os.chmod(COMPOSE_BACKUP_DIR, 0o700)
    off_vm_path = os.path.join(COMPOSE_BACKUP_DIR, f"{service.name}-{update_id}.yml")
    with open(off_vm_path, "w") as f:
        f.write(content)
    os.chmod(off_vm_path, 0o600)

    return True, off_vm_path


def rollback_compose_file(service: ServiceConfig, update_id: int, *, identity_file: str = "") -> tuple[bool, str]:
    if service.registry is not None:
        return False, (
            f"{service.name} floats on tag registry resolution (its compose file's tag string "
            f"never changes between versions) -- restoring the file wouldn't revert the running "
            f"image. This needs a VM-level (Proxmox/PBS) or file-level (Kopia) restore instead."
        )

    off_vm_path = os.path.join(COMPOSE_BACKUP_DIR, f"{service.name}-{update_id}.yml")
    if not os.path.exists(off_vm_path):
        return False, f"no off-VM backup found at {off_vm_path}"
    with open(off_vm_path) as f:
        content = f.read()

    compose_file = f"{service.compose_dir}/docker-compose.yml"
    ok, detail = _ssh_run_with_stdin(
        service.ssh_host, service.ssh_user,
        f"sudo tee {compose_file}.new > /dev/null && sudo cp {compose_file}.new {compose_file} "
        f"&& sudo rm {compose_file}.new",
        content, identity_file=identity_file,
    )
    if not ok:
        return False, f"restoring the compose file failed: {detail}"

    return _ssh_run(
        service.ssh_host, service.ssh_user, f"cd {service.compose_dir} && docker compose up -d",
        identity_file=identity_file,
    )


def redeploy_pinned_digest(
    service: ServiceConfig, image: str, digest: str, *, identity_file: str = "",
) -> tuple[bool, str]:
    compose_file = f"{service.compose_dir}/docker-compose.yml"
    pinned_ref = f"{image}@{digest}"
    command = (
        f"sed 's|image: {image}:.*|image: {pinned_ref}|' {compose_file} "
        f"| sudo tee {compose_file}.new > /dev/null "
        f"&& sudo cp {compose_file}.new {compose_file} && sudo rm {compose_file}.new "
        f"&& cd {service.compose_dir} && docker compose pull && docker compose up -d --force-recreate"
    )
    return _ssh_run(service.ssh_host, service.ssh_user, command, identity_file=identity_file, timeout=300.0)


def restore_library_backup_and_redeploy(
    service: ServiceConfig, image: str, digest: str, *, identity_file: str = "",
) -> tuple[bool, str]:
    data_dir = f"{service.compose_dir}/data"
    compose_file = f"{service.compose_dir}/docker-compose.yml"
    pinned_ref = f"{image}@{digest}"
    command = (
        f"cd {service.compose_dir} && docker compose stop "
        f"&& sudo cp {data_dir}/library.db.backup {data_dir}/library.db "
        f"&& sudo rm {data_dir}/library.db-wal {data_dir}/library.db-shm -f "
        f"&& sed 's|image: {image}:.*|image: {pinned_ref}|' {compose_file} "
        f"| sudo tee {compose_file}.new > /dev/null "
        f"&& sudo cp {compose_file}.new {compose_file} && sudo rm {compose_file}.new "
        f"&& docker compose pull && docker compose up -d --force-recreate"
    )
    ok, detail = _ssh_run(service.ssh_host, service.ssh_user, command, identity_file=identity_file, timeout=300.0)
    if not ok:
        return False, f"restore-and-redeploy failed (container may be stopped, check manually): {detail}"
    return True, detail


def restore_immich_database(service: ServiceConfig, *, identity_file: str = "") -> tuple[bool, str]:
    find_backup = (
        "ls -t /mnt/immich_media/backups/immich-db-backup-*.sql.gz 2>/dev/null | head -1"
    )
    ok, backup_path = _ssh_run(service.ssh_host, service.ssh_user, find_backup, identity_file=identity_file)
    backup_path = backup_path.strip()
    if not ok or not backup_path:
        return False, "no backup-database dump found under /mnt/immich_media/backups"

    command = (
        f"docker stop immich_server immich_machine_learning "
        f"&& docker exec immich_postgres psql -U postgres -c 'DROP DATABASE IF EXISTS immich WITH (FORCE);' "
        f"&& docker exec immich_postgres psql -U postgres -c 'CREATE DATABASE immich;' "
        f"&& gunzip -c {backup_path} | docker exec -i immich_postgres "
        f"psql -U postgres -d immich --single-transaction --set ON_ERROR_STOP=on"
    )
    ok, detail = _ssh_run(service.ssh_host, service.ssh_user, command, identity_file=identity_file, timeout=600.0)
    if not ok:
        return False, f"database restore failed (app containers are stopped, check manually): {detail}"
    return True, f"restored {backup_path} into a freshly recreated immich database"


_NEXTCLOUD_DUMP_RETENTION = 3


def trigger_nextcloud_db_backup(service: ServiceConfig, *, identity_file: str = "") -> tuple[bool, str]:
    if service.db_backup is None:
        return False, f"{service.name} has no db_backup configured -- nothing to dump"

    dump_path = f"{service.compose_dir}/nextcloud-db-backup-{int(time.time())}.sql.gz"
    command = (
        f"docker exec {service.db_backup.container} sh -c "
        f"'pg_dump -U \"$POSTGRES_USER\" \"$POSTGRES_DB\"' | gzip > {dump_path} "
        f"&& ls -t {service.compose_dir}/nextcloud-db-backup-*.sql.gz "
        f"| tail -n +{_NEXTCLOUD_DUMP_RETENTION + 1} | xargs -r rm --"
    )
    ok, detail = _ssh_run(service.ssh_host, service.ssh_user, command, identity_file=identity_file, timeout=600.0)
    if not ok:
        return False, f"pg_dump failed: {detail}"
    return True, dump_path


def restore_nextcloud_database(service: ServiceConfig, *, identity_file: str = "") -> tuple[bool, str]:
    if service.db_backup is None:
        return False, f"{service.name} has no db_backup configured -- can't restore"
    db_container = service.db_backup.container
    app_containers = " ".join(service.log_watch_containers)

    find_backup = f"ls -t {service.compose_dir}/nextcloud-db-backup-*.sql.gz 2>/dev/null | head -1"
    ok, dump_path = _ssh_run(service.ssh_host, service.ssh_user, find_backup, identity_file=identity_file)
    dump_path = dump_path.strip()
    if not ok or not dump_path:
        return False, f"no nextcloud-db-backup-*.sql.gz dump found under {service.compose_dir}"

    if service.occ_container:
        _ssh_run(
            service.ssh_host, service.ssh_user,
            f"docker exec -u www-data {service.occ_container} php occ maintenance:mode --on",
            identity_file=identity_file,
        )

    command = (
        f"docker stop {app_containers} "
        f"&& docker exec {db_container} sh -c "
        f"'psql -U \"$POSTGRES_USER\" -d postgres -c \"DROP DATABASE IF EXISTS $POSTGRES_DB WITH (FORCE);\"' "
        f"&& docker exec {db_container} sh -c "
        f"'psql -U \"$POSTGRES_USER\" -d postgres -c \"CREATE DATABASE $POSTGRES_DB;\"' "
        f"&& gunzip -c {dump_path} | docker exec -i {db_container} sh -c "
        f"'psql -U \"$POSTGRES_USER\" -d \"$POSTGRES_DB\" --single-transaction --set ON_ERROR_STOP=on' "
        f"&& docker start {app_containers}"
    )
    ok, detail = _ssh_run(service.ssh_host, service.ssh_user, command, identity_file=identity_file, timeout=600.0)

    if service.occ_container:
        _ssh_run(
            service.ssh_host, service.ssh_user,
            f"docker exec -u www-data {service.occ_container} php occ maintenance:mode --off "
            f"&& docker exec -u www-data {service.occ_container} php occ maintenance:repair",
            identity_file=identity_file,
        )

    if not ok:
        return False, f"database restore failed (app containers may be stopped, check manually): {detail}"
    return True, f"restored {dump_path} into a freshly recreated {service.name} database"


def backup_env_file(service: ServiceConfig, update_id: int, *, identity_file: str = "") -> tuple[bool, str | None]:
    if not service.compose_dir:
        return True, None
    env_file = f"{service.compose_dir}/.env"

    exists, _ = _ssh_run(service.ssh_host, service.ssh_user, f"test -f {env_file}", identity_file=identity_file)
    if not exists:
        return True, None

    local_backup = f"{env_file}.bak-{update_id}"
    ok, detail = _ssh_run(
        service.ssh_host, service.ssh_user, f"sudo cp {env_file} {local_backup}",
        identity_file=identity_file,
    )
    if not ok:
        return False, f"local .env backup failed: {detail}"

    ok, content = _ssh_run(service.ssh_host, service.ssh_user, f"cat {env_file}", identity_file=identity_file)
    if not ok:
        return False, f"could not read .env for off-VM backup: {content}"

    os.makedirs(ENV_BACKUP_DIR, exist_ok=True)
    os.chmod(ENV_BACKUP_DIR, 0o700)
    off_vm_path = os.path.join(ENV_BACKUP_DIR, f"{service.name}-{update_id}.env")
    with open(off_vm_path, "w") as f:
        f.write(content)
    os.chmod(off_vm_path, 0o600)

    return True, off_vm_path


def check_and_restore_env(service: ServiceConfig, update_id: int, *, identity_file: str = "") -> tuple[bool, str]:
    off_vm_path = os.path.join(ENV_BACKUP_DIR, f"{service.name}-{update_id}.env")
    if not os.path.exists(off_vm_path):
        return False, "no .env backup was taken for this update (service has no separate .env)"
    with open(off_vm_path) as f:
        backed_up_content = f.read()
    if not backed_up_content.strip():
        return False, "backed-up .env was already empty -- nothing meaningful to restore"

    if not service.compose_dir:
        return False, "no compose_dir configured"
    env_file = f"{service.compose_dir}/.env"
    ok, current_content = _ssh_run(service.ssh_host, service.ssh_user, f"cat {env_file}", identity_file=identity_file)
    if ok and current_content.strip():
        return False, "no change detected -- .env still has content"

    ok, detail = _ssh_run_with_stdin(
        service.ssh_host, service.ssh_user,
        f"sudo tee {env_file}.new > /dev/null && sudo cp {env_file}.new {env_file} "
        f"&& sudo rm {env_file}.new",
        backed_up_content, identity_file=identity_file,
    )
    if not ok:
        return False, f"detected the .env was cleared, but restoring it failed: {detail}"
    return True, f"detected the .env was cleared and automatically restored it ({len(backed_up_content)} bytes)"


def get_discourse_git_commit(service: ServiceConfig, *, identity_file: str = "") -> str | None:
    ok, out = _ssh_run(
        service.ssh_host, service.ssh_user,
        "docker exec app bash -c '"
        "git config --global --add safe.directory /var/www/discourse 2>/dev/null; "
        "cd /var/www/discourse && git rev-parse HEAD'",
        identity_file=identity_file, timeout=30,
    )
    if not ok:
        return None
    commit = out.strip()
    return commit if re.fullmatch(r"[0-9a-f]{40}", commit) else None


def list_upgradable_packages(service: ServiceConfig, *, identity_file: str = "",
                              mgmt_host: str = "", mgmt_ssh_user: str = "") -> str:
    ok, out = _ssh_relay_aware(
        service, "apt list --upgradable 2>/dev/null",
        identity_file=identity_file, timeout=60, mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
    )
    return out.strip() if ok else f"(couldn't list pending packages: {out.strip()})"


def list_installed_kernel_packages(service: ServiceConfig, *, identity_file: str = "",
                                   mgmt_host: str = "", mgmt_ssh_user: str = "") -> str:
    ok, out = _ssh_relay_aware(
        service,
        "dpkg-query -W -f='${db:Status-Abbrev} ${Package} ${Version}\\n' 'linux-image-*' 2>/dev/null "
        "| awk '$1==\"ii\"{print $2, $3}'",
        identity_file=identity_file, timeout=30, mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
    )
    return out.strip() if ok else ""


def reboot_required(service: ServiceConfig, *, identity_file: str = "",
                     mgmt_host: str = "", mgmt_ssh_user: str = "") -> bool:
    _, out = _ssh_relay_aware(
        service, "test -e /var/run/reboot-required && echo REBOOT_REQUIRED || echo OK",
        identity_file=identity_file, timeout=30, mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
    )
    return "REBOOT_REQUIRED" in out


def prune_docker_images(service: ServiceConfig, *, identity_file: str = "",
                         mgmt_host: str = "", mgmt_ssh_user: str = "") -> tuple[bool, str]:
    ok, out = _ssh_relay_aware(
        service,
        "command -v docker >/dev/null 2>&1 && { docker image prune -f; docker builder prune -f; } "
        "|| echo 'no docker on this host'",
        identity_file=identity_file, timeout=300, mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
    )
    return ok, out.strip()


def prune_local_docker() -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            ["bash", "-c", "command -v docker >/dev/null 2>&1 && "
             "{ docker image prune -f; docker builder prune -f; } || echo 'no docker on this host'"],
            capture_output=True, text=True, timeout=300,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    return proc.returncode == 0, (proc.stdout + proc.stderr).strip()

_OLLAMA_GATE_PORT = 11434
_OLLAMA_BACKEND_PORT = 11435
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def ollama_auth_gate_command(host_ip: str) -> str:
    return (f"for p in {_OLLAMA_GATE_PORT} {_OLLAMA_BACKEND_PORT}; do printf '%s:' $p; "
            f"curl -s -o /dev/null -w '%{{http_code}}' -m 5 http://{host_ip}:$p/api/tags; echo; done; true")


def ollama_auth_gate_probe(service: ServiceConfig, *, identity_file: str = "",
                           mgmt_host: str = "", mgmt_ssh_user: str = "") -> dict[int, str] | None:
    if not _IPV4_RE.match(service.ssh_host or ""):
        return None
    ok, out = _ssh_relay_aware(
        service, ollama_auth_gate_command(service.ssh_host), identity_file=identity_file,
        mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user, timeout=30,
    )
    if not ok:
        return None
    codes: dict[int, str] = {}
    for line in out.splitlines():
        m = re.match(r"^(\d+):(\d{3})$", line.strip())
        if m:
            codes[int(m.group(1))] = m.group(2)
    return codes if {_OLLAMA_GATE_PORT, _OLLAMA_BACKEND_PORT} <= codes.keys() else None


def kernel_version_info(service: ServiceConfig, *, identity_file: str = "",
                         mgmt_host: str = "", mgmt_ssh_user: str = "") -> tuple[str, str, str] | None:
    ok, out = _ssh_relay_aware(
        service,
        'echo "KERNEL:$(uname -r)"; . /etc/os-release 2>/dev/null; echo "DISTRO:$PRETTY_NAME"; '
        'echo "VIRT:$(systemd-detect-virt --container 2>/dev/null)"; '
        'echo "PKGVER:$(dpkg-query -W -f=\'${Version}\' linux-image-$(uname -r) 2>/dev/null)"',
        identity_file=identity_file, timeout=15, mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
    )
    if not ok:
        return None
    values: dict[str, str] = {}
    for line in out.strip().splitlines():
        key, sep, val = line.partition(":")
        if sep and key in ("KERNEL", "DISTRO", "PKGVER", "VIRT"):
            values[key] = val.strip()
    if values.get("VIRT", "") == "lxc":
        return None
    kernel_version, distro = values.get("KERNEL", ""), values.get("DISTRO", "")
    if not kernel_version or not distro:
        return None
    return distro, kernel_version, values.get("PKGVER", "")


def guest_resource_info(service: ServiceConfig, *, oom_lookback_hours: float = 13.0,
                         identity_file: str = "", mgmt_host: str = "",
                         mgmt_ssh_user: str = "") -> dict | None:
    db_unit = service.db_systemd_unit
    command = (
        "free -b | awk '/^Mem:/{print \"MEM_TOTAL:\"$2; print \"MEM_USED:\"$3}"
        "/^Swap:/{print \"SWAP_TOTAL:\"$2}'; "
        "echo \"LOAD1:$(cut -d' ' -f1 /proc/loadavg)\"; "
        "echo \"NPROC:$(nproc)\"; "
        "echo \"DISK_PCT:$(df -P / | awk 'NR==2{print $5}' | tr -d '%')\"; "
        f"OOM_RAW=$(journalctl -k --since '-{oom_lookback_hours:.1f} hours' --no-pager 2>&1); "
        'echo "OOM_STATUS:$?"; '
        'echo "OOM:$(echo "$OOM_RAW" | grep -iE \'out of memory|oom-kill\' | tail -3 | base64 -w0)"'
        + (f'; echo "DB_UNIT_STATE:$(systemctl is-active {shlex.quote(db_unit)} 2>&1)"' if db_unit else "")
    )
    ok, out = _ssh_relay_aware(
        service, command, identity_file=identity_file, timeout=30,
        mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
    )
    if not ok:
        logger.warning("guest_resource_info(%s): ssh failed: %s", service.ssh_host, out.strip()[:300])
        return None
    values: dict[str, str] = {}
    for line in out.strip().splitlines():
        key, sep, val = line.partition(":")
        if sep:
            values[key] = val.strip()

    try:
        mem_total, mem_used = int(values["MEM_TOTAL"]), int(values["MEM_USED"])
        swap_total = int(values["SWAP_TOTAL"])
        load1, nproc = float(values["LOAD1"]), int(values["NPROC"])
        disk_pct = float(values["DISK_PCT"])
    except (KeyError, ValueError) as exc:
        logger.warning("guest_resource_info(%s): unparseable (%r): %r", service.ssh_host, exc, out[:300])
        return None

    oom_readable = values.get("OOM_STATUS") == "0"
    oom_lines: list[str] = []
    if oom_readable:
        try:
            oom_lines = [
                ln for ln in base64.b64decode(values.get("OOM", "")).decode(errors="replace").splitlines()
                if ln.strip()
            ]
        except Exception:
            oom_lines = []

    return {
        "mem_total": mem_total, "mem_used": mem_used, "swap_total": swap_total,
        "load1": load1, "nproc": nproc, "disk_pct": disk_pct,
        "oom_readable": oom_readable, "oom_lines": oom_lines,
        "db_unit": db_unit, "db_unit_state": values.get("DB_UNIT_STATE"),
    }


def postgres_container_ready(service: ServiceConfig, container: str, *, identity_file: str = "",
                              mgmt_host: str = "", mgmt_ssh_user: str = "") -> str | None:
    _, out = _ssh_relay_aware(
        service, f"docker exec {shlex.quote(container)} pg_isready 2>&1",
        identity_file=identity_file, timeout=30, mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
    )
    out = out.strip()
    if not out:
        return None
    for phrase in ("accepting connections", "rejecting connections", "no response", "no attempt"):
        if phrase in out:
            return phrase
    return out


def sv_status_running(service: ServiceConfig, container: str, programs: list[str], *,
                       identity_file: str = "", mgmt_host: str = "",
                       mgmt_ssh_user: str = "") -> list[str] | None:
    cmd = f"docker exec {shlex.quote(container)} sv status " + " ".join(shlex.quote(p) for p in programs)
    _, out = _ssh_relay_aware(
        service, cmd, identity_file=identity_file, timeout=30,
        mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
    )
    lines = [ln.strip() for ln in out.strip().splitlines() if ln.strip()]
    if not lines:
        return None
    up = []
    for line in lines:
        for program in programs:
            if line.startswith(f"run: {program}:"):
                up.append(program)
    return up


def apply_os_patch(service: ServiceConfig, *, identity_file: str = "",
                    mgmt_host: str = "", mgmt_ssh_user: str = "") -> tuple[bool, str]:
    command = "sudo apt-get update && sudo apt-get -y full-upgrade"
    ok, out = _ssh_relay_aware(
        service, command, identity_file=identity_file, timeout=1800,
        mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
    )
    attempts = 1
    while not ok and attempts < 5 and "Could not get lock" in out:
        time.sleep(90)
        attempts += 1
        ok, out = _ssh_relay_aware(
            service, command, identity_file=identity_file, timeout=1800,
            mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
        )
    if not ok:
        return False, out.strip()
    reboot_note = "\n\nReboot required: YES" if reboot_required(
        service, identity_file=identity_file, mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
    ) else "\n\nReboot required: no"
    return True, out.strip() + reboot_note


def active_sessions(service: ServiceConfig, *, identity_file: str = "",
                     mgmt_host: str = "", mgmt_ssh_user: str = "") -> str:
    ok, out = _ssh_relay_aware(
        service, "who", identity_file=identity_file, timeout=15,
        mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
    )
    if not ok:
        return f"(couldn't check active sessions: {out.strip()})"
    return out.strip() if out.strip() else "(no active sessions)"


def trigger_reboot(service: ServiceConfig, *, identity_file: str = "",
                    mgmt_host: str = "", mgmt_ssh_user: str = "") -> None:
    _ssh_relay_aware(
        service, "sudo systemctl reboot", identity_file=identity_file, timeout=10,
        mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
    )


def wait_for_reboot(
    service: ServiceConfig, *, down_timeout: float = 120.0, up_timeout: float = 300.0,
    poll_interval: float = 5.0, identity_file: str = "",
    mgmt_host: str = "", mgmt_ssh_user: str = "",
) -> tuple[bool, str]:
    def _ssh_alive() -> bool:
        ok, _ = _ssh_relay_aware(
            service, "true", identity_file=identity_file, timeout=5,
            mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
        )
        return ok

    deadline = time.monotonic() + down_timeout
    went_down = False
    while time.monotonic() < deadline:
        if not _ssh_alive():
            went_down = True
            break
        time.sleep(poll_interval)
    if not went_down:
        pass

    deadline = time.monotonic() + up_timeout
    while time.monotonic() < deadline:
        if _ssh_alive():
            return True, (
                "host came back up"
                if went_down else
                "host never appeared to go down, but is reachable now "
                "(may have rebooted faster than this could detect, or the "
                "reboot command didn't actually fire -- worth a manual check)"
            )
        time.sleep(poll_interval)
    return False, (
        f"host did not come back within {up_timeout:.0f}s of going down"
        if went_down else
        f"host never went down and never confirmed up within {down_timeout + up_timeout:.0f}s total -- "
        f"the reboot command may not have actually fired"
    )


_TEAMSPEAK_DIST_FILES = (
    "ts3server", "libts3db_mariadb.so", "libts3db_postgresql.so",
    "libts3db_sqlite3.so", "libts3_ssh.so", "CHANGELOG", "LICENSE",
    "3RD_PARTY_LICENSES", "doc", "redist", "serverquerydocs", "tsdns", "sql",
    "ts3server_minimal_runscript.sh", "ts3server_startscript.sh",
)
_TEAMSPEAK_STAGING_DIR = "/home/rbdroot/ts3-update-staging"
_TEAMSPEAK_INSTALL_DIR = "/opt/teamspeak"
_TEAMSPEAK_BACKUP_DIR = f"{_TEAMSPEAK_INSTALL_DIR}/.rbd-backup"


def apply_teamspeak_update(service: ServiceConfig, new_version: str, *,
                            identity_file: str = "") -> tuple[bool, str]:
    info = teamspeak.get_download_info()
    if info is None:
        return False, "couldn't fetch TeamSpeak's download feed"
    if info["version"] != new_version:
        return False, (
            f"download feed now reports {info['version']!r}, not the expected "
            f"{new_version!r} -- refusing to apply a different version than what was staged/approved"
        )

    dist_paths = " ".join(f"{_TEAMSPEAK_STAGING_DIR}/{f}" for f in _TEAMSPEAK_DIST_FILES)
    quoted_url = shlex.quote(info["url"])
    quoted_checksum = shlex.quote(info["checksum"])
    download_cmd = (
        f"rm -rf {_TEAMSPEAK_STAGING_DIR} && mkdir -p {_TEAMSPEAK_STAGING_DIR} "
        f"&& cd {_TEAMSPEAK_STAGING_DIR} "
        f"&& curl -sL -o ts3.tar.bz2 {quoted_url} "
        f"&& echo {quoted_checksum}'  ts3.tar.bz2' | sha256sum -c - "
        f"&& tar xjf ts3.tar.bz2 --strip-components=1 && rm -f ts3.tar.bz2 "
        f"&& test -x ts3server"
    )
    ok, detail = _ssh_run(service.ssh_host, service.ssh_user, download_cmd,
                           identity_file=identity_file, timeout=120.0)
    if not ok:
        return False, f"download/extract failed, nothing live touched: {detail}"

    backup_dist_paths = " ".join(f"{_TEAMSPEAK_INSTALL_DIR}/{f}" for f in _TEAMSPEAK_DIST_FILES)
    backup_targets = " ".join(f"{_TEAMSPEAK_BACKUP_DIR}/{f}" for f in _TEAMSPEAK_DIST_FILES)
    swap_cmd = (
        f"sudo systemctl stop teamspeak "
        f"&& sudo mkdir -p {_TEAMSPEAK_BACKUP_DIR} "
        f"&& sudo cp -r {backup_dist_paths} {_TEAMSPEAK_BACKUP_DIR}/ "
        f"&& sudo cp -r {dist_paths} {_TEAMSPEAK_INSTALL_DIR}/ "
        f"&& sudo chown -R teamspeak:teamspeak {backup_dist_paths} "
        f"&& sudo systemctl start teamspeak"
    )
    ok, swap_detail = _ssh_run(service.ssh_host, service.ssh_user, swap_cmd,
                               identity_file=identity_file, timeout=60.0)

    verified_version = None
    if ok:
        time.sleep(5)
        verified_version = teamspeak.get_installed_version(service.ssh_host)

    if ok and verified_version == new_version:
        _ssh_run(service.ssh_host, service.ssh_user, f"rm -rf {_TEAMSPEAK_STAGING_DIR}",
                  identity_file=identity_file, timeout=30.0)
        return True, f"updated to {new_version}, confirmed live via ServerQuery"

    restore_cmd = (
        f"sudo systemctl stop teamspeak "
        f"&& sudo cp -r {backup_targets} {_TEAMSPEAK_INSTALL_DIR}/ "
        f"&& sudo chown -R teamspeak:teamspeak {backup_dist_paths} "
        f"&& sudo systemctl start teamspeak"
    )
    restore_ok, restore_detail = _ssh_run(service.ssh_host, service.ssh_user, restore_cmd,
                                           identity_file=identity_file, timeout=60.0)
    failure_reason = (
        f"swap command failed: {swap_detail}" if not ok
        else f"post-swap verification failed (ServerQuery reports {verified_version!r}, expected {new_version!r})"
    )
    if restore_ok:
        return False, f"{failure_reason} -- reverted to the previous version successfully"
    return False, f"{failure_reason} -- REVERT ALSO FAILED: {restore_detail} -- needs manual attention"


def apply_update(service: ServiceConfig, image: str, new_version: str, *,
                  identity_file: str = "", portainer_token: str = "",
                  mgmt_host: str = "", mgmt_ssh_user: str = "") -> tuple[bool, str]:
    if not _SAFE_IMAGE_RE.match(image) or not _SAFE_TAG_RE.match(new_version):
        return False, (
            f"refusing to apply update: image={image!r} or new_version={new_version!r} "
            "doesn't match the expected Docker tag/image shape"
        )
    if service.portainer:
        if not portainer_token:
            return False, f"{service.name} is Portainer-managed but PORTAINER_TOKEN isn't set"
        return portainer_client.update_stack(service.portainer, portainer_token)
    if service.launcher:
        command = f"sudo {service.launcher_dir}/launcher rebuild app"
    elif service.compose_dir:
        commands = []
        compose_file = f"{service.compose_dir}/docker-compose.yml"
        if service.registry is None:
            commands.append(
                f"sed 's|image: {image}:.*|image: {image}:{new_version}|' {compose_file} "
                f"| sudo tee {compose_file}.new > /dev/null "
                f"&& sudo cp {compose_file}.new {compose_file} && sudo rm {compose_file}.new"
            )
            force_recreate = ""
        else:
            current_tag = _read_current_tag(service, image, identity_file=identity_file,
                                            mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user)
            target_tag = _floating_tag_for_version(current_tag, new_version) if current_tag else None
            if current_tag and target_tag and target_tag != current_tag:
                commands.append(
                    f"sed 's|image: {image}:{current_tag}|image: {image}:{target_tag}|' {compose_file} "
                    f"| sudo tee {compose_file}.new > /dev/null "
                    f"&& sudo cp {compose_file}.new {compose_file} && sudo rm {compose_file}.new"
                )
            compose_services = _read_compose_services(service, image, identity_file=identity_file,
                                                      mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user)
            force_recreate = f" --force-recreate {' '.join(compose_services)}" if compose_services else " --force-recreate"
        commands.append(f"cd {service.compose_dir} && docker compose pull && docker compose up -d{force_recreate}")
        command = " && ".join(commands)
    elif service.systemd_service == "teamspeak":
        return apply_teamspeak_update(service, new_version, identity_file=identity_file)
    elif service.systemd_service == "ollama":
        ok, installed_after, output = ollama_client.apply_update(
            mgmt_host, mgmt_ssh_user,
            ollama_ssh_host=service.ssh_host, ollama_ssh_user=service.ssh_user,
            identity_file=identity_file,
        )
        if not ok:
            return False, f"installer failed or post-install version check failed:\n{output[-1500:]}"
        if installed_after != new_version:
            return False, (
                f"installer ran but installed version ({installed_after!r}) doesn't match "
                f"the expected new version ({new_version!r})"
            )
        return True, f"ollama upgraded to {installed_after}"
    elif service.systemd_service:
        return False, (
            f"{service.name} is a native/systemd service with no update-application "
            f"logic built yet -- this needs a manual update on the host"
        )
    else:
        return False, (
            f"{service.name} has no compose_dir, launcher, portainer, or systemd_service "
            f"config -- don't know how to apply its update"
        )
    return _ssh_relay_aware(
        service, command, identity_file=identity_file,
        mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
    )


def _read_current_tag(service: ServiceConfig, image: str, *, identity_file: str = "",
                      mgmt_host: str = "", mgmt_ssh_user: str = "") -> str | None:
    if not service.compose_dir:
        return None
    compose_file = f"{service.compose_dir}/docker-compose.yml"
    ok, out = _ssh_relay_aware(
        service, f"grep -m1 'image: {image}:' {compose_file}",
        identity_file=identity_file, mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user, timeout=30,
    )
    if not ok or not out.strip():
        return None
    return out.strip().splitlines()[0].rsplit(":", 1)[-1].strip()


def read_deployed_digest(service: ServiceConfig, image: str, *, identity_file: str = "",
                          mgmt_host: str = "", mgmt_ssh_user: str = "") -> str | None:
    current_tag = _read_current_tag(service, image, identity_file=identity_file,
                                    mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user)
    if not current_tag:
        ok, out = _ssh_relay_aware(
            service, f"docker ps --format '{{{{.Image}}}}' | grep -m1 '^{image}:'",
            identity_file=identity_file, timeout=30,
            mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
        )
        if not ok or ":" not in out.strip():
            return None
        current_tag = out.strip().splitlines()[0].rsplit(":", 1)[-1]
    ok, out = _ssh_relay_aware(
        service, f"docker image inspect {image}:{current_tag} --format '{{{{index .RepoDigests 0}}}}'",
        identity_file=identity_file, timeout=60,
        mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
    )
    if not ok or "@" not in out:
        return None
    return out.strip().rsplit("@", 1)[-1]


def _compose_services_for_image(compose_text: str, image: str) -> list[str]:
    current_service = None
    matches = []
    for line in compose_text.splitlines():
        service_match = re.match(r"^  ([A-Za-z0-9_.-]+):\s*$", line)
        if service_match:
            current_service = service_match.group(1)
            continue
        if re.match(rf"^\s+image:\s*{re.escape(image)}:", line) and current_service:
            matches.append(current_service)
    return matches


def _read_compose_services(service: ServiceConfig, image: str, *, identity_file: str = "",
                           mgmt_host: str = "", mgmt_ssh_user: str = "") -> list[str]:
    compose_file = f"{service.compose_dir}/docker-compose.yml"
    ok, out = _ssh_relay_aware(
        service, f"cat {compose_file}",
        identity_file=identity_file, mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user, timeout=30,
    )
    if not ok:
        return []
    return _compose_services_for_image(out, image)


def _floating_tag_for_version(current_tag: str, new_version: str) -> str | None:
    if current_tag.lower() == "latest":
        return current_tag
    major = new_version.split(".", 1)[0].lstrip("vV")
    if not major.isdigit():
        return None
    return f"v{major}" if current_tag.lower().startswith("v") else major


def collect_recent_logs(service: ServiceConfig, *, lines: int = 300, identity_file: str = "",
                         mgmt_host: str = "", mgmt_ssh_user: str = "") -> str:
    if service.systemd_service:
        ok, out = _ssh_relay_aware(
            service, f"journalctl -u {service.systemd_service} --no-pager -n {lines}",
            identity_file=identity_file, mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
        )
        return f"=== {service.systemd_service} ===\n{out if ok else f'(could not fetch logs: {out})'}"

    sections = []
    for container in service.log_watch_containers:
        ok, out = _ssh_relay_aware(
            service, f"docker logs --timestamps --tail {lines} {container}",
            identity_file=identity_file, mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
        )
        sections.append(f"=== {container} ===\n{out if ok else f'(could not fetch logs: {out})'}")
    return "\n\n".join(sections)


def restart_containers(service: ServiceConfig, *, identity_file: str = "",
                        mgmt_host: str = "", mgmt_ssh_user: str = "") -> tuple[bool, str]:
    if service.systemd_service:
        ok, detail = _ssh_relay_aware(
            service, f"sudo systemctl restart {service.systemd_service}",
            identity_file=identity_file, mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
        )
        if not ok:
            return False, f"restart of {service.systemd_service} failed: {detail}"
        return True, f"restarted {service.systemd_service}"

    for container in service.log_watch_containers:
        ok, detail = _ssh_relay_aware(
            service, f"docker restart {container}",
            identity_file=identity_file, mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
        )
        if not ok:
            return False, f"restart of {container} failed: {detail}"
    return True, f"restarted {len(service.log_watch_containers)} container(s)"


def supervisor_status(service: ServiceConfig, container: str, *, identity_file: str = "",
                      mgmt_host: str = "", mgmt_ssh_user: str = "") -> str:
    _, out = _ssh_relay_aware(
        service, f"docker exec {container} supervisorctl status",
        identity_file=identity_file, mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user, timeout=30,
    )
    return out


def stop_service(service: ServiceConfig, *, identity_file: str = "",
                  mgmt_host: str = "", mgmt_ssh_user: str = "") -> tuple[bool, str]:
    if service.systemd_service:
        ok, detail = _ssh_relay_aware(
            service, f"sudo systemctl stop {service.systemd_service}",
            identity_file=identity_file, mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
        )
        if not ok:
            return False, f"stop of {service.systemd_service} failed: {detail}"
        return True, f"stopped {service.systemd_service}"

    for container in service.log_watch_containers:
        ok, detail = _ssh_relay_aware(
            service, f"docker stop {container}",
            identity_file=identity_file, mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
        )
        if not ok:
            return False, f"stop of {container} failed: {detail}"
    return True, f"stopped {len(service.log_watch_containers)} container(s)"


def start_service(service: ServiceConfig, *, identity_file: str = "",
                   mgmt_host: str = "", mgmt_ssh_user: str = "") -> tuple[bool, str]:
    if service.systemd_service:
        ok, detail = _ssh_relay_aware(
            service, f"sudo systemctl start {service.systemd_service}",
            identity_file=identity_file, mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
        )
        if not ok:
            return False, f"start of {service.systemd_service} failed: {detail}"
        return True, f"started {service.systemd_service}"

    for container in service.log_watch_containers:
        ok, detail = _ssh_relay_aware(
            service, f"docker start {container}",
            identity_file=identity_file, mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
        )
        if not ok:
            return False, f"start of {container} failed: {detail}"
    return True, f"started {len(service.log_watch_containers)} container(s)"


def stop_cf_tunnel(service: ServiceConfig, *, identity_file: str = "",
                    mgmt_host: str = "", mgmt_ssh_user: str = "") -> tuple[bool, str]:
    tunnel = service.cf_tunnel
    if tunnel is None:
        return False, f"{service.name} has no cf_tunnel configured -- nothing to stop"
    if tunnel.kind == "systemd":
        ok, detail = _ssh_relay_aware(
            service, f"sudo systemctl stop {tunnel.name}",
            identity_file=identity_file, mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
        )
    elif tunnel.kind == "container":
        ok, detail = _ssh_relay_aware(
            service, f"docker stop {tunnel.name}",
            identity_file=identity_file, mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
        )
    else:
        return False, f"{service.name}'s cf_tunnel.kind={tunnel.kind!r} is neither 'container' nor 'systemd'"
    if not ok:
        return False, f"stop of tunnel {tunnel.name} failed: {detail}"
    return True, f"stopped tunnel {tunnel.name}"


def start_cf_tunnel(service: ServiceConfig, *, identity_file: str = "",
                     mgmt_host: str = "", mgmt_ssh_user: str = "") -> tuple[bool, str]:
    tunnel = service.cf_tunnel
    if tunnel is None:
        return False, f"{service.name} has no cf_tunnel configured -- nothing to start"
    if tunnel.kind == "systemd":
        ok, detail = _ssh_relay_aware(
            service, f"sudo systemctl start {tunnel.name}",
            identity_file=identity_file, mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
        )
    elif tunnel.kind == "container":
        ok, detail = _ssh_relay_aware(
            service, f"docker start {tunnel.name}",
            identity_file=identity_file, mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
        )
    else:
        return False, f"{service.name}'s cf_tunnel.kind={tunnel.kind!r} is neither 'container' nor 'systemd'"
    if not ok:
        return False, f"start of tunnel {tunnel.name} failed: {detail}"
    return True, f"started tunnel {tunnel.name}"


def _watch_systemd_unit(
    service: ServiceConfig, *, duration_seconds: int, poll_interval: int, identity_file: str,
    mgmt_host: str = "", mgmt_ssh_user: str = "",
) -> tuple[bool, str]:
    unit = service.systemd_service
    elapsed = 0
    restart_baseline: str | None = None

    while elapsed < duration_seconds:
        ok, out = _ssh_relay_aware(
            service, f"systemctl show {unit} --property=NRestarts,ActiveState --value",
            identity_file=identity_file, mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
        )
        if not ok:
            return False, f"could not inspect unit {unit}: {out}"
        parts = out.strip().split("\n")
        if len(parts) < 2:
            return False, f"unexpected systemctl show output for {unit}: {out!r}"
        restarts, status = parts[0], parts[1]
        if status != "active":
            return False, f"{unit} is not active (status={status})"
        if restart_baseline is not None and restarts != restart_baseline:
            return False, f"{unit} restarted during the log-watch window"
        restart_baseline = restarts

        ok, logs = _ssh_relay_aware(
            service, f"journalctl -u {unit} --since '{poll_interval + 5} seconds ago' --no-pager",
            identity_file=identity_file, mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
        )
        if any(pattern in logs for pattern in _ERROR_PATTERNS):
            return False, f"{unit} logged an error pattern:\n{logs[-2000:]}"

        time.sleep(poll_interval)
        elapsed += poll_interval

    return True, f"no errors or restarts over {duration_seconds}s"


def get_container_id(
    service: ServiceConfig, container: str, *,
    identity_file: str = "", mgmt_host: str = "", mgmt_ssh_user: str = "",
) -> str:
    ok, out = _ssh_relay_aware(
        service, f"docker inspect --format='{{{{.Id}}}}' {container}",
        identity_file=identity_file, mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
    )
    return out.strip() if ok else ""


def wait_for_container_health(
    service: ServiceConfig, container: str, *, baseline_id: str = "",
    timeout_seconds: int = 120, poll_interval: int = 5,
    identity_file: str = "", mgmt_host: str = "", mgmt_ssh_user: str = "",
) -> tuple[bool, str]:
    elapsed = 0
    while elapsed < timeout_seconds:
        ok, out = _ssh_relay_aware(
            service,
            f"docker inspect --format='{{{{.Id}}}}|{{{{.State.Health.Status}}}}' {container}",
            identity_file=identity_file, mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
        )
        if ok and "|" in out:
            current_id, _, health = out.strip().partition("|")
            is_new = (not baseline_id) or (current_id != baseline_id)
            if is_new and health == "healthy":
                return True, f"{container} is healthy (waited {elapsed}s)"
        time.sleep(poll_interval)
        elapsed += poll_interval
    return False, f"{container} did not report a new healthy instance within {timeout_seconds}s"


def watch_logs(
    service: ServiceConfig,
    *,
    duration_seconds: int,
    poll_interval: int,
    identity_file: str = "",
    mgmt_host: str = "",
    mgmt_ssh_user: str = "",
) -> tuple[bool, str]:
    if service.systemd_service:
        return _watch_systemd_unit(
            service, duration_seconds=duration_seconds, poll_interval=poll_interval,
            identity_file=identity_file, mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
        )

    elapsed = 0
    restart_baseline: dict[str, str] = {}
    since_ts = int(time.time())

    while elapsed < duration_seconds:
        for container in service.log_watch_containers:
            ok, out = _ssh_relay_aware(
                service, f"docker inspect --format='{{{{.RestartCount}}}} {{{{.State.Status}}}}' {container}",
                identity_file=identity_file, mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
            )
            if not ok:
                return False, f"could not inspect container {container}: {out}"
            restarts, status = out.strip().split()
            if status != "running":
                return False, f"{container} is not running (status={status})"
            if container in restart_baseline and restarts != restart_baseline[container]:
                return False, f"{container} restarted during the log-watch window"
            restart_baseline[container] = restarts

            ok, logs = _ssh_relay_aware(
                service, f"docker logs --since {since_ts} {container}",
                identity_file=identity_file, mgmt_host=mgmt_host, mgmt_ssh_user=mgmt_ssh_user,
            )
            if any(pattern in logs for pattern in _ERROR_PATTERNS):
                return False, f"{container} logged an error pattern:\n{logs[-2000:]}"

        time.sleep(poll_interval)
        elapsed += poll_interval

    return True, f"no errors or restarts over {duration_seconds}s"


def run_repair_plan(service: ServiceConfig, commands: list[str], *,
                     identity_file: str = "") -> tuple[bool, list[str]]:
    if not service.occ_container:
        return False, [f"{service.name} has no occ_container configured -- !repair isn't supported for it"]

    output: list[str] = []
    for cmd in commands:
        full_cmd = f"docker exec -u www-data {service.occ_container} php occ {cmd}"
        ok, out = _ssh_run(service.ssh_host, service.ssh_user, full_cmd, identity_file=identity_file)
        output.append(f"$ occ {cmd}\n{out.strip()}")
        if not ok:
            return False, output
    return True, output
