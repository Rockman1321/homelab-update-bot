"""Triggers Immich's built-in database backup before an update."""
from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass

import requests


@dataclass
class ImmichDbBackupConfig:
    base_url: str
    backup_dir: str = "/mnt/immich_media/backups"


def get_job_activity(base_url: str, api_key: str, *, timeout: float = 15.0) -> str:
    try:
        resp = requests.get(
            f"{base_url}/api/jobs", headers={"x-api-key": api_key}, timeout=timeout,
        )
        resp.raise_for_status()
        jobs = resp.json()
    except Exception as exc:
        return f"(couldn't check job activity: {exc})"

    busy = []
    for name, info in jobs.items():
        counts = info.get("jobCounts", {})
        active, waiting = counts.get("active", 0), counts.get("waiting", 0)
        if active or waiting:
            busy.append(f"{name}: {active} active, {waiting} waiting")
    return "\n".join(busy) if busy else "All job queues idle."


def trigger_db_backup(base_url: str, api_key: str, *, timeout: float = 15.0) -> tuple[bool, str]:
    try:
        resp = requests.post(
            f"{base_url}/api/jobs",
            headers={"x-api-key": api_key, "Content-Type": "application/json"},
            json={"name": "backup-database"},
            timeout=timeout,
        )
        resp.raise_for_status()
    except Exception as exc:
        return False, str(exc)
    return True, "triggered"


def _ssh_run(host: str, user: str, command: str, *, identity_file: str = "",
             timeout: float = 30.0) -> tuple[bool, str]:
    ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new"]
    if identity_file:
        ssh_cmd += ["-i", identity_file]
    ssh_cmd += [f"{user}@{host}", command]
    proc = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout)
    return proc.returncode == 0, (proc.stdout + proc.stderr)


def wait_for_fresh_backup(
    ssh_host: str, ssh_user: str, backup_dir: str, *, identity_file: str = "",
    poll_interval: float = 15.0, timeout: float = 1800.0,
) -> tuple[bool, str]:
    marker = f"/tmp/immich-backup-marker-{int(time.time())}"
    ok, detail = _ssh_run(ssh_host, ssh_user, f"touch {marker}", identity_file=identity_file)
    if not ok:
        return False, f"could not create timing marker: {detail}"

    try:
        deadline = time.time() + timeout
        while time.time() < deadline:
            ok, out = _ssh_run(
                ssh_host, ssh_user,
                f"find {backup_dir} -name 'immich-db-backup-*.sql.gz' -newer {marker} -print -quit",
                identity_file=identity_file,
            )
            if ok and out.strip():
                return True, out.strip()
            time.sleep(poll_interval)
        return False, f"no fresh backup file appeared in {backup_dir} within {timeout}s"
    finally:
        _ssh_run(ssh_host, ssh_user, f"rm -f {marker}", identity_file=identity_file)
