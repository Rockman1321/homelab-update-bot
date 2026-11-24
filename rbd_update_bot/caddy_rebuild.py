"""Rebuilds and redeploys custom Caddy images when the base image or a plugin changes."""
from __future__ import annotations

import subprocess
import time

import requests

from . import portainer as portainer_client
from .config import CaddyRebuildTarget

_UPSTREAM_REPO = "library/caddy"
_UPSTREAM_TAG = "builder"
_BACKUP_TAG_PREFIX = "rbd-caddy-backup"

_SETTLE_SECONDS = {"compose": 15.0, "portainer": 60.0}


def get_upstream_digest() -> str:
    resp = requests.get(
        f"https://hub.docker.com/v2/repositories/{_UPSTREAM_REPO}/tags/{_UPSTREAM_TAG}",
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()["digest"]


def _ssh_run(host: str, user: str, command: str, *, identity_file: str = "",
             timeout: float = 600.0) -> tuple[bool, str]:
    ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new"]
    if identity_file:
        ssh_cmd += ["-i", identity_file]
    ssh_cmd += [f"{user}@{host}", command]
    proc = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout)
    return proc.returncode == 0, (proc.stdout + proc.stderr)


def _current_image_id(target: CaddyRebuildTarget, *, identity_file: str) -> str | None:
    ok, out = _ssh_run(
        target.ssh_host, target.ssh_user,
        f"docker inspect {target.container_name} --format '{{{{.Image}}}}'",
        identity_file=identity_file,
    )
    return out.strip() if ok else None


def _health_check(target: CaddyRebuildTarget, *, identity_file: str,
                   settle_seconds: float = 10.0, poll_interval: float = 3.0) -> tuple[bool, str]:
    deadline = time.monotonic() + settle_seconds
    status, restarts, out = "", "", ""
    while True:
        ok, out = _ssh_run(
            target.ssh_host, target.ssh_user,
            f"docker inspect {target.container_name} --format '{{{{.State.Status}}}} {{{{.RestartCount}}}}'",
            identity_file=identity_file,
        )
        if ok:
            status, restarts = out.strip().split()
            if status == "running":
                break
        if time.monotonic() >= deadline:
            if not ok:
                return False, f"could not inspect {target.container_name} after redeploy: {out}"
            return False, f"{target.container_name} is not running after redeploy (status={status})"
        time.sleep(poll_interval)

    if restarts != "0":
        return False, f"{target.container_name} has already restarted {restarts} time(s) since redeploy"

    deadline = time.monotonic() + settle_seconds
    detail = ""
    while True:
        try:
            resp = requests.get(target.health_url, timeout=15)
        except requests.RequestException as exc:
            detail = f"{target.health_url} did not respond after redeploy: {exc}"
        else:
            if resp.status_code < 500:
                return True, f"{target.container_name} running, {target.health_url} returned {resp.status_code}"
            detail = f"{target.health_url} returned {resp.status_code} after redeploy"
        if time.monotonic() >= deadline:
            return False, detail
        time.sleep(poll_interval)


def _rebuild_compose(target: CaddyRebuildTarget, *, identity_file: str) -> tuple[bool, str]:
    ok, out = _ssh_run(
        target.ssh_host, target.ssh_user,
        f"cd {target.compose_dir} && docker compose build {target.compose_service}",
        identity_file=identity_file, timeout=900,
    )
    return ok, out


def _redeploy_compose(target: CaddyRebuildTarget, *, identity_file: str) -> tuple[bool, str]:
    return _ssh_run(
        target.ssh_host, target.ssh_user,
        f"cd {target.compose_dir} && docker compose up -d --force-recreate {target.compose_service}",
        identity_file=identity_file, timeout=120,
    )


def _rebuild_host_image(target: CaddyRebuildTarget, *, identity_file: str) -> tuple[bool, str]:
    return _ssh_run(
        target.ssh_host, target.ssh_user,
        f"docker build -t {target.image_tag} {target.build_context}",
        identity_file=identity_file, timeout=900,
    )


def _redeploy_portainer(target: CaddyRebuildTarget, portainer_token: str, *,
                         retries: int = 3, retry_delay: float = 10.0) -> tuple[bool, str]:
    ok, out = False, ""
    for attempt in range(retries):
        ok, out = portainer_client.update_stack(target.portainer, portainer_token)
        if ok or "409" not in out:
            return ok, out
        if attempt < retries - 1:
            time.sleep(retry_delay)
    return ok, out


def _backup_current_image(target: CaddyRebuildTarget, *, identity_file: str) -> tuple[bool, str]:
    image_id = _current_image_id(target, identity_file=identity_file)
    if not image_id:
        return False, f"could not determine {target.container_name}'s current image ID -- refusing to rebuild without a backup"
    backup_tag = f"{_BACKUP_TAG_PREFIX}:{target.name}"
    ok, out = _ssh_run(
        target.ssh_host, target.ssh_user, f"docker tag {image_id} {backup_tag}",
        identity_file=identity_file,
    )
    return ok, out if not ok else backup_tag


def _revert_to_backup(target: CaddyRebuildTarget, *, identity_file: str,
                       portainer_token: str = "") -> tuple[bool, str]:
    backup_tag = f"{_BACKUP_TAG_PREFIX}:{target.name}"
    ok, out = _ssh_run(
        target.ssh_host, target.ssh_user, f"docker tag {backup_tag} {target.image_tag}",
        identity_file=identity_file,
    )
    if not ok:
        return False, f"could not restore backup tag: {out}"

    if target.mechanism == "compose":
        redeploy_ok, redeploy_out = _redeploy_compose(target, identity_file=identity_file)
    else:
        redeploy_ok, redeploy_out = _redeploy_portainer(target, portainer_token)
    if not redeploy_ok:
        return False, f"restored the previous image but redeploy failed: {redeploy_out}"

    healthy, detail = _health_check(
        target, identity_file=identity_file, settle_seconds=_SETTLE_SECONDS.get(target.mechanism, 15.0),
    )
    return healthy, detail


def rebuild_target(target: CaddyRebuildTarget, *, identity_file: str,
                    portainer_token: str = "") -> tuple[bool, str, bool]:
    backup_ok, backup_result = _backup_current_image(target, identity_file=identity_file)
    if not backup_ok:
        return False, f"aborted before touching anything: {backup_result}", False

    if target.mechanism == "compose":
        build_ok, build_out = _rebuild_compose(target, identity_file=identity_file)
    else:
        build_ok, build_out = _rebuild_host_image(target, identity_file=identity_file)
    if not build_ok:
        return False, f"build failed, old image still running untouched:\n{build_out[-1500:]}", False

    if target.mechanism == "compose":
        redeploy_ok, redeploy_out = _redeploy_compose(target, identity_file=identity_file)
    else:
        redeploy_ok, redeploy_out = _redeploy_portainer(target, portainer_token)
    if not redeploy_ok:
        return False, f"build succeeded but redeploy failed: {redeploy_out}", False

    healthy, detail = _health_check(
        target, identity_file=identity_file, settle_seconds=_SETTLE_SECONDS.get(target.mechanism, 15.0),
    )
    if healthy:
        return True, detail, False

    revert_ok, revert_detail = _revert_to_backup(
        target, identity_file=identity_file, portainer_token=portainer_token,
    )
    if revert_ok:
        return True, f"new build failed health check ({detail}) -- automatically reverted: {revert_detail}", True
    return False, (
        f"new build failed health check ({detail}), AND the automatic revert also failed "
        f"({revert_detail}) -- needs a human now"
    ), True
