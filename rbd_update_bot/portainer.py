"""Portainer API client for Portainer-managed stacks."""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass

import requests

ENV_BACKUP_DIR = "env-backups"


@dataclass
class PortainerConfig:
    base_url: str
    stack_name: str
    verify_tls: bool = False


def _headers(api_key: str) -> dict:
    return {"X-API-KEY": api_key}


def find_stack(config: PortainerConfig, api_key: str) -> tuple[int, int]:
    resp = requests.get(
        f"{config.base_url}/api/stacks", headers=_headers(api_key),
        verify=config.verify_tls, timeout=15,
    )
    resp.raise_for_status()
    for stack in resp.json():
        if stack.get("Name") == config.stack_name:
            return stack["Id"], stack["EndpointId"]
    raise ValueError(f"no Portainer stack named {config.stack_name!r} found")


def get_stack_file_content(config: PortainerConfig, api_key: str, stack_id: int) -> str:
    file_resp = requests.get(
        f"{config.base_url}/api/stacks/{stack_id}/file", headers=_headers(api_key),
        verify=config.verify_tls, timeout=15,
    )
    file_resp.raise_for_status()
    return file_resp.json()["StackFileContent"]


def _get_stack_env(config: PortainerConfig, api_key: str, stack_id: int) -> list:
    stack_resp = requests.get(
        f"{config.base_url}/api/stacks/{stack_id}", headers=_headers(api_key),
        verify=config.verify_tls, timeout=15,
    )
    stack_resp.raise_for_status()
    return stack_resp.json().get("Env") or []


def backup_stack_env(config: PortainerConfig, api_key: str, update_id: int) -> tuple[bool, str | None]:
    try:
        stack_id, _ = find_stack(config, api_key)
        env = _get_stack_env(config, api_key, stack_id)
    except (requests.RequestException, KeyError, ValueError) as exc:
        return False, f"could not back up stack Env: {exc}"

    os.makedirs(ENV_BACKUP_DIR, exist_ok=True)
    os.chmod(ENV_BACKUP_DIR, 0o700)
    off_vm_path = os.path.join(ENV_BACKUP_DIR, f"{config.stack_name}-{update_id}.json")
    with open(off_vm_path, "w") as f:
        json.dump(env, f)
    os.chmod(off_vm_path, 0o600)
    return True, off_vm_path


def check_and_restore_stack_env(config: PortainerConfig, api_key: str, update_id: int) -> tuple[bool, str]:
    off_vm_path = os.path.join(ENV_BACKUP_DIR, f"{config.stack_name}-{update_id}.json")
    if not os.path.exists(off_vm_path):
        return False, "no stack Env backup was taken for this update"
    with open(off_vm_path) as f:
        backed_up_env = json.load(f)
    if not backed_up_env:
        return False, "backed-up stack Env was already empty -- nothing meaningful to restore"

    try:
        stack_id, endpoint_id = find_stack(config, api_key)
        current_env = _get_stack_env(config, api_key, stack_id)
        if current_env:
            return False, "no change detected -- stack Env still has content"

        file_resp = requests.get(
            f"{config.base_url}/api/stacks/{stack_id}/file", headers=_headers(api_key),
            verify=config.verify_tls, timeout=15,
        )
        file_resp.raise_for_status()
        stack_content = file_resp.json()["StackFileContent"]

        update_resp = requests.put(
            f"{config.base_url}/api/stacks/{stack_id}",
            params={"endpointId": endpoint_id},
            headers=_headers(api_key),
            json={
                "StackFileContent": stack_content,
                "Env": backed_up_env,
                "RepullImageAndRedeploy": False,
            },
            verify=config.verify_tls,
            timeout=60,
        )
        update_resp.raise_for_status()
    except (requests.RequestException, KeyError, ValueError) as exc:
        return False, f"detected the stack Env was cleared, but restoring it failed: {exc}"
    return True, f"detected the stack Env was cleared and automatically restored it ({len(backed_up_env)} vars)"


def update_stack(config: PortainerConfig, api_key: str, *, timeout: float = 300.0) -> tuple[bool, str]:
    try:
        stack_id, endpoint_id = find_stack(config, api_key)
        existing_env = _get_stack_env(config, api_key, stack_id)
        stack_content = get_stack_file_content(config, api_key, stack_id)

        update_resp = requests.put(
            f"{config.base_url}/api/stacks/{stack_id}",
            params={"endpointId": endpoint_id},
            headers=_headers(api_key),
            json={
                "StackFileContent": stack_content,
                "Env": existing_env,
                "RepullImageAndRedeploy": True,
            },
            verify=config.verify_tls,
            timeout=timeout,
        )
        update_resp.raise_for_status()
        return True, f"stack {config.stack_name!r} (id={stack_id}) repulled and redeployed"
    except requests.RequestException as exc:
        return False, f"Portainer update failed: {exc}"
    except (KeyError, ValueError) as exc:
        return False, f"Portainer update failed: {exc}"


def redeploy_pinned_digests(
    config: PortainerConfig, api_key: str, pins: list[tuple[str, str]], *, timeout: float = 300.0,
) -> tuple[bool, str]:
    try:
        stack_id, endpoint_id = find_stack(config, api_key)
        existing_env = _get_stack_env(config, api_key, stack_id)
        content = get_stack_file_content(config, api_key, stack_id)

        for image, digest in pins:
            pattern = re.compile(rf"{re.escape(image)}:\$\{{[A-Z_]+:-[^}}]*\}}")
            content, count = pattern.subn(f"{image}@{digest}", content)
            if count == 0:
                return False, f"could not find a variable-substituted image line for {image!r} to pin"

        update_resp = requests.put(
            f"{config.base_url}/api/stacks/{stack_id}",
            params={"endpointId": endpoint_id}, headers=_headers(api_key),
            json={"StackFileContent": content, "Env": existing_env, "RepullImageAndRedeploy": True},
            verify=config.verify_tls, timeout=timeout,
        )
        update_resp.raise_for_status()
        return True, f"stack {config.stack_name!r} pinned to {len(pins)} exact digest(s) and redeployed"
    except (requests.RequestException, KeyError, ValueError) as exc:
        return False, f"Portainer digest-pinned redeploy failed: {exc}"
