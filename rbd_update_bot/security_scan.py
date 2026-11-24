"""Starts a fleet-wide read-only security sweep."""
from __future__ import annotations

import json
import subprocess


def trigger_security_scan(
    host: str,
    user: str,
    *,
    hosts: list[dict],
    fortigate_api_host: str = "",
    fortigate_token_file: str = "",
    omada_config_file: str = "",
    identity_file: str = "",
    timeout: float = 1800.0,
) -> tuple[bool, str]:
    payload_dict = {
        "mode": "security_scan",
        "hosts": hosts,
    }
    if fortigate_api_host and fortigate_token_file:
        payload_dict["fortigate"] = {
            "api_host": fortigate_api_host,
            "token_file": fortigate_token_file,
        }
    if omada_config_file:
        payload_dict["omada"] = {"config_file": omada_config_file}
    payload = json.dumps(payload_dict)
    ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes"]
    if identity_file:
        ssh_cmd += ["-i", identity_file]
    ssh_cmd += [f"{user}@{host}", "true"]
    proc = subprocess.run(ssh_cmd, input=payload, capture_output=True, text=True, timeout=timeout)
    return proc.returncode == 0, (proc.stdout + proc.stderr)
