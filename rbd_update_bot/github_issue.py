"""Files a GitHub issue when an investigation concludes the bot's own code needs a fix."""
from __future__ import annotations

import json
import subprocess


def trigger_create_issue(
    host: str,
    user: str,
    *,
    repo: str,
    issue_token_file: str,
    title: str,
    body: str,
    labels: list[str],
    identity_file: str = "",
    timeout: float = 30.0,
) -> tuple[bool, int | None, str]:
    payload = json.dumps({
        "mode": "github_issue_create",
        "github": {"repo": repo, "issue_token_file": issue_token_file},
        "title": title, "body": body, "labels": labels,
    })
    ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes"]
    if identity_file:
        ssh_cmd += ["-i", identity_file]
    ssh_cmd += [f"{user}@{host}", "true"]
    proc = subprocess.run(ssh_cmd, input=payload, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        return False, None, f"SSH failed: {proc.stderr.strip() or proc.stdout.strip()}"
    try:
        body_dict = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return False, None, f"bad JSON from mgmt1: {proc.stdout.strip()[:500]}"
    if not body_dict.get("ok"):
        return False, None, body_dict.get("detail", "unknown error")
    return True, body_dict.get("issue_number"), body_dict.get("detail", "")
