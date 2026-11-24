"""Checks that the management host's SSH agent has its key loaded."""
from __future__ import annotations

from . import ollama as ollama_client

BAD_STATES = {"empty", "no_agent"}

FIX_HINT = (
    "run `SSH_AUTH_SOCK=/run/user/1000/ssh-agent.socket ssh-add ~/.ssh/id_ed25519` "
    "in a real terminal on rbd-mgmt1 (it needs the key's passphrase)"
)


def check_agent(mgmt_host: str, mgmt_user: str, *, identity_file: str = "") -> dict:
    result = ollama_client._mgmt_relay(
        mgmt_host, mgmt_user, {"mode": "ssh_agent_status"},
        identity_file=identity_file, timeout=20.0,
    )
    state = result.get("state")
    if not state:
        return {"state": "unreachable", "keys": 0,
                "detail": "; ".join(result.get("errors") or ["no state in relay reply"])}
    return {"state": state, "keys": int(result.get("keys") or 0),
            "detail": "; ".join(result.get("errors") or [])}


def describe(status: dict) -> str:
    if status["state"] == "empty":
        return "mgmt1's SSH agent is running but has no key loaded (mgmt1 was probably rebooted)"
    if status["state"] == "no_agent":
        return "mgmt1's SSH agent isn't running (check `systemctl --user status ssh-agent` on mgmt1)"
    if status["state"] == "unreachable":
        return f"couldn't reach mgmt1's relay to check its SSH agent ({status['detail']})"
    if status["state"] == "loaded":
        return f"mgmt1's SSH agent has {status['keys']} key(s) loaded"
    return f"mgmt1's SSH agent state is unknown ({status['detail']})"
