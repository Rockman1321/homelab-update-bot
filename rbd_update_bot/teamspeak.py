"""TeamSpeak version detection and occupancy check."""
from __future__ import annotations

import re
import socket

import requests

_VERSION_FEED_URL = "https://teamspeak.com/versions/server.json"

_TS3_UNESCAPE = {
    r"\s": " ", r"\p": "|", r"\/": "/", r"\\": "\\",
    r"\a": "\a", r"\b": "\b", r"\f": "\f", r"\n": "\n", r"\r": "\r", r"\t": "\t",
}


def _ts3_unescape(value: str) -> str:
    for escaped, real in _TS3_UNESCAPE.items():
        value = value.replace(escaped, real)
    return value


def get_latest_version(*, platform: str = "linux", arch: str = "x86_64",
                        timeout: float = 15.0) -> str | None:
    try:
        resp = requests.get(_VERSION_FEED_URL, timeout=timeout)
        resp.raise_for_status()
        return resp.json()[platform][arch]["version"]
    except Exception:
        return None


def get_download_info(*, platform: str = "linux", arch: str = "x86_64",
                       timeout: float = 15.0) -> dict | None:
    try:
        resp = requests.get(_VERSION_FEED_URL, timeout=timeout)
        resp.raise_for_status()
        entry = resp.json()[platform][arch]
        return {
            "version": entry["version"],
            "url": entry["mirrors"]["teamspeak.com"],
            "checksum": entry["checksum"],
        }
    except Exception:
        return None


_VERSION_RE = re.compile(r"^version=(\S+)\s+build=(\S+)\s+platform=(\S+)", re.MULTILINE)


def get_installed_version(host: str, *, port: int = 10011, timeout: float = 10.0) -> str | None:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            buf = b""
            sock.recv(4096)
            sock.sendall(b"version\n")
            while b"error id=" not in buf:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
        match = _VERSION_RE.search(buf.decode("utf-8", errors="replace"))
        return match.group(1) if match else None
    except Exception:
        return None


def get_occupancy(host: str, login: str, password: str, *,
                   port: int = 10011, timeout: float = 10.0) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)

            def send(cmd: str) -> str:
                sock.sendall((cmd + "\n").encode())
                buf = b""
                while b"error id=" not in buf:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                return buf.decode("utf-8", errors="replace")

            sock.recv(4096)
            login_resp = send(f"login client_login_name={login} client_login_password={password}")
            if "error id=0" not in login_resp:
                return f"(couldn't check occupancy: login failed -- {login_resp.strip()})"
            use_resp = send("use port=9987")
            if "error id=0" not in use_resp:
                return f"(couldn't check occupancy: {use_resp.strip()})"
            list_resp = send("clientlist")
    except Exception as exc:
        return f"(couldn't check occupancy: {exc})"

    data_line = list_resp.split("\n", 1)[0].strip()
    clients = []
    for entry in data_line.split("|"):
        fields = dict(part.split("=", 1) for part in entry.split(" ") if "=" in part)
        if fields.get("client_type") == "0":
            clients.append(_ts3_unescape(fields.get("client_nickname", "unknown")))

    if not clients:
        return "No voice clients connected."
    return f"{len(clients)} voice client(s) connected: {', '.join(clients)}"
