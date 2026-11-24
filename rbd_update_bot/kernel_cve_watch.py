"""Checks each kernel version in the fleet for critical CVEs and patches once a fix is released."""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, replace

import requests

import anthropic

_WEB_SEARCH_TOOL_TYPE = "web_search_20260209"
_MAX_SEARCHES = 6
_ALLOWED_DOMAINS = [
    "ubuntu.com", "launchpad.net", "security-tracker.debian.org",
    "kernel.org", "lore.kernel.org", "nvd.nist.gov",
    "forum.proxmox.com", "git.proxmox.com", "pve.proxmox.com",
]

_RESEARCH_SYSTEM_PROMPT = """You are checking whether a specific Linux \
kernel version, as shipped by a specific distro, has any currently known \
critical or high-severity CVE against it, for a home server fleet. Call \
the web_search tool directly (never through code execution or any other \
indirection) against the distro's own security tracker (ubuntu.com/security, \
security-tracker.debian.org), launchpad.net, kernel.org/lore.kernel.org, \
and/or NVD. You have a hard limit of a few web_search calls -- use them \
efficiently, and the moment you hit a tool-limit error, STOP searching \
and write your summary from whatever results you already have. Partial \
real results beat no answer -- never discard findings from earlier \
successful searches just because a later search attempt failed or was \
refused. Report: (1) whether you found an official source describing a \
critical/high CVE that applies to this exact running kernel version, with \
its CVE id and URL, (2) whether a fix has actually been RELEASED (a real \
package version you can point to) as opposed to merely announced/"work in \
progress"/"pending" -- these are not the same thing, and conflating them \
would make a fleet reboot itself for a fix that doesn't exist yet, (3) the \
minimum fixed package version, if released, (4) severity, (5) a short \
plain-language summary. \
For Ubuntu, a CVE's tracker page (ubuntu.com/security/CVE-YYYY-NNNN) has a \
per-package, per-release status table; prefer the machine-friendly \
`?format=md` variant of that URL when it appears in search results. Find the \
row for the SOURCE PACKAGE that actually produced the running kernel, not \
just the generic `linux` row -- e.g. a `6.8.0-NNN-generic` kernel on 22.04 \
jammy is source package `linux-hwe-6.8`, not `linux`/`linux-aws`/etc. -- and \
read that row's own status: "Fixed NNN" with a real version means the fix \
is RELEASED (report that version as the fixed version); only "needed", \
"pending", "in-progress" etc. mean unreleased. Do not report a CVE as \
unfixed because some OTHER package/release row is unfixed. For severity, \
use Ubuntu's own assigned Priority (Critical/High/Medium/Low/Negligible) \
from the tracker, NOT the raw CVSS base score (a generic CVSS3 9.8 can sit \
next to an Ubuntu priority of Low); only fall back to CVSS if Ubuntu \
publishes no priority, and say so in the summary. If your searches genuinely found nothing from an \
official source, say so plainly -- do not guess or infer from unofficial \
discussion, and do not report a CVE that doesn't clearly cover this exact \
kernel version."""

_ADVISORY_TOOL = {
    "name": "report_kernel_cve",
    "description": "Report whether a known critical/high CVE applies to this kernel version, and whether a fix has actually shipped.",
    "input_schema": {
        "type": "object",
        "properties": {
            "has_critical_cve": {
                "type": "boolean",
                "description": (
                    "True only if an official source clearly describes a critical/high CVE "
                    "covering this exact kernel version. If research was inconclusive or no "
                    "official source was found, set this to the CAUTIOUS answer: true if "
                    "there's real reason to suspect this version is affected, false only when "
                    "research clearly found nothing applicable."
                ),
            },
            "cve_id": {"type": "string", "description": "The CVE id, or empty if none found."},
            "fixed_version": {
                "type": "string",
                "description": "Minimum fixed package version, or empty if none released yet.",
            },
            "fix_available": {
                "type": "boolean",
                "description": (
                    "True ONLY if the tracker explicitly marks a fix as released (a real "
                    "version string you can point to) -- false for \"work in progress\", "
                    "\"pending\", \"needed\", or any other not-yet-shipped status, even if a "
                    "target version number is mentioned. This gates an unattended fleet "
                    "patch+reboot -- fail toward false whenever genuinely unsure."
                ),
            },
            "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "none"]},
            "source_url": {"type": "string", "description": "The official source's URL, or empty if none found."},
            "summary": {"type": "string", "description": "1-3 sentence plain-language summary."},
        },
        "required": ["has_critical_cve", "cve_id", "fixed_version", "fix_available", "severity", "source_url", "summary"],
    },
}


@dataclass
class KernelCVEAdvisory:
    has_critical_cve: bool
    cve_id: str
    fixed_version: str
    fix_available: bool
    severity: str
    source_url: str
    summary: str


def check_kernel_cve(
    *, client: anthropic.Anthropic, model: str, distro: str, kernel_version: str,
) -> KernelCVEAdvisory:
    research_text = _run_research_call(client=client, model=model, distro=distro, kernel_version=kernel_version)
    return _run_decision_call(client=client, model=model, research_text=research_text)


def already_patched(installed_version: str, fixed_version: str) -> bool:
    if not installed_version or not fixed_version:
        return False
    try:
        result = subprocess.run(
            ["dpkg", "--compare-versions", installed_version, "ge", fixed_version],
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


_UBUNTU_CODENAMES = {"20.04": "focal", "22.04": "jammy", "24.04": "noble", "26.04": "resolute"}
_TRACKER_JSON_URL = "https://ubuntu.com/security/cves/{cve_id}.json"
_NOTICES_JSON_URL = "https://ubuntu.com/security/notices.json?details=linux&release={codename}&limit=20"


def ubuntu_source_package(distro: str, kernel_version: str,
                          installed_version: str) -> tuple[str, str] | None:
    if not distro.startswith("Ubuntu") or not kernel_version.endswith("-generic") \
            or not installed_version:
        return None
    release = re.search(r"\b(\d{2}\.\d{2})", distro)
    codename = _UBUNTU_CODENAMES.get(release.group(1)) if release else None
    if not codename:
        return None
    mm = re.match(r"(\d+)\.(\d+)\.", installed_version)
    if not mm:
        return None
    package = f"linux-hwe-{mm.group(1)}.{mm.group(2)}" if "~" in installed_version else "linux"
    return package, codename


def fetch_kernel_notices(codename: str) -> list[dict] | None:
    try:
        resp = requests.get(_NOTICES_JSON_URL.format(codename=codename), timeout=60,
                            headers={"User-Agent": "rbd-update-bot"})
        resp.raise_for_status()
        notices = resp.json()["notices"]
    except (requests.RequestException, ValueError, KeyError, TypeError):
        return None
    out = []
    for n in notices:
        pkgs = {p.get("name") for p in (n.get("release_packages") or {}).get(codename, [])
                if p.get("is_source")}
        out.append({"id": n.get("id", ""), "published": n.get("published", ""), "source_packages": pkgs})
    out.sort(key=lambda n: n["published"], reverse=True)
    return out


def latest_usn_for(notices: list[dict] | None, package: str) -> str | None:
    for n in notices or []:
        if package in n["source_packages"]:
            return n["id"]
    return None


def research_reason(cached: dict | None, *, now_ts: float, max_age_hours: float,
                    latest_usn: str | None) -> str | None:
    if max_age_hours <= 0:
        return "caching disabled"
    if not cached:
        return "no cached research for this kernel"
    age_h = (now_ts - float(cached.get("researched_at", 0))) / 3600
    if age_h >= max_age_hours:
        return f"cached research is {age_h:.0f}h old"
    if cached.get("has_critical_cve") and not cached.get("tracker_ok"):
        return "open CVE with no deterministic tracker row -- re-researching every cycle"
    if latest_usn and latest_usn != cached.get("usn"):
        return f"new kernel notice {latest_usn}"
    return None


def ubuntu_tracker_status(cve_id: str, distro: str, kernel_version: str,
                          installed_version: str) -> dict | None:
    if not cve_id.startswith("CVE-"):
        return None
    src = ubuntu_source_package(distro, kernel_version, installed_version)
    if src is None:
        return None
    package, codename = src
    try:
        resp = requests.get(_TRACKER_JSON_URL.format(cve_id=cve_id), timeout=30,
                            headers={"User-Agent": "rbd-update-bot"})
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError):
        return None
    for pkg in data.get("packages") or []:
        if pkg.get("name") != package:
            continue
        for st in pkg.get("statuses") or []:
            if st.get("release_codename") == codename:
                status = st.get("status") or ""
                return {
                    "package": package, "codename": codename, "status": status,
                    "fixed_version": (st.get("description") or "").strip() if status == "released" else "",
                }
    return None


def _run_research_call(*, client: anthropic.Anthropic, model: str, distro: str, kernel_version: str) -> str:
    web_search_tool: dict = {
        "type": _WEB_SEARCH_TOOL_TYPE, "name": "web_search", "max_uses": _MAX_SEARCHES,
        "allowed_domains": _ALLOWED_DOMAINS,
    }
    message = client.messages.create(
        model=model,
        max_tokens=2048,
        system=_RESEARCH_SYSTEM_PROMPT,
        tools=[web_search_tool],
        tool_choice={"type": "auto"},
        messages=[{
            "role": "user",
            "content": f"Distro: {distro}\nRunning kernel version: {kernel_version}",
        }],
    )
    texts = [b.text for b in message.content if b.type == "text"]
    return "\n".join(texts) if texts else "(no research findings -- the model returned no text)"


def _run_decision_call(*, client: anthropic.Anthropic, model: str, research_text: str) -> KernelCVEAdvisory:
    message = client.messages.create(
        model=model,
        max_tokens=1024,
        tools=[_ADVISORY_TOOL],
        tool_choice={"type": "tool", "name": "report_kernel_cve"},
        messages=[{
            "role": "user",
            "content": f"Research findings:\n{research_text}",
        }],
    )
    tool_use = next(b for b in message.content if b.type == "tool_use")
    data = tool_use.input
    return KernelCVEAdvisory(
        has_critical_cve=data["has_critical_cve"],
        cve_id=data["cve_id"],
        fixed_version=data["fixed_version"],
        fix_available=data["fix_available"],
        severity=data["severity"],
        source_url=data["source_url"],
        summary=data["summary"],
    )
