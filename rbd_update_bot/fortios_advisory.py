"""Checks the running FortiOS version against Fortinet's published advisories."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass

import anthropic
import requests

_WEB_SEARCH_TOOL_TYPE = "web_search_20260209"
_MAX_SEARCHES = 6
_ALLOWED_DOMAINS = ["fortiguard.com", "fortinet.com", "nvd.nist.gov"]

_RESEARCH_SYSTEM_PROMPT = """You are checking whether a specific FortiOS \
firmware version has any currently known security advisory against it, \
for a home network firewall. Call the web_search tool directly (never \
through code execution or any other indirection) against Fortinet's own \
PSIRT advisories (fortiguard.com/fortinet.com) and/or NVD. You have a hard \
limit of a few web_search calls -- use them efficiently, and the moment \
you hit a tool-limit error, STOP searching and write your summary from \
whatever results you already have. Partial real results beat no answer -- \
never discard findings from earlier successful searches just because a \
later search attempt failed or was refused. Report: (1) whether you found \
an advisory that applies to this exact version, with its URL, (2) the \
minimum version that fixes it, if stated, (3) severity if stated, (4) a \
short plain-language summary. If you find nothing from an official \
source, say so plainly -- do not guess or infer from unofficial discussion, \
and do not report an advisory that doesn't clearly cover this version."""

_ADVISORY_TOOL = {
    "name": "report_fortios_advisory",
    "description": "Report whether a known security advisory applies to this FortiOS version.",
    "input_schema": {
        "type": "object",
        "properties": {
            "has_advisory": {
                "type": "boolean",
                "description": (
                    "True only if an official source (Fortinet/NVD) clearly describes an "
                    "advisory covering this exact running version. If research was "
                    "inconclusive or no official source was found, set this to the "
                    "CAUTIOUS answer: true if there's real reason to suspect this version "
                    "is behind, false only when research clearly found nothing applicable."
                ),
            },
            "fixed_version": {"type": "string", "description": "Minimum fixed version, or empty if unknown."},
            "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "none"]},
            "source_url": {"type": "string", "description": "The official source's URL, or empty if none found."},
            "source_is_official": {"type": "boolean"},
            "summary": {"type": "string", "description": "1-3 sentence plain-language summary."},
        },
        "required": ["has_advisory", "fixed_version", "severity", "source_url", "source_is_official", "summary"],
    },
}


@dataclass
class FortiOSAdvisory:
    has_advisory: bool
    fixed_version: str
    severity: str
    source_url: str
    source_is_official: bool
    summary: str


_PSIRT_RSS_URL = "https://filestore.fortinet.com/fortiguard/rss/ir.xml"
_FG_IR_RE = re.compile(r"FG-IR-\d{2}-\d+")


def fetch_fortios_psirt_ids() -> set[str] | None:
    try:
        resp = requests.get(_PSIRT_RSS_URL, timeout=30, headers={"User-Agent": "rbd-update-bot"})
        resp.raise_for_status()
        items = ET.fromstring(resp.content).findall(".//item")
    except (requests.RequestException, ET.ParseError):
        return None
    ids: set[str] = set()
    for it in items:
        text = f"{it.findtext('title') or ''} {it.findtext('description') or ''}"
        if not re.search(r"fortios", text, re.IGNORECASE):
            continue
        m = _FG_IR_RE.search(f"{it.findtext('link') or ''} {it.findtext('guid') or ''}")
        if m:
            ids.add(m.group(0))
    return ids


def research_reason(cached: dict | None, *, now_ts: float, max_age_hours: float,
                    current_version: str, psirt_ids: set[str] | None) -> str | None:
    if max_age_hours <= 0:
        return "caching disabled"
    if not cached:
        return "no cached research"
    if cached.get("version") != current_version:
        return f"running version changed ({cached.get('version')} -> {current_version})"
    age_h = (now_ts - float(cached.get("researched_at", 0))) / 3600
    if age_h >= max_age_hours:
        return f"cached research is {age_h:.0f}h old"
    if psirt_ids:
        new = sorted(psirt_ids - set(cached.get("psirt_ids") or []))
        if new:
            return f"new FortiOS PSIRT advisory {', '.join(new[:3])}"
    return None


def check_fortios_advisory(
    *, client: anthropic.Anthropic, model: str, current_version: str, model_name: str,
) -> FortiOSAdvisory:
    research_text = _run_research_call(
        client=client, model=model, current_version=current_version, model_name=model_name,
    )
    return _run_decision_call(client=client, model=model, research_text=research_text)


def _run_research_call(
    *, client: anthropic.Anthropic, model: str, current_version: str, model_name: str,
) -> str:
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
            "content": f"Device: {model_name}\nRunning FortiOS version: {current_version}",
        }],
    )
    texts = [b.text for b in message.content if b.type == "text"]
    return "\n".join(texts) if texts else "(no research findings -- the model returned no text)"


def _run_decision_call(*, client: anthropic.Anthropic, model: str, research_text: str) -> FortiOSAdvisory:
    message = client.messages.create(
        model=model,
        max_tokens=1024,
        tools=[_ADVISORY_TOOL],
        tool_choice={"type": "tool", "name": "report_fortios_advisory"},
        messages=[{
            "role": "user",
            "content": f"Research findings:\n{research_text}",
        }],
    )
    tool_use = next(b for b in message.content if b.type == "tool_use")
    data = tool_use.input
    return FortiOSAdvisory(
        has_advisory=data["has_advisory"],
        fixed_version=data["fixed_version"],
        severity=data["severity"],
        source_url=data["source_url"],
        source_is_official=data["source_is_official"],
        summary=data["summary"],
    )
