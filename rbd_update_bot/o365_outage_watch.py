"""Checks Microsoft's status pages when Graph calls start failing."""
from __future__ import annotations

from dataclasses import dataclass

import anthropic

_WEB_SEARCH_TOOL_TYPE = "web_search_20260209"
_MAX_SEARCHES = 6
_ALLOWED_DOMAINS = [
    "microsoft.com", "status.cloud.microsoft", "techcommunity.microsoft.com",
    "learn.microsoft.com", "azure.status.microsoft",
]

_RESEARCH_SYSTEM_PROMPT = """You are checking whether Microsoft 365 / Microsoft Graph is \
currently experiencing a known service incident, for a small home-tenant integration that \
just started seeing failures calling the Graph API (mail/mailbox-rule endpoints specifically). \
Call the web_search tool directly (never through code execution or any other indirection) \
against Microsoft's own status surfaces: status.cloud.microsoft, the Microsoft 365 admin \
service health documentation on learn.microsoft.com, Microsoft's tech community posts, or \
azure.status.microsoft. You have a hard limit of a few web_search calls -- use them \
efficiently, and the moment you hit a tool-limit error, STOP searching and write your summary \
from whatever results you already have. Partial real results beat no answer -- never discard \
findings from earlier successful searches just because a later search attempt failed. Report: \
(1) whether an official Microsoft source describes a CURRENT or very recent (last few hours) \
incident affecting Exchange Online, Outlook, or Microsoft Graph / Entra ID, with a URL, \
(2) which workload(s) it names, (3) its current status (investigating/identified/mitigating/ \
resolved), (4) a short plain-language summary. If your searches genuinely found nothing current \
from an official source, say so plainly -- do not guess or infer from unofficial discussion, and \
do not report an incident that doesn't clearly look current (a resolved incident from days ago \
is not a current outage)."""

_ADVISORY_TOOL = {
    "name": "report_o365_outage",
    "description": "Report whether Microsoft 365/Graph has a current known service incident.",
    "input_schema": {
        "type": "object",
        "properties": {
            "has_active_outage": {
                "type": "boolean",
                "description": (
                    "True only if an official Microsoft source clearly describes a CURRENT "
                    "incident covering Exchange Online/Outlook/Graph/Entra. If research was "
                    "inconclusive, set this to the CAUTIOUS answer: true if there's real reason "
                    "to suspect an ongoing incident, false only when research clearly found "
                    "nothing current."
                ),
            },
            "affected_workloads": {
                "type": "string",
                "description": "Comma-separated workload names the incident names, or empty if none found.",
            },
            "status": {
                "type": "string",
                "enum": ["investigating", "identified", "mitigating", "resolved", "unknown"],
            },
            "source_url": {"type": "string", "description": "The official source's URL, or empty if none found."},
            "summary": {"type": "string", "description": "1-3 sentence plain-language summary."},
        },
        "required": ["has_active_outage", "affected_workloads", "status", "source_url", "summary"],
    },
}


@dataclass
class O365OutageAdvisory:
    has_active_outage: bool
    affected_workloads: str
    status: str
    source_url: str
    summary: str


def check_o365_outage(*, client: anthropic.Anthropic, model: str, trigger_detail: str) -> O365OutageAdvisory:
    research_text = _run_research_call(client=client, model=model, trigger_detail=trigger_detail)
    return _run_decision_call(client=client, model=model, research_text=research_text)


def _run_research_call(*, client: anthropic.Anthropic, model: str, trigger_detail: str) -> str:
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
            "content": f"Local symptom that triggered this check: {trigger_detail or '(no detail captured)'}",
        }],
    )
    texts = [b.text for b in message.content if b.type == "text"]
    return "\n".join(texts) if texts else "(no research findings -- the model returned no text)"


def _run_decision_call(*, client: anthropic.Anthropic, model: str, research_text: str) -> O365OutageAdvisory:
    message = client.messages.create(
        model=model,
        max_tokens=1024,
        tools=[_ADVISORY_TOOL],
        tool_choice={"type": "tool", "name": "report_o365_outage"},
        messages=[{
            "role": "user",
            "content": f"Research findings:\n{research_text}",
        }],
    )
    tool_use = next(b for b in message.content if b.type == "tool_use")
    data = tool_use.input
    return O365OutageAdvisory(
        has_active_outage=data["has_active_outage"],
        affected_workloads=data["affected_workloads"],
        status=data["status"],
        source_url=data["source_url"],
        summary=data["summary"],
    )
