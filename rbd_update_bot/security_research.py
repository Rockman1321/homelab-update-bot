"""Web research for emergency containment of an actively exploited vulnerability."""
from __future__ import annotations

from dataclasses import dataclass

import anthropic

_WEB_SEARCH_TOOL_TYPE = "web_search_20260209"
_MAX_SEARCHES = 6

_RESEARCH_SYSTEM_PROMPT = """You are researching a software vulnerability \
for a self-hosted homelab service, to inform an emergency containment \
decision. Call the web_search tool directly (never through code execution \
or any other indirection) to check the vendor's own advisories, the \
project's GitHub Security Advisories, and/or NVD for this CVE/vulnerability. \
You have a hard limit of a few web_search calls -- use them efficiently, \
and the moment you hit a tool-limit error, STOP searching and write your \
summary from whatever results you already have. Partial real results beat \
no answer -- never discard findings from earlier successful searches just \
because a later search attempt failed or was refused. Report: (1) whether \
you found an official source describing it, with its URL, (2) whether it's \
exploitable only over the network/externally, or also locally/internally, \
(3) a short plain-language summary. If you find nothing from an official \
source, say so plainly -- do not guess or infer from unofficial discussion."""

_CONTAINMENT_TOOL = {
    "name": "report_containment_action",
    "description": "Report which pre-built containment action to take for this vulnerability.",
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["stop_tunnel", "stop_service"],
                "description": (
                    "\"stop_tunnel\": an official source confirms this is exploitable only "
                    "over the network/externally -- cutting external access alone is "
                    "sufficient containment. \"stop_service\": no official source was found, "
                    "the research was inconclusive, OR it's exploitable locally/internally too "
                    "-- fail toward the more aggressive containment whenever uncertain."
                ),
            },
            "source_url": {"type": "string", "description": "The official source's URL, or empty if none found."},
            "source_is_official": {"type": "boolean"},
            "summary": {"type": "string", "description": "1-3 sentence plain-language summary."},
        },
        "required": ["action", "source_url", "source_is_official", "summary"],
    },
}


@dataclass
class ContainmentDecision:
    action: str
    source_url: str
    source_is_official: bool
    summary: str


def research_containment_action(
    *,
    client: anthropic.Anthropic,
    model: str,
    service_name: str,
    vulnerability_summary: str,
    allowed_domains: list[str],
) -> ContainmentDecision:
    research_text = _run_research_call(
        client=client, model=model, service_name=service_name,
        vulnerability_summary=vulnerability_summary, allowed_domains=allowed_domains,
    )
    return _run_decision_call(client=client, model=model, research_text=research_text)


def _run_research_call(
    *, client: anthropic.Anthropic, model: str, service_name: str,
    vulnerability_summary: str, allowed_domains: list[str],
) -> str:
    web_search_tool: dict = {"type": _WEB_SEARCH_TOOL_TYPE, "name": "web_search", "max_uses": _MAX_SEARCHES}
    if allowed_domains:
        web_search_tool["allowed_domains"] = allowed_domains

    message = client.messages.create(
        model=model,
        max_tokens=2048,
        system=_RESEARCH_SYSTEM_PROMPT,
        tools=[web_search_tool],
        tool_choice={"type": "auto"},
        messages=[{
            "role": "user",
            "content": (
                f"Service: {service_name}\n"
                f"Vulnerability (from release notes/classifier): {vulnerability_summary}"
            ),
        }],
    )
    texts = [b.text for b in message.content if b.type == "text"]
    return "\n".join(texts) if texts else "(no research findings -- the model returned no text)"


def _run_decision_call(*, client: anthropic.Anthropic, model: str, research_text: str) -> ContainmentDecision:
    message = client.messages.create(
        model=model,
        max_tokens=1024,
        tools=[_CONTAINMENT_TOOL],
        tool_choice={"type": "tool", "name": "report_containment_action"},
        messages=[{
            "role": "user",
            "content": f"Research findings:\n{research_text}",
        }],
    )
    tool_use = next(b for b in message.content if b.type == "tool_use")
    data = tool_use.input
    return ContainmentDecision(
        action=data["action"],
        source_url=data["source_url"],
        source_is_official=data["source_is_official"],
        summary=data["summary"],
    )
