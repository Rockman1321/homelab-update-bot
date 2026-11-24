"""Turns a security-scan report into discrete findings that can be tracked between runs."""
from __future__ import annotations

import re
from dataclasses import dataclass

import anthropic

_TOOL = {
    "name": "report_security_findings",
    "description": "Report the discrete CVE and open-port findings extracted from a security scan report.",
    "input_schema": {
        "type": "object",
        "properties": {
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string"},
                        "finding_type": {"type": "string", "enum": ["cve", "open_port"]},
                        "identifier": {
                            "type": "string",
                            "description": (
                                "The real CVE id (e.g. \"CVE-2026-12345\") when the report states one, "
                                "or the port number as a string for an open_port finding. Use "
                                "\"pkg:<package-name>\" (e.g. \"pkg:pillow\") ONLY for a genuinely "
                                "rolled-up count/summary with no real CVE id listed -- and only when "
                                "the report itself describes that whole bucket as having no fix "
                                "available. If the report names even one real CVE id for a package "
                                "(patchable or not), use that real id, never the pkg: bucket form, even "
                                "if the report also mentions a larger unnamed count alongside it. Never "
                                "invent a CVE-looking id (\"CVE-UNKNOWN-...\") that isn't real; that "
                                "breaks dedup against future scans. Package names: lowercase, dashes/"
                                "underscores only, no spaces."
                            ),
                        },
                        "has_fix": {
                            "type": "boolean",
                            "description": (
                                "For a CVE finding: true if the report names a real fixed version "
                                "to upgrade to (even if it's bundled with other no-fix CVEs in the "
                                "same `detail` sentence) -- false if the report is a pure no-fix "
                                "rollup (the \"pkg:\" bucket form) or says no fix is available yet. "
                                "This is checked independently of `severity` (which also factors in "
                                "raw CRITICAL/HIGH/MEDIUM severity, not just fixability) -- used to "
                                "detect, on a later scan, the moment a previously no-fix CVE becomes "
                                "patchable, so it can be surfaced again instead of staying silently "
                                "deferred. For an open_port finding: always true (there's always a "
                                "concrete fix -- close the port -- so this field is a no-op there)."
                            ),
                        },
                        "severity": {
                            "type": "string",
                            "enum": ["critical", "warning", "info"],
                            "description": (
                                "Our own three-tier scheme, not Trivy's, and ranked by what's "
                                "actionable right now, not by Trivy's raw label. For a CVE: CRITICAL "
                                "or HIGH WITH a fixed version available -> \"critical\" (top priority "
                                "-- there's a real action to take right now, and the fact that the "
                                "normal image-update pipeline would also eventually pick it up doesn't "
                                "make it less worth flagging today). CRITICAL with NO fix available "
                                "yet -> \"warning\" (worth tracking, but waiting won't resolve it and "
                                "there's nothing to actually do about it right now, so it shouldn't "
                                "outrank something patchable). HIGH/MEDIUM with a fix available -> "
                                "\"warning\". MEDIUM, LOW, or UNKNOWN with no fix, or anything LOW/ "
                                "UNKNOWN regardless of fix status -> \"info\". Fixed 2026-10-24: "
                                "patchable HIGH/CRITICAL findings were being out-ranked by (or hidden "
                                "inside a rolled-up count behind) no-fix CRITICAL findings that "
                                "couldn't actually be acted on -- the thing we can fix today should "
                                "never be lower priority than the thing we can't. An unexpected/"
                                "concerning open port -> \"warning\" or \"critical\" by context (e.g. "
                                "an admin panel open to the world with no auth is critical; a port "
                                "that's merely redundant with an existing tunnel is warning)."
                            ),
                        },
                        "detail": {
                            "type": "string",
                            "description": (
                                "Package/version and fixed-version-or-\"no fix yet\" for a CVE, or the "
                                "service/context for a port. 1 sentence."
                            ),
                        },
                    },
                    "required": ["host", "finding_type", "identifier", "severity", "has_fix", "detail"],
                },
            },
        },
        "required": ["findings"],
    },
}

_SYSTEM_PROMPT = """You are extracting discrete, machine-trackable findings \
from a fleet security scan report (Trivy CVE data and port exposure, \
already analyzed by a prior step -- your job is structure extraction, not \
re-analysis). Extract exactly two kinds of finding:

1. CVEs: one entry per distinct affected package per host, using the real \
CVE id as the identifier whenever the report states one (if a package has \
several CVE ids, pick the single most severe/representative one as the \
identifier and mention the rest in `detail` -- but if any of those several \
ids has a fix available, that patchable one is always the representative \
id, never a no-fix one, even if the no-fix id is nominally more severe). \
Only use "pkg:<package-name>" as the identifier, instead of a real CVE id, \
for a package the report describes purely as a rolled-up no-fix count with \
no individual CVE id given at all -- never invent a CVE-looking id that \
isn't real. Normalize Trivy's severity to our scheme as described in the \
tool schema, which ranks patchable findings above no-fix ones regardless \
of Trivy's own CRITICAL/HIGH label. Set `has_fix` to match what you just \
decided for that CVE -- true if you used a real fixed-version id as the \
identifier, false only for a genuine "pkg:" no-fix rollup.

2. Open ports the report itself flags as unexpected or concerning -- NOT \
every port mentioned. A port the report describes as expected/already \
firewalled/intentionally exposed should NOT be extracted as a finding at \
all; only extract ports the report itself treats as a real concern.

Do not extract failed-auth-log mentions, general narrative, or anything \
else -- only CVEs and concerning open ports. If the report mentions \
neither for a host, that host contributes no findings. If the report is \
entirely clean, return an empty findings array -- that is a valid, correct \
answer, not a failure to find something."""

_HOST_NOTE_TEMPLATE = """

`host` must be exactly one name from this list, copied verbatim -- never a \
shortened or renamed variant (the report itself may call a host by a \
shorthand; translate it to the matching name here): {names}.

For an open_port finding, `identifier` is always ONE port number as a \
string. Never a range ("8420-8422") or a comma list ("10011, 10022") -- if \
a host has several concerning ports, emit one separate finding per port, \
each with its own identifier, not one finding covering several ports."""


def _build_system_prompt(host_names: list[str] | None) -> str:
    if not host_names:
        return _SYSTEM_PROMPT
    return _SYSTEM_PROMPT + _HOST_NOTE_TEMPLATE.format(names=", ".join(sorted(host_names)))


@dataclass
class SecurityFinding:
    host: str
    finding_type: str
    identifier: str
    severity: str
    has_fix: bool
    detail: str


_PLACEHOLDER_IDENTIFIERS = {"", "<unknown>", "unknown", "n/a", "none", "null"}


def _canonical_host(host: str, host_names: list[str] | None) -> str:
    if not host_names or host in host_names:
        return host
    by_lower = {h.lower(): h for h in host_names}
    if host.lower() in by_lower:
        return by_lower[host.lower()]
    by_stripped = {h.lower().removeprefix("rbd-"): h for h in host_names}
    stripped = host.lower().removeprefix("rbd-")
    return by_stripped.get(stripped, host)


def _split_port_identifier(identifier: str) -> list[str]:
    parts: list[str] = []
    for chunk in identifier.split(","):
        chunk = chunk.strip()
        m = re.fullmatch(r"(\d+)\s*-\s*(\d+)", chunk)
        if m:
            lo, hi = int(m.group(1)), int(m.group(2))
            if 0 <= hi - lo <= 20:
                parts.extend(str(p) for p in range(lo, hi + 1))
                continue
        parts.append(chunk)
    return parts or [identifier]


def extract_findings(
    *, client: anthropic.Anthropic, model: str, report_text: str, host_names: list[str] | None = None,
) -> list[SecurityFinding]:
    message = client.messages.create(
        model=model,
        max_tokens=16384,
        system=_build_system_prompt(host_names),
        tools=[_TOOL],
        tool_choice={"type": "tool", "name": "report_security_findings"},
        messages=[{"role": "user", "content": f"Security scan report:\n{report_text}"}],
    )
    if message.stop_reason == "max_tokens":
        raise RuntimeError("security finding extraction hit max_tokens -- output was truncated, not trustworthy")
    tool_use = next(b for b in message.content if b.type == "tool_use")

    results: list[SecurityFinding] = []
    for f in tool_use.input.get("findings", []):
        identifier = (f.get("identifier") or "").strip()
        if identifier.lower() in _PLACEHOLDER_IDENTIFIERS:
            continue
        host = _canonical_host(f["host"], host_names)
        idents = _split_port_identifier(identifier) if f["finding_type"] == "open_port" else [identifier]
        for ident in idents:
            results.append(SecurityFinding(
                host=host, finding_type=f["finding_type"], identifier=ident,
                severity=f["severity"], has_fix=f.get("has_fix", True), detail=f["detail"],
            ))
    return results
