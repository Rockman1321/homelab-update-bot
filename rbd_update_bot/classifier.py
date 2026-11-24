"""Claude calls that rate an update's risk from its release notes, review post-update logs, and write the daily briefing."""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

import anthropic

from . import local_llm
from .models import RiskAssessment

logger = logging.getLogger(__name__)

_TOOL = {
    "name": "report_risk_assessment",
    "description": "Report the breaking-change risk assessment for a software update.",
    "input_schema": {
        "type": "object",
        "properties": {
            "risk_level": {"type": "string", "enum": ["low", "medium", "high"]},
            "breaking_changes": {"type": "boolean"},
            "security_severity": {
                "type": "string",
                "enum": ["none", "important", "emergency"],
                "description": (
                    "\"none\": no security/CVE content. \"important\": a CVE, security "
                    "advisory, or explicit security/vulnerability fix is mentioned, but "
                    "nothing indicates active exploitation. \"emergency\": the release "
                    "notes/advisory describe active in-the-wild exploitation, a 0-day, or "
                    "an unauthenticated RCE -- reserve this for genuine \"patch now\" "
                    "severity, not every security mention. Independent of risk_level (a "
                    "security fix can still carry breaking changes and be high risk at the "
                    "same time)."
                ),
            },
            "summary": {
                "type": "string",
                "description": "2-4 sentence summary of what changed and why it's risky (or not).",
            },
            "citations": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Specific lines/sections from the release notes that drove the assessment.",
            },
        },
        "required": ["risk_level", "breaking_changes", "security_severity", "summary", "citations"],
    },
}

_SYSTEM_PROMPT = """You are assessing the risk of applying a software update \
to a self-hosted homelab service. You will be given release notes for the \
version delta being applied. Classify the risk of applying this update \
without extra manual review. Treat any of the following as at least medium \
risk: database migrations, config file format changes, removed or renamed \
environment variables, changed default ports, auth/permission model \
changes, or explicit "BREAKING" callouts. Default to "high" risk whenever \
the release notes are missing or too sparse to assess confidently -- \
absence of information is not evidence of safety.

Exception: if the release notes begin with the literal marker \
"VERIFIED-NO-CHANGES:", that means the actual upstream commit history was \
checked directly and confirmed to contain nothing new -- this is the \
opposite of missing information, it's a direct, positive confirmation \
that there is nothing to assess. Classify this as "low" risk with \
breaking_changes false, and say so plainly in the summary (e.g. an image \
rebuild with no underlying code change). Do not apply the "absence of \
information defaults to high" rule here -- there is no absence, the real \
history was checked and is empty.

Separately, set security_severity independent of risk_level -- do not use it \
as a substitute for the risk judgment above. A security fix can be low risk \
(a clean, well-documented patch) or high risk (a security fix that also \
changes config format or auth behavior) at the same time; report both \
honestly rather than letting one influence the other. Reserve "emergency" \
specifically for active in-the-wild exploitation, a 0-day, or an \
unauthenticated RCE -- an ordinary CVE fix with no sign of active \
exploitation is "important," not "emergency": this distinction drives a \
real automated containment action, so it must not be inflated."""


def _create_light(client: anthropic.Anthropic, model: str, fallback_model: str | None, **kwargs):
    try:
        return _create_light_api(client, model, fallback_model, **kwargs)
    except Exception as exc:
        reason = local_llm.unavailable_reason(exc)
        if reason is None or not local_llm.enabled():
            raise
        logger.warning("Anthropic API unavailable (%s: %s) -- answering on the local model", reason, exc)
        try:
            return local_llm.create_message(reason=reason, detail=str(exc), **kwargs)
        except Exception:
            logger.exception("local model fallback also failed")
            raise exc from None


def _create_light_api(client: anthropic.Anthropic, model: str, fallback_model: str | None, **kwargs):
    if not fallback_model or fallback_model == model:
        return client.messages.create(model=model, **kwargs)
    try:
        message = client.messages.create(model=model, **kwargs)
    except (anthropic.BadRequestError, anthropic.NotFoundError, anthropic.PermissionDeniedError) as exc:
        logger.warning("light model %s request failed (%s) -- retrying on %s", model, exc, fallback_model)
        return client.messages.create(model=fallback_model, **kwargs)
    if message.stop_reason == "refusal":
        logger.warning("light model %s declined (%s) -- retrying on %s", model,
                       getattr(getattr(message, "stop_details", None), "category", None), fallback_model)
        return client.messages.create(model=fallback_model, **kwargs)
    return message


def classify(
    *,
    client: anthropic.Anthropic,
    model: str,
    service_name: str,
    image: str,
    current_version: str,
    new_version: str,
    release_notes: str,
) -> RiskAssessment:
    if not release_notes.strip():
        release_notes = "(no release notes found for this version range)"

    message = client.messages.create(
        model=model,
        max_tokens=1024,
        system=_SYSTEM_PROMPT,
        tools=[_TOOL],
        tool_choice={"type": "tool", "name": "report_risk_assessment"},
        messages=[{
            "role": "user",
            "content": (
                f"Service: {service_name}\nImage: {image}\n"
                f"Version delta: {current_version} -> {new_version}\n\n"
                f"Release notes:\n{release_notes}"
            ),
        }],
    )

    tool_use = next(b for b in message.content if b.type == "tool_use")
    data = tool_use.input
    return RiskAssessment(
        risk_level=data["risk_level"],
        breaking_changes=data["breaking_changes"],
        summary=data["summary"],
        citations=data.get("citations", []),
        security_severity=data.get("security_severity", "none"),
    )


_LOG_HEALTH_TOOL = {
    "name": "report_log_health",
    "description": "Report whether a service's post-update log output looks healthy.",
    "input_schema": {
        "type": "object",
        "properties": {
            "verdict": {"type": "string", "enum": ["clean", "concerns"]},
            "summary": {
                "type": "string",
                "description": (
                    "1-3 sentences: what the logs actually show. Call out anything "
                    "worth a human's attention even if it isn't a hard failure."
                ),
            },
        },
        "required": ["verdict", "summary"],
    },
}

_LOG_CONCERN_CRITERIA = """

Before flagging a warning, check it against these questions. Flag it only if \
the answer to at least one is yes:
- Does it point to something broken or degraded right now (a failed \
connection that never recovers, a disabled app, an error a user would hit)?
- Does it look caused by this specific change rather than a standing condition \
that would show up on any restart?
- Does it affect a feature this service visibly uses in these logs?
Warnings an image's entrypoint prints on every start (for example "file X \
differs from the latest version of this image", which only means a local copy \
is older than the bundled default) and network-discovery probes that later \
succeed are standing noise unless the logs show something actually failing \
because of them. Don't speculate that something "could have" changed \
behavior -- name what the logs show, or don't flag it."""


_LOG_HEALTH_SYSTEM_PROMPT = """You are reviewing the post-update log output of \
a self-hosted homelab service, right after a version bump was applied. A \
separate, fast check already confirmed the container didn't crash-loop or \
restart -- your job is to catch the subtler stuff that check can't: an app \
or feature that got silently disabled during a migration, a deprecation or \
compatibility warning that suggests something didn't come up quite right, \
config that no longer matches the new version's expectations, or anything \
else a human glancing at these logs would want to know about. Ordinary \
startup noise (routine info-level logging, expected one-time migration \
messages, cosmetic warnings like a missing ServerName directive) is not a \
concern. Only flag "concerns" for something a human would actually want to \
look at -- don't manufacture risk to seem thorough.""" + _LOG_CONCERN_CRITERIA


def assess_log_health(
    *,
    client: anthropic.Anthropic,
    model: str,
    service_name: str,
    current_version: str,
    new_version: str,
    log_output: str,
    fallback_model: str | None = None,
) -> tuple[str, str]:
    if not log_output.strip():
        return "concerns", "No log output was collected to review."

    message = _create_light(
        client, model, fallback_model,
        max_tokens=768,
        system=_LOG_HEALTH_SYSTEM_PROMPT,
        tools=[_LOG_HEALTH_TOOL],
        tool_choice={"type": "tool", "name": "report_log_health"},
        messages=[{
            "role": "user",
            "content": (
                f"Service: {service_name}\nVersion delta: {current_version} -> {new_version}\n\n"
                f"Log output:\n{log_output[-12000:]}"
            ),
        }],
    )

    tool_use = next(b for b in message.content if b.type == "tool_use")
    data = tool_use.input
    if note := local_llm.notice_for(message):
        return data["verdict"], f"{data['summary']}\n{note}"
    return data["verdict"], data["summary"]


_REBOOT_HEALTH_TOOL = {
    "name": "report_reboot_health",
    "description": "Report whether a service's post-reboot log output looks healthy.",
    "input_schema": {
        "type": "object",
        "properties": {
            "verdict": {"type": "string", "enum": ["clean", "concerns"]},
            "summary": {
                "type": "string",
                "description": (
                    "1-3 sentences: what the logs actually show. Call out anything "
                    "worth a human's attention even if it isn't a hard failure."
                ),
            },
        },
        "required": ["verdict", "summary"],
    },
}

_REBOOT_HEALTH_SYSTEM_PROMPT = """You are reviewing the log output of a self-hosted homelab \
service's containers, right after the VM they run on was rebooted (not updated -- no new \
version, no image change, just the OS underneath coming back up). A separate, fast check \
already confirmed the containers are running and didn't crash-loop or restart on startup -- \
your job is to catch the subtler stuff that check can't: a dependency that came up in the \
wrong order, a connection error to another service that hasn't settled yet, a warning that \
suggests something didn't reattach cleanly after the reboot (a stale lock file, a volume \
mount issue, a database needing recovery), or anything else a human glancing at these logs \
would want to know about. Ordinary startup noise (routine info-level logging, normal \
reconnection/retry messages that then succeed) is not a concern. Only flag "concerns" for \
something a human would actually want to look at -- don't manufacture risk to seem thorough.""" + _LOG_CONCERN_CRITERIA


def assess_reboot_health(
    *,
    client: anthropic.Anthropic,
    model: str,
    service_name: str,
    log_output: str,
    fallback_model: str | None = None,
) -> tuple[str, str]:
    if not log_output.strip():
        return "concerns", "No log output was collected to review."

    message = _create_light(
        client, model, fallback_model,
        max_tokens=768,
        system=_REBOOT_HEALTH_SYSTEM_PROMPT,
        tools=[_REBOOT_HEALTH_TOOL],
        tool_choice={"type": "tool", "name": "report_reboot_health"},
        messages=[{
            "role": "user",
            "content": f"Service: {service_name}\n\nLog output:\n{log_output[-12000:]}",
        }],
    )

    tool_use = next(b for b in message.content if b.type == "tool_use")
    data = tool_use.input
    if note := local_llm.notice_for(message):
        return data["verdict"], f"{data['summary']}\n{note}"
    return data["verdict"], data["summary"]


_BRIEFING_SYSTEM_PROMPT = """You are writing a short status briefing for a homelab \
update-automation bot, for a human who wants a quick "where's everything at" look instead of \
reading raw tables. He's explicitly asked for this to read like a standup -- what's coming up \
gets said before what already happened, since the whole point is knowing what to expect and plan \
around, not just a retrospective. You will be given the bot's real current state: anything \
awaiting his approval and the next scheduled-maintenance window, open findings, anything the \
bot auto-restarted on its own in the last ~18h, recent update/patch/reboot outcomes, the latest \
ops-health and disk-health checks (ops-health includes backup-age, disk space, TLS cert expiry, \
and node resource checks), real per-night network bandwidth peaks for the backup-relevant hosts \
that have genuinely changed from their established baseline (already filtered -- a host that's \
still doing what it always does is pre-collapsed into one steady-state line, not handed to you \
in full detail every time), and which of the currently-pending approvals are NEW since the last \
briefing versus which cleared and how. Use ONLY what's given -- never invent or assume anything \
not present in the data.

Structure the reply under exactly these section headers, in this order (plain text, e.g. \
"Upcoming:"), and skip a section entirely if there's nothing to say under it rather than writing \
"none to report":
- Upcoming -- anything awaiting his `!approve`/`!confirm-maintenance` right now, and the next \
  scheduled-maintenance window (when, which services, and its current approval state). This is \
  the one section that's forward-looking, not a report of what already ran -- frame it that way. \
  Lean on the new-vs-cleared-since-last-briefing data you're given: call out anything genuinely \
  NEW by name, and don't re-describe an item that's unchanged since last time as if it just \
  showed up -- a queue that hasn't moved is worth one line ("still sitting since last time"), \
  not a fresh restatement of the whole list. If something cleared, say what happened to it \
  (deployed, failed, or turned out to be stale and got superseded) rather than just dropping it \
  silently. If you're given an "Upcoming window" label (a scheduled morning/evening briefing \
  names one -- "today" or "tonight/tomorrow"), title this section "Upcoming (<that label>):" \
  exactly, and only talk about what falls in that window; an on-demand !briefing gets no label, \
  so just use the plain "Upcoming:" header.
- Auto-Remediation -- anything the bot noticed was down and handled itself without paging him \
  (an automatic restart that worked). Frame this as "handled, no action needed," distinct from \
  Open Issues below (which is specifically things that still need him). If a restart attempt is \
  still in a failed/unresolved state, that belongs in Open Issues instead, not here.
- Updates Performed -- what actually ran (or failed); group repeats, name real version numbers, \
  call out any failure plainly. If you're given an "Updates Performed window" label ("yesterday" \
  for a morning briefing, "today" for an evening one), title this section "Updates Performed \
  (<that label>):" exactly -- the data you're given is already filtered to exactly that window, \
  so don't say "recently" or re-derive the window yourself, and if the list is empty just say \
  "nothing finished <label>." An on-demand !briefing gets no label and no date filtering -- use \
  the plain "Updates Performed:" header for that case, same as before.
- Backup Status -- from ops-health's backup-age checks specifically; call out anything stale or \
  alerting, otherwise a one-line "all current" is enough.
- Network Trends -- a host marked CHANGED is given with the real reason and its full per-night \
  numbers; narrate those in full, including the likely cause where one is given (never invent \
  one for a night that has none). Everything else is already pre-collapsed into one "steady, no \
  change" line -- just relay that line briefly, don't try to re-derive or restate the pattern \
  behind it. If nothing is CHANGED and there's no steady-state line either, there's nothing to \
  say here at all.
- Open Issues -- open findings and anything else actively alerting (disk health, other ops \
  health checks not already covered under Backup Status). Each finding's summary is its text \
  from when it was OPENED (its age is given); when a "current reading" is given, describe the \
  issue from that current reading, not the original summary's numbers or projections. Say how \
  long something has been open when it's more than a few days. A finding marked "investigated, \
  report delivered" is not active work -- give its conclusion in a few words from "investigation \
  said" and that it's waiting to clear, don't present it as being investigated right now. A \
  finding whose check "now reads OK" should be described as recovered-but-not-closed. A reading \
  marked STALE hasn't been re-checked recently -- say so rather than presenting it as current. \
  Lead with what genuinely needs his action; group long-standing low-stakes items (an old \
  unknown device, a minor version lag) into one short line instead of a bullet each.
- WiFi -- one line only: the peak busy-airtime and interference numbers over the last 24h, and \
  which AP/band they were on. Skip this section entirely if no WiFi RF data was given.
- Reachability -- only the services with BOTH an internal (Kuma) and external (UptimeRobot) \
  check. If every one of them is healthy both ways, one line is enough ("N/N services reachable \
  both internally and externally"). If any show up internally but not externally, name them and \
  say plainly this points at a tunnel/DNS/WAF problem with that specific hostname, NOT the service \
  itself being down -- don't alarm him about an outage that isn't real. If three or more are in \
  that same state at once, say this looks like a possible ISP/upstream issue rather than several \
  unrelated per-service problems. Skip this section entirely if no reachability data was given.

End with one line as an overall read ("looking clean" / "a couple things worth a look" / etc). \
Keep each section to 1-3 short bullets (Open Issues may use up to 5) -- this gets relayed into a Matrix chat message, not a \
report."""


_CHECK_STALE_HOURS = 36


def _age_text(iso: str | None) -> str:
    if not iso:
        return "unknown age"
    try:
        then = datetime.fromisoformat(iso)
    except ValueError:
        return "unknown age"
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    hours = (datetime.now(timezone.utc) - then).total_seconds() / 3600
    return f"{hours:.0f}h" if hours < 48 else f"{hours / 24:.0f}d"


def _stale_note(last_checked: str | None) -> str:
    if not last_checked:
        return ""
    try:
        then = datetime.fromisoformat(last_checked)
    except ValueError:
        return ""
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    hours = (datetime.now(timezone.utc) - then).total_seconds() / 3600
    if hours <= _CHECK_STALE_HOURS:
        return ""
    return f" [STALE -- not re-checked for {_age_text(last_checked)}, reading may be out of date]"


def _report_opening(report: str, limit: int = 320) -> str:
    text = re.sub(r"[*_`#>]+", "", report or "")
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit] + ("..." if len(text) > limit else "")


def _briefing_finding_line(f: dict, ops_health: list[dict]) -> str:
    status = f["status"]
    if status == "investigating" and f.get("investigation_report"):
        status = "investigated, report delivered -- waiting for the condition to clear"
    line = (f"- [{f['severity']}] {f['source']}: {f['summary']} "
            f"(opened {_age_text(f.get('created_at'))} ago; status: {status})")
    check = next((c for c in ops_health if c.get("check_id") == f.get("subject")), None)
    if check is not None:
        state = "still bad" if check.get("last_alerted_bad") else "check now reads OK -- finding not closed yet"
        line += (f"\n    current reading: {check.get('status')} -- {check.get('detail') or ''} "
                 f"({state}){_stale_note(check.get('last_checked'))}")
    if f.get("investigation_report"):
        line += f"\n    investigation said: {_report_opening(f['investigation_report'])}"
    return line


def generate_health_briefing(
    *,
    client: anthropic.Anthropic,
    model: str,
    findings: list[dict],
    recent_updates: list,
    ops_health: list[dict],
    disk_health: list[dict],
    network_trend: dict | None = None,
    network_notable: dict[str, str] | None = None,
    network_steady: list[str] | None = None,
    pending_updates: list | None = None,
    next_maintenance: dict | None = None,
    auto_remediation: list[dict] | None = None,
    new_pending_ids: set[int] | None = None,
    cleared_pending_lines: list[str] | None = None,
    reachability: list[dict] | None = None,
    wifi_rf_peaks: dict[str, dict] | None = None,
    wifi_rf_crowding_peak: dict | None = None,
    framing: str = "This briefing was requested on-demand via !briefing.",
    fallback_model: str | None = None,
    updates_period_label: str | None = None,
    upcoming_period_label: str | None = None,
) -> str:
    findings_text = "\n".join(_briefing_finding_line(f, ops_health) for f in findings) or "(none open)"
    updates_text = "\n".join(
        f"- #{u.id} {u.service_name} ({u.kind}): {u.current_version} -> {u.new_version} "
        f"[{u.stage.value}]" + (f" -- {u.error}" if u.error else "")
        for u in recent_updates
    ) or "(none recorded yet)"
    ops_text = "\n".join(
        f"- {c['check_id']}: {c['status']}" + (" [ALERTING]" if c["last_alerted_bad"] else "")
        + _stale_note(c.get("last_checked"))
        for c in ops_health
    ) or "(no checks recorded yet)"
    disk_text = "\n".join(
        f"- {d['disk_id']} ({d['model']}): health={d['health']}, "
        + (f"life remaining={d['wearout']}% (used {100 - int(d['wearout'])}%)"
           if isinstance(d['wearout'], (int, float)) else "life remaining=n/a")
        + (" [ALERTING]" if d["last_alerted_bad"] else "")
        for d in disk_health
    ) or "(no disks recorded yet)"
    network_notable = network_notable or {}
    network_lines = []
    for label, data in (network_trend or {}).items():
        if data.get("error"):
            network_lines.append(f"- {label}: {data['error']}")
            continue
        nights = data.get("nights", [])
        if not nights:
            network_lines.append(f"- {label}: no data")
            continue
        if label not in network_notable:
            continue
        per_night = []
        for n in nights:
            hhmm = n["peak_time_utc"][11:16]
            cause = f" (correlates with {n['likely_cause']})" if n.get("likely_cause") else ""
            per_night.append(
                f"{n['date']} peaked {n['in_mbps']:.0f}Mbps in / {n['out_mbps']:.0f}Mbps out "
                f"at {hhmm}Z{cause}"
            )
        network_lines.append(
            f"- {label} (CHANGED -- {network_notable[label]}): " + "; ".join(per_night)
        )
    if network_steady:
        network_lines.append(
            f"- Steady, no change from baseline: {', '.join(network_steady)} -- same nightly "
            f"backup-driven pattern as usual, nothing new to say."
        )
    network_text = "\n".join(network_lines) or "(no network trend data available)"

    upcoming_lines = [
        f"- #{u.id} {u.service_name} ({u.kind}): {u.current_version} -> {u.new_version} "
        f"[{u.risk_level or 'unknown'} risk] -- awaiting !approve"
        + (" **(new since last briefing)**" if u.id in (new_pending_ids or set()) else "")
        for u in (pending_updates or [])
    ]
    if next_maintenance is not None:
        window_str = next_maintenance["window_start"].strftime("%a %Y-%m-%d %H:%M")
        services_str = ", ".join(next_maintenance["services"]) or "(none configured)"
        approval_label = {
            "": "summary not sent yet", "pending": "awaiting !confirm-maintenance",
            "approved": "confirmed, will run", "declined": "declined/skipped this week",
        }.get(next_maintenance["approval"], next_maintenance["approval"])
        upcoming_lines.append(
            f"- Next scheduled maintenance: {window_str} -- {services_str} ({approval_label})"
        )
    upcoming_text = "\n".join(upcoming_lines) or "(nothing pending)"
    cleared_pending_text = "\n".join(
        f"- {line}" for line in (cleared_pending_lines or [])
    ) or "(nothing cleared since the last briefing)"

    auto_remediation_text = "\n".join(
        f"- {f['subject']}: {f['summary']} (status: {f['status']})"
        for f in (auto_remediation or [])
    ) or "(nothing auto-handled recently)"

    reachability_lines = [
        f"- {r['service']}: internal={r['internal_status']}, external={r['external_status']} "
        f"({r['classification']})"
        for r in (reachability or [])
    ]
    reachability_text = "\n".join(reachability_lines)

    wifi_rf_lines = []
    for field_label, peak in (wifi_rf_peaks or {}).items():
        if peak:
            wifi_rf_lines.append(
                f"- {field_label}: {peak['val']}% on {peak['ap_name']} ({peak['band']}) at {peak['ts']}"
            )
    if wifi_rf_crowding_peak:
        band_label = "2.4GHz" if wifi_rf_crowding_peak["band"] == "2g" else "5GHz"
        signal = wifi_rf_crowding_peak.get("strongest_signal")
        wifi_rf_lines.append(
            f"- busiest channel: {band_label} ch{wifi_rf_crowding_peak['channel']} "
            f"({wifi_rf_crowding_peak['neighbor_count']} neighbor(s)"
            + (f", strongest {signal}dBm)" if signal is not None else ")")
        )
    wifi_rf_text = "\n".join(wifi_rf_lines)

    message = _create_light(
        client, model, fallback_model,
        max_tokens=1800,
        thinking={"type": "disabled"},
        system=_BRIEFING_SYSTEM_PROMPT,
        messages=[{
            "role": "user",
            "content": (
                f"{framing}\n\n"
                + (
                    f"Updates Performed window: {updates_period_label} (already filtered to "
                    f"exactly this calendar window -- title the section \"Updates Performed "
                    f"({updates_period_label}):\" and don't re-derive or second-guess the window)\n"
                    f"Upcoming window: {upcoming_period_label} (title the section \"Upcoming "
                    f"({upcoming_period_label}):\")\n\n"
                    if updates_period_label and upcoming_period_label else ""
                )
                + f"Upcoming -- awaiting approval or scheduled to run:\n{upcoming_text}\n\n"
                f"Cleared from the approval queue since the last briefing:\n{cleared_pending_text}\n\n"
                f"Auto-remediation -- handled automatically, no action needed:\n{auto_remediation_text}\n\n"
                f"Open findings:\n{findings_text}\n\n"
                f"Recent updates/patches/reboots (newest first):\n{updates_text}\n\n"
                f"Ops health (backups, disk space, TLS, node resources):\n{ops_text}\n\n"
                f"Disk/SMART health:\n{disk_text}\n\n"
                f"Network bandwidth -- real peak per night over the last several days, from "
                f"LibreNMS's own history (not a live snapshot):\n{network_text}"
                + (
                    f"\n\nReachability (internal Kuma vs. external UptimeRobot, per service):\n{reachability_text}"
                    if reachability_text else ""
                )
                + (
                    f"\n\nWiFi RF -- peak busy-airtime/interference over the last 24h:\n{wifi_rf_text}"
                    if wifi_rf_text else ""
                )
            ),
        }],
    )
    text = next(b.text for b in message.content if b.type == "text").strip()
    if note := local_llm.notice_for(message):
        return f"{note}\n\n{text}"
    return text
