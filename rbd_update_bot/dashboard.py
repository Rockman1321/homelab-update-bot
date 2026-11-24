"""Small read-only status dashboard."""
from __future__ import annotations

import html
import re
from datetime import datetime, timezone

from aiohttp import web

from .db import Store
from .models import UpdateRecord

_GOOD = "#0ca30c"
_WARNING = "#fab219"
_SERIOUS = "#ec835a"
_CRITICAL = "#d03b3b"

_PAGE_TEMPLATE = """<!DOCTYPE html>
<html><head><title>rbd-update-bot status</title>
<meta http-equiv="refresh" content="30">
<meta charset="utf-8">
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; background: #111; color: #eee; }}
h1 {{ margin-bottom: 0.2rem; }}
h2 {{ border-bottom: 1px solid #444; padding-bottom: 0.3rem; margin-top: 2rem; }}
table {{ border-collapse: collapse; width: 100%; }}
td, th {{ text-align: left; padding: 0.3rem 0.6rem; border-bottom: 1px solid #333; }}
th {{ color: #999; font-weight: normal; }}
.critical {{ color: #ff6b6b; }}
.warning {{ color: #ffd166; }}
.info {{ color: #888; }}
.empty {{ color: #666; font-style: italic; }}

/* Stat tiles -- label/value/status accent, per the dataviz skill's
   "stat tile" contract. The value stays in primary ink (text never
   wears the status color); the left accent bar carries the status. */
.tiles {{ display: flex; gap: 1rem; flex-wrap: wrap; margin: 1rem 0 2rem; }}
.tile {{
  background: #1a1a19; border-left: 4px solid #383835; border-radius: 4px;
  padding: 0.6rem 1rem; min-width: 9rem;
}}
.tile.tile-critical {{ border-left-color: """ + _CRITICAL + """; }}
.tile.tile-warning {{ border-left-color: """ + _WARNING + """; }}
.tile.tile-good {{ border-left-color: """ + _GOOD + """; }}
.tile-label {{ color: #898781; font-size: 0.8rem; }}
.tile-value {{ font-size: 1.8rem; font-weight: 600; line-height: 1.2; }}

/* Meter -- the fill carries severity, track is a neutral hairline-gray
   step so state reads across the whole bar (dataviz skill's "meter"
   mark). Width 25% (buckets to the nearest 10 for ARIA correctness
   without a sub-pixel-precision claim this data doesn't have). */
.meter-row {{ display: flex; align-items: center; gap: 0.5rem; }}
.meter {{ flex: 0 0 90px; height: 8px; background: #2c2c2a; border-radius: 4px; overflow: hidden; }}
.meter-fill {{ height: 100%; border-radius: 4px; }}
.meter-label {{ font-variant-numeric: tabular-nums; color: #c3c2b7; }}

/* Status pill -- icon-shaped dot + label, never color alone (fixed
   status palette, same rule as the meter fill colors). */
.pill {{ display: inline-flex; align-items: center; gap: 0.4rem; }}
.pill::before {{ content: ""; width: 8px; height: 8px; border-radius: 50%; flex: none; }}
.pill-good::before {{ background: """ + _GOOD + """; }}
.pill-warning::before {{ background: """ + _WARNING + """; }}
.pill-critical::before {{ background: """ + _CRITICAL + """; }}
.pill-neutral::before {{ background: #898781; }}

/* Active-update timeline -- replaces the plain <ul> of stage_events
   with a small vertical line + dot per event, current stage as a pill. */
.timeline {{ list-style: none; margin: 0.4rem 0 0; padding: 0; border-left: 2px solid #383835; }}
.timeline li {{ position: relative; padding: 0.15rem 0 0.15rem 1rem; margin-left: -2px; font-size: 0.9rem; color: #c3c2b7; }}
.timeline li::before {{ content: ""; position: absolute; left: -5px; top: 0.4rem; width: 8px; height: 8px; border-radius: 50%; background: #383835; }}
.timeline li:last-child::before {{ background: #3987e5; }}
.update-block {{ margin-bottom: 1.2rem; }}
</style></head>
<body>
<h1>rbd-update-bot</h1>
<p class="empty">Auto-refreshes every 30s. Generated {now}.</p>

<div class="tiles">{tiles}</div>

<h2>Active right now ({active_count})</h2>
{active_table}

<h2>Open findings ({finding_count})</h2>
{findings_table}

<h2>Recent updates</h2>
{updates_table}

<h2>Scheduled maintenance</h2>
{maintenance_status}

<h2>Ops health</h2>
{ops_health_table}

<h2>Disk / SMART health</h2>
{disk_health_table}

<h2>Network devices</h2>
{devices_table}

<h2>WireGuard peers</h2>
{wg_peers_table}

<h2>Caddy builds</h2>
{caddy_builds_table}
</body></html>"""


def _esc(value: object) -> str:
    return html.escape(str(value)) if value is not None else ""


def _age_str(created_at: str) -> str:
    try:
        created = datetime.fromisoformat(created_at)
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age_hours = (datetime.now(timezone.utc) - created).total_seconds() / 3600
    except (ValueError, TypeError):
        return "?"
    if age_hours < 1:
        return f"{age_hours * 60:.0f}m"
    if age_hours < 48:
        return f"{age_hours:.1f}h"
    return f"{age_hours / 24:.1f}d"


_PCT_RE = re.compile(r"(\d+(?:\.\d+)?)%")
_DAYS_REMAINING_RE = re.compile(r"(\d+)d remaining")


def _status_class(is_bad: bool) -> str:
    return "critical" if is_bad else "good"


def _meter(pct: float, *, is_bad: bool, label: str) -> str:
    pct = max(0.0, min(100.0, pct))
    color = _CRITICAL if is_bad else _GOOD
    return (
        f'<span class="meter-row" title="{_esc(label)}">'
        f'<span class="meter"><span class="meter-fill" '
        f'style="width:{pct:.0f}%;background:{color}"></span></span>'
        f'<span class="meter-label">{_esc(label)}</span></span>'
    )


def _pill(status_text: str, *, is_bad: bool) -> str:
    cls = _status_class(is_bad)
    return f'<span class="pill pill-{cls}">{_esc(status_text)}</span>'


def _stat_tile(label: str, value: int, *, cls: str = "neutral") -> str:
    return (
        f'<div class="tile tile-{cls}"><div class="tile-value">{value}</div>'
        f'<div class="tile-label">{_esc(label)}</div></div>'
    )


_SEVERITY_PILL_CLASS = {"critical": "critical", "warning": "warning"}


def _render_findings(findings: list[dict]) -> str:
    if not findings:
        return '<p class="empty">No open findings.</p>'
    rows = []
    for f in findings:
        severity = str(f.get("severity") or "info")
        pill_cls = _SEVERITY_PILL_CLASS.get(severity, "neutral")
        rows.append(
            f"<tr>"
            f"<td>#{_esc(f.get('id'))}</td>"
            f'<td><span class="pill pill-{pill_cls}">{_esc(severity)}</span></td>'
            f"<td>{_esc(f.get('status'))}</td>"
            f"<td>{_esc(f.get('source'))}</td>"
            f"<td>{_esc(f.get('summary'))}</td>"
            f"<td>{_age_str(f.get('created_at', ''))}</td>"
            f"</tr>"
        )
    return (
        "<table><tr><th>ID</th><th>Severity</th><th>Status</th><th>Source</th>"
        "<th>Summary</th><th>Age</th></tr>" + "".join(rows) + "</table>"
    )


def _render_updates(updates: list[UpdateRecord]) -> str:
    if not updates:
        return '<p class="empty">No updates recorded yet.</p>'
    rows = []
    for u in updates:
        rows.append(
            f"<tr>"
            f'<td><a href="/update/{_esc(u.id)}">#{_esc(u.id)}</a></td>'
            f"<td>{_esc(u.service_name)}</td>"
            f"<td>{_esc(u.kind)}</td>"
            f"<td>{_esc(u.current_version)} &rarr; {_esc(u.new_version)}</td>"
            f"<td>{_esc(u.stage.value)}</td>"
            f"<td>{_esc(u.risk_level) or '-'}</td>"
            f"<td>{_age_str(u.created_at or '')}</td>"
            f"</tr>"
        )
    return (
        "<table><tr><th>ID</th><th>Service</th><th>Kind</th><th>Version</th>"
        "<th>Stage</th><th>Risk</th><th>Age</th></tr>" + "".join(rows) + "</table>"
    )


_JOB_PAGE_TEMPLATE = """<!DOCTYPE html>
<html><head><title>Update #{update_id} -- rbd-update-bot</title>
<meta charset="utf-8">
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; background: #111; color: #eee; }}
h1 {{ margin-bottom: 0.2rem; }}
a {{ color: #3987e5; }}
.empty {{ color: #666; font-style: italic; }}
.meta {{ color: #c3c2b7; margin: 0.5rem 0 1.5rem; }}
.pill {{ display: inline-flex; align-items: center; gap: 0.4rem; }}
.pill::before {{ content: ""; width: 8px; height: 8px; border-radius: 50%; flex: none; background: #898781; }}
.timeline {{ list-style: none; margin: 0.4rem 0 0; padding: 0; border-left: 2px solid #383835; }}
.timeline li {{ position: relative; padding: 0.3rem 0 0.3rem 1.2rem; margin-left: -2px; font-size: 0.95rem; color: #c3c2b7; }}
.timeline li::before {{ content: ""; position: absolute; left: -5px; top: 0.5rem; width: 8px; height: 8px; border-radius: 50%; background: #383835; }}
.timeline li:last-child::before {{ background: #3987e5; }}
</style></head>
<body>
<p><a href="/">&larr; back to dashboard</a></p>
<h1>#{update_id} {service_name} ({kind})</h1>
<p class="meta">{current_version} &rarr; {new_version} &nbsp; <span class="pill">{stage}</span>
&nbsp; risk: {risk_level} &nbsp; started {age}</p>
{error_block}
<h2>Full step history ({event_count})</h2>
{timeline}
</body></html>"""


def _render_job_detail(record: UpdateRecord, store: Store) -> str:
    events = store.events_for(record.id)
    event_lines = "".join(
        f"<li>{_esc(e['created_at'])} &mdash; {_esc(e['message'])}</li>" for e in events
    ) or '<li class="empty">(no stage events recorded)</li>'
    error_block = (
        f'<p class="meta" style="color:#ff6b6b">Error: {_esc(record.error)}</p>' if record.error else ""
    )
    return _JOB_PAGE_TEMPLATE.format(
        update_id=_esc(record.id),
        service_name=_esc(record.service_name),
        kind=_esc(record.kind),
        current_version=_esc(record.current_version),
        new_version=_esc(record.new_version),
        stage=_esc(record.stage.value),
        risk_level=_esc(record.risk_level) or "-",
        age=_age_str(record.created_at or ""),
        error_block=error_block,
        event_count=len(events),
        timeline=f'<ul class="timeline">{event_lines}</ul>',
    )


def _render_active(active: list[UpdateRecord], store: Store) -> str:
    if not active:
        return '<p class="empty">Nothing in progress right now.</p>'
    blocks = []
    for u in active:
        events = store.events_for(u.id)
        recent = events[-5:]
        event_lines = "".join(
            f"<li>{_esc(e['created_at'])} &mdash; {_esc(e['message'])}</li>"
            for e in recent
        ) or '<li class="empty">(no stage events recorded yet)</li>'
        blocks.append(
            f'<div class="update-block"><strong><a href="/update/{_esc(u.id)}">#{_esc(u.id)}</a> '
            f'{_esc(u.service_name)}</strong> '
            f"({_esc(u.kind)}): {_esc(u.current_version)} &rarr; {_esc(u.new_version)} &nbsp; "
            f'<span class="pill pill-neutral">{_esc(u.stage.value)}</span>'
            f'<ul class="timeline">{event_lines}</ul></div>'
        )
    return "".join(blocks)


_METER_SOURCES = ("disk_space", "node_resources", "dsm_system")


def _render_ops_health(checks: list[dict]) -> str:
    if not checks:
        return '<p class="empty">No ops-health checks recorded yet.</p>'
    rows = []
    for c in checks:
        is_bad = bool(c.get("last_alerted_bad"))
        source = c.get("source") or ""
        status = str(c.get("status") or "")
        pct_match = _PCT_RE.search(status) if source in _METER_SOURCES else None
        days_match = _DAYS_REMAINING_RE.search(status) if source == "cert_expiry" else None
        if pct_match:
            status_cell = _meter(float(pct_match.group(1)), is_bad=is_bad, label=status)
        elif days_match:
            days = int(days_match.group(1))
            status_cell = _meter(min(100.0, days / 90 * 100), is_bad=is_bad, label=status)
        else:
            status_cell = _pill(status, is_bad=is_bad)
        rows.append(
            f"<tr>"
            f"<td>{_esc(c.get('check_id'))}</td>"
            f"<td>{status_cell}</td>"
            f"<td>{_esc(c.get('detail')) or '-'}</td>"
            f"<td>{_age_str(c.get('last_checked', ''))}</td>"
            f"</tr>"
        )
    return (
        "<table><tr><th>Check</th><th>Status</th><th>Detail</th><th>Last checked</th></tr>"
        + "".join(rows) + "</table>"
    )


def _render_disk_health(disks: list[dict]) -> str:
    if not disks:
        return '<p class="empty">No disks recorded yet.</p>'
    rows = []
    for d in disks:
        is_bad = bool(d.get("last_alerted_bad"))
        wearout = d.get("wearout")
        wearout_cell = (
            _meter(float(wearout), is_bad=is_bad, label=f"{wearout}%")
            if wearout is not None else "-"
        )
        rows.append(
            f"<tr>"
            f"<td>{_esc(d.get('disk_id'))}</td>"
            f"<td>{_esc(d.get('model')) or '-'}</td>"
            f"<td>{_pill(str(d.get('health')), is_bad=is_bad)}</td>"
            f"<td>{wearout_cell}</td>"
            f"<td>{_age_str(d.get('last_checked', ''))}</td>"
            f"</tr>"
        )
    return (
        "<table><tr><th>Disk</th><th>Model</th><th>Health</th><th>Life remaining</th>"
        "<th>Last checked</th></tr>" + "".join(rows) + "</table>"
    )


def _render_devices(devices: list[dict]) -> str:
    if not devices:
        return '<p class="empty">No devices recorded yet.</p>'
    rows = []
    for d in devices:
        label = d.get("label") or ("trusted" if d.get("trusted_at") else "")
        rows.append(
            f"<tr><td>{_esc(d.get('mac'))}</td><td>{_esc(d.get('ip')) or '-'}</td>"
            f"<td>{_esc(d.get('vlan')) or '-'}</td><td>{_esc(d.get('port')) or '-'}</td>"
            f"<td>{_esc(d.get('source')) or '-'}</td><td>{_esc(label) or '-'}</td>"
            f"<td>{_age_str(d.get('last_seen', ''))}</td></tr>"
        )
    return (
        "<table><tr><th>MAC</th><th>IP</th><th>VLAN</th><th>Port/AP</th><th>Source</th>"
        "<th>Label</th><th>Last seen</th></tr>" + "".join(rows) + "</table>"
    )


def _render_wg_peers(peers: list[dict]) -> str:
    if not peers:
        return '<p class="empty">No WireGuard peers recorded yet.</p>'
    rows = []
    for p in peers:
        connected = "yes" if p.get("currently_connected") else "no"
        rows.append(
            f"<tr><td>{_esc(p.get('label')) or '(unlabeled)'}</td>"
            f"<td>{_esc(p.get('allowed_ips')) or '-'}</td>"
            f"<td>{connected}</td>"
            f"<td>{_age_str(p.get('last_handshake_at') or '') if p.get('last_handshake_at') else 'never'}</td>"
            f"<td>{_age_str(p.get('last_seen', ''))}</td></tr>"
        )
    return (
        "<table><tr><th>Label</th><th>Allowed IP</th><th>Connected</th>"
        "<th>Last handshake</th><th>Last seen</th></tr>" + "".join(rows) + "</table>"
    )


def _render_caddy_builds(builds: list[dict]) -> str:
    if not builds:
        return '<p class="empty">No Caddy builds recorded yet.</p>'
    rows = []
    for b in builds:
        digest = str(b.get("last_built_digest") or "")
        rows.append(
            f"<tr><td>{_esc(b.get('name'))}</td><td>{_esc(digest[:19])}&hellip;</td>"
            f"<td>{_age_str(b.get('last_built_at', ''))}</td></tr>"
        )
    return (
        "<table><tr><th>Image</th><th>Last built digest</th><th>Last built</th></tr>"
        + "".join(rows) + "</table>"
    )


def build_dashboard_app(store: Store) -> web.Application:
    app = web.Application()

    async def handle_index(request: web.Request) -> web.Response:
        active = store.list_active()
        findings = store.list_findings()
        updates = store.list_recent(limit=20)
        maint_week = store.get_meta("sched_maint_week")
        maint_approval = store.get_meta("sched_maint_approval")
        ops_health = store.list_ops_health()
        disk_health = store.list_disk_health()
        devices = store.list_known_devices()
        wg_peers = store.list_wg_peers()
        caddy_builds = store.list_caddy_builds()

        if maint_week:
            maintenance_status = (
                f'<p>Current window: <strong>{_esc(maint_week)}</strong> -- '
                f'approval: <strong>{_esc(maint_approval) or "(none pending)"}</strong></p>'
            )
        else:
            maintenance_status = '<p class="empty">Scheduled maintenance has not run yet.</p>'

        critical_count = sum(1 for f in findings if f.get("severity") == "critical")
        warning_count = sum(1 for f in findings if f.get("severity") == "warning")
        alerting_count = sum(1 for c in ops_health if c.get("last_alerted_bad")) + sum(
            1 for d in disk_health if d.get("last_alerted_bad")
        )
        tiles = "".join([
            _stat_tile("Critical findings", critical_count, cls="critical" if critical_count else "good"),
            _stat_tile("Warning findings", warning_count, cls="warning" if warning_count else "good"),
            _stat_tile("Active right now", len(active)),
            _stat_tile("Health checks alerting", alerting_count, cls="critical" if alerting_count else "good"),
        ])

        html_body = _PAGE_TEMPLATE.format(
            now=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            tiles=tiles,
            active_count=len(active),
            active_table=_render_active(active, store),
            finding_count=len(findings),
            findings_table=_render_findings(findings),
            updates_table=_render_updates(updates),
            maintenance_status=maintenance_status,
            ops_health_table=_render_ops_health(ops_health),
            disk_health_table=_render_disk_health(disk_health),
            devices_table=_render_devices(devices),
            wg_peers_table=_render_wg_peers(wg_peers),
            caddy_builds_table=_render_caddy_builds(caddy_builds),
        )
        return web.Response(text=html_body, content_type="text/html")

    async def handle_job_detail(request: web.Request) -> web.Response:
        try:
            update_id = int(request.match_info["update_id"])
        except ValueError:
            return web.Response(text="Not a valid update id.", status=404)
        record = store.get(update_id)
        if record is None:
            return web.Response(text=f"No update #{update_id}.", status=404)
        return web.Response(text=_render_job_detail(record, store), content_type="text/html")

    app.router.add_get("/", handle_index)
    app.router.add_get("/update/{update_id}", handle_job_detail)
    return app
