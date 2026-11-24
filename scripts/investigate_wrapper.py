#!/usr/bin/env python3
"""Forced-command SSH target on the management host for investigations and security scans."""
from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

import requests

_MGMT1_SSH_AGENT_SOCK = "/run/user/1000/ssh-agent.socket"


def _ssh_err(stderr: str) -> str:
    stderr = (stderr or "").strip()
    if "Permission denied (publickey" not in stderr:
        return stderr
    try:
        probe = subprocess.run(
            ["ssh-add", "-l"], capture_output=True, text=True, timeout=5,
            env={**os.environ, "SSH_AUTH_SOCK": _MGMT1_SSH_AGENT_SOCK},
        )
    except (OSError, subprocess.TimeoutExpired):
        return stderr
    if probe.returncode == 1:
        return (f"{stderr} -- mgmt1's SSH agent has no key loaded (mgmt1 was "
                f"probably rebooted); run `SSH_AUTH_SOCK={_MGMT1_SSH_AGENT_SOCK} "
                f"ssh-add ~/.ssh/id_ed25519` on mgmt1, then retry")
    if probe.returncode == 2:
        return (f"{stderr} -- mgmt1's SSH agent isn't running at "
                f"{_MGMT1_SSH_AGENT_SOCK}; check `systemctl --user status ssh-agent` on mgmt1")
    return stderr


_PROMPT_TEMPLATE = """A homelab service update just failed and needs a root-cause \
investigation. You are running in read-only plan mode -- investigate only, do not \
attempt to fix, change, or restart anything. Report findings and a recommendation; \
someone else will act on it.

Service: {service}
Version: {current_version} -> {new_version}
Failure reported by the update pipeline:
{error}
{bot_host_note}
Investigate the root cause (check relevant logs, container/service status, and \
recent config on the affected host over SSH as needed). Then report:
1. What actually went wrong, in plain terms.
2. Whether this looks like a bad update (recommend rollback) or something \
environmental (disk space, network, an unrelated dependency) that a rollback won't fix.
3. Any other detail worth a human knowing before they decide what to do next.
{repair_plan_note}
{rollback_safety_note}
{mass_recovery_note}
{immich_recovery_note}
{nextcloud_recovery_note}
{discourse_recovery_note}
Keep the report under 300 words -- it gets relayed into a Matrix chat message."""

_SECURITY_SCAN_PROMPT_TEMPLATE = """Run a read-only security sweep across the homelab hosts listed below. \
You are running in read-only plan mode -- investigate and report only, do not fix, \
change, restart, or scan/probe anything not listed here. Each host's ssh_host/ssh_user \
is given; SSH to each one (or run locally for any host whose ssh_host is "localhost").

Hosts:
{host_list}

For EACH host, check exactly these three things:

1. **Unexpected listening ports.** Run `ss -tlnp` (or equivalent). For a docker host, \
compare against what's actually declared in that service's compose file if you can \
read it (paths are in {compose_dir_note}) -- flag anything bound to 0.0.0.0 that isn't \
the expected reverse-proxy/tunnel container, and anything you don't recognize at all. \
A container-internal port not published to the host is fine and not worth mentioning.

2. **Failed-auth log patterns.** Check recent auth logs (`journalctl -u ssh --no-pager -n 200` \
or `/var/log/auth.log`) for repeated "Failed password"/"Invalid user" entries -- note \
volume, source IPs if visible, and whether it looks like routine internet background \
noise vs. something targeted or successful.

3. **Package/CVE staleness on running images.** Collect every container's exact image \
reference across ALL hosts first (`docker inspect --format='{{{{.Config.Image}}}}' <container>`), \
then de-duplicate that list -- if the same image:tag runs in multiple containers (e.g. an \
app and a cron container sharing one image), scan it only once. Then, for each DISTINCT \
image, run `/home/rbdroot/.local/bin/trivy image --scanners vuln --severity HIGH,CRITICAL \
--timeout 90s <image-ref>` (trivy runs locally on this machine -- it doesn't need to be on \
the remote host, just given the exact image:tag string). For ANY finding -- CRITICAL or \
HIGH -- that Trivy shows a fixed version for, report one line per affected package: \
`<package> <installed>-><fixed-version> (<real CVE id(s)>)` -- always give the real CVE \
id(s), never a bare count or a made-up placeholder id. A patchable finding must never be \
buried inside a rolled-up count, regardless of whether Trivy calls it CRITICAL or HIGH -- \
these are the ones that actually drive this report's priority, since there's a real action \
available right now. Only findings with NO fix available yet may be rolled up into a single \
count per image/severity (e.g. "+34 HIGH with no fix yet") -- there's nothing to act on for \
those beyond noting they exist. If a scan is clearly hanging past its own 90s timeout, move \
on -- note it as "scan timed out" rather than waiting indefinitely.

Some images (custom Caddy builds, Discourse's launcher-rebuilt app image) are built \
locally on their own host and don't exist in any registry -- a plain `trivy image <ref>` on \
one of these will fail outright (nothing to pull), not just be slow. If a scan fails with a \
registry/pull error rather than a timeout, use one of these two fallbacks depending on the \
image:

- **Discourse's host specifically (ssh_host for discourse) has Trivy installed locally** \
(confirmed live 2026-10-05, same binary/version as this machine) -- for `local_discourse/app`, \
SSH there and scan in place instead of transferring anything: `ssh <discourse ssh_host> \
"~/.local/bin/trivy image local_discourse/app:latest --scanners vuln --severity \
HIGH,CRITICAL --timeout 300s"`. That image is ~6.85GB, far too large to usefully transfer \
over this network (confirmed ~40Mbps uplink elsewhere in this homelab -- a plain `docker \
save`+`scp` of it would take ~20+ minutes just for the copy); scanning in place instead \
takes well under 5 minutes (confirmed live: 3m34s) since nothing but the small text report \
crosses the network. This was a real, confirmed-permanent gap before Trivy was installed \
there -- don't fall back to the transfer method for this specific image.
- **Every other locally-built image** (the Caddy builds -- all well under 200MB, confirmed \
live) is small enough that the transfer method works fine (confirmed live: ~24s end-to-end): \
stream it from the host it runs on -- `ssh <ssh_host> "docker save <image-ref> -o \
/tmp/rbd-scan-image.tar"`, then `scp <ssh_host>:/tmp/rbd-scan-image.tar \
/tmp/rbd-scan-image.tar`, then `/home/rbdroot/.local/bin/trivy image --input \
/tmp/rbd-scan-image.tar --scanners vuln --severity HIGH,CRITICAL --timeout 90s`, then clean \
up both the remote and local tarball afterward (`ssh <ssh_host> "rm -f \
/tmp/rbd-scan-image.tar"` and `rm -f /tmp/rbd-scan-image.tar`).

If either path still somehow eats into your time budget, note "not scanned, locally-built \
image, ran out of time" and move on rather than letting one image stall the rest of the sweep.

{fortigate_note}
{omada_note}
IMPORTANT -- this is a single, one-shot, non-interactive invocation: once you produce your \
final answer this process exits and nothing continues afterward. There is no "later" you can \
report back in, no background job that finishes on its own, and nobody re-invokes you to pick \
up where you left off. Do not end your turn with a status update saying more is still running \
or a fuller report is coming -- there will be no fuller report unless you produce it now, in \
this one response. If time is tight, prioritize finishing every check listed above across all \
hosts at lower depth (e.g. skip scanning images you've already established are unlikely to \
matter, or note "not scanned, ran out of time" plainly) over reporting deep results for only \
some hosts and leaving others unaddressed.

Report back, grouped by host, only what's actually worth attention -- skip a host entirely \
in your report if every check for it comes back clean rather than writing "nothing found" for \
every host. End with one overall line: how many hosts had at least one real finding, and \
whether every host was actually checked or any had to be skipped for time. Keep the whole \
report under 600 words -- it gets relayed into a Matrix chat message."""

_FORTIGATE_NOTE_TEMPLATE = """
4. **FortiGate log check.** Read the API token from the local file {token_file} on this \
machine (never print its contents, never put it in a shell command's argument list where \
`ps` could see it -- read it inside a script/subshell instead, e.g. \
`TOKEN=$(cat {token_file}); curl -sk -H "Authorization: Bearer $TOKEN" ...`). This \
FortiGate may have no log disk, so query \
{api_host}/api/v2/log/memory/event/system (recent entries, e.g. `?count=50`), not \
/log/disk/ and not /log/memory/event/admin (that path 404s on this firmware -- admin login/ \
logout/config-change events are all under event/system instead, not a separate admin \
category). Look for failed admin logins, lockouts, or config changes you wouldn't expect. \
Also check .../log/memory/traffic for hits on the geo-block/ \
BLOCKLIST deny policy if you can identify it -- a real spike there would mean active \
probing against the exposed game-server/LiveKit ports. `Authorization: Bearer` is the \
confirmed-working auth method; if it ever stops authenticating, retry with the token as a \
`?access_token=` query parameter before giving up. Also query \
{api_host}/api/v2/monitor/system/dhcp for current DHCP leases (IP/MAC/hostname/vci/expiry) \
-- confirmed working live 2026-09-28 with this profile's Network: Read grant. Flag anything \
that looks unfamiliar: a hostname you don't recognize, a vendor-class-identifier/MAC that \
doesn't match a device you know, or a lease you wouldn't expect on that interface/VLAN. If \
unreachable or the auth doesn't work either way, say so plainly in the report as its own line ("FortiGate check \
failed: <why>") and move on -- don't let it block the checks above."""

_OMADA_NOTE_TEMPLATE = """
5. **Omada switch/network check.** Read {config_file} on this machine (never print its \
contents or put any value from it in a shell command's argument list where `ps` could see \
it -- read it into shell variables inside a script/subshell instead) -- it has \
OMADA_BASE_URL, OMADA_CLIENT_ID, OMADA_OMADAC_ID, OMADA_CLIENT_SECRET as KEY=VALUE lines. \
This is TP-Link's cloud Omada Open API, confirmed working live 2026-09-28:
  a. Get an access token: POST $OMADA_BASE_URL/openapi/authorize/token?grant_type=client_credentials \
with JSON body {{"omadacId": $OMADA_OMADAC_ID, "client_id": $OMADA_CLIENT_ID, "client_secret": \
$OMADA_CLIENT_SECRET}} -- the token is at .result.accessToken in the response.
  b. Every subsequent call uses header `Authorization: AccessToken=<token>` (note: literally \
"AccessToken=", NOT "Bearer" -- this API does not use the standard OAuth2 header format).
  c. List sites: GET $OMADA_BASE_URL/openapi/v1/$OMADA_OMADAC_ID/sites?page=1&pageSize=100 \
-- the site list is at .result.data (or .result if that's a bare list -- handle both shapes).
  d. For each site (often just one), using its siteId: \
GET .../sites/{{siteId}}/devices?page=1&pageSize=100 (device inventory -- switches/APs, \
online/offline status, firmware) and \
GET .../sites/{{siteId}}/switches/ports/overview?page=1&pageSize=100 (per-port connected \
client/device info).
  e. Also try GET .../sites/{{siteId}}/clients?page=1&pageSize=100 for the connected-client \
list (which switch port or AP each device is on). This endpoint's exact shape isn't \
independently confirmed like the ones above -- if it 404s or errors, just note "client list \
endpoint not available" as one line and move on, don't treat it as a hard failure of the \
whole check.
Report anything that looks like it doesn't belong: a device you wouldn't expect to see, a \
port showing something unusual, or a device offline that you'd expect to be up. There is no \
stored baseline from a prior run to compare against yet, so just report what's actually \
there factually rather than guessing at what's "new" -- same honest framing as the \
WireGuard peer check above. If the API is unreachable or auth fails, say so plainly as its \
own line ("Omada check failed: <why>") and move on -- don't let it block the checks above."""

_REPAIR_PLAN_NOTE = """
If you find a specific, safe, mechanical fix -- one that's just running the right \
occ command(s), with no judgment calls needed at execution time -- end your report \
with a section starting with exactly this line:

REPAIR PLAN:

followed by each command on its own line, in the exact form "$ occ <subcommand>" \
(e.g. "$ occ db:add-missing-indices"), nothing else on those lines -- no numbering, \
no explanation, no other text. A human decides whether to actually run this later; \
it is executed completely mechanically, exactly as written, so only include a \
command here if running it verbatim is genuinely safe. If there's no safe mechanical \
fix -- the problem needs more diagnosis, human judgment, or isn't an occ-level issue \
at all -- omit this section entirely rather than force one.
"""

_ROLLBACK_SAFETY_NOTE = """
This service is eligible for an automatic compose-level rollback (restoring the \
previous version's container -- no database changes of its own). Before anything \
acts on that, check specifically whether the new version's container actually \
started and began running (not just "docker compose up" exiting without error) -- \
if it did, this app runs its own database migrations automatically on startup, and \
those migrations have no automatic way back. A rollback at that point means the OLD \
application code running against an ALREADY-MIGRATED database schema, which can be \
a worse, more confusing failure than the one being fixed, not a safe recovery. Look \
for real evidence either way (container start time vs. failure time, migration-\
related log lines, whether the app ever became reachable) -- don't assume.

End your report with exactly one of these two lines:

ROLLBACK SAFETY: safe
ROLLBACK SAFETY: unsafe -- <one-sentence reason>

Only say "safe" if you found real evidence the new version never got far enough to \
touch the database. If you're unsure or the evidence is mixed, say "unsafe" -- a \
human reviewing it manually is the safe default, not assuming the best case.
"""

_MASS_RECOVERY_NOTE = """
This service (Music Assistant) floats on a plain "latest" registry tag -- a compose-level \
rollback of the file alone would just float right back onto the same new version, so any fix \
here means redeploying a specific prior image digest instead. Music Assistant maintains its own \
embedded SQLite library database (library.db) with its own migration logic that runs \
automatically at startup -- and, importantly, the app itself already writes library.db.backup \
immediately before running any migration, specifically so a bad migration has something real to \
recover to. Check specifically: did the new version's container start and attempt its migration \
step before failing (migration-related log lines, container start time vs. failure time, whether \
the web UI/API ever became reachable)? If a migration ran, is library.db.backup present and does \
its modification time line up with this update attempt (not some much older, stale snapshot)?

End your report with exactly one of these four lines:

MASS RECOVERY: redeploy-only
MASS RECOVERY: restore-and-redeploy
MASS RECOVERY: needs-vm-restore -- <one-sentence reason>
MASS RECOVERY: unknown -- <one-sentence reason>

"redeploy-only" means you found real evidence no migration ran -- just a bad container, data \
untouched. "restore-and-redeploy" means a migration ran and library.db.backup looks like the \
right, current pre-migration snapshot to recover to. "needs-vm-restore" means the problem goes \
beyond what a digest/library.db recovery can fix (e.g. the backup itself looks stale, missing, or \
something else entirely is wrong) -- this requires an actual Proxmox-level restore, which only a \
human can trigger; say so plainly, don't attempt to describe exact commands for it. If genuinely \
unsure, say "unknown" -- never assume the safe case.
"""

_IMMICH_RECOVERY_NOTE = """
This service (Immich) is Portainer-managed and floats on a registry-resolved version -- there is \
no compose file this investigation can edit directly. Immich's Postgres database runs its own \
migrations automatically on startup, with no automatic way back. Check specifically whether the \
new version's immich_server container actually started and began running before failing \
(migration-related log lines, container start time vs. failure time, whether the API ever became \
reachable).

If no migration ran: the automated fix is redeploying the exact pair of images (immich-server AND \
immich-machine-learning together) this service ran successfully before this update.

If a migration DID run: this pipeline already triggers Immich's own backup-database job \
immediately before every update, so a genuinely fresh dump already exists under \
/mnt/immich_media/backups, dated right before this update started. The automated fix in that case \
restores that dump into a freshly recreated immich database (app containers stopped, Postgres \
itself never touched) and redeploys the matching old image pair -- NOT Immich's own documented \
disaster-recovery procedure (that one wipes volumes and needs a fresh install, out of scope here).

End your report with exactly one of these three lines:

IMMICH RECOVERY: redeploy-safe
IMMICH RECOVERY: restore-db-and-redeploy
IMMICH RECOVERY: unknown -- <one-sentence reason>

Only say "redeploy-safe" if you found real evidence the new version never got far enough to touch \
the database. Only say "restore-db-and-redeploy" if a migration genuinely ran and a fresh backup \
dump should exist. If genuinely unsure, say "unknown" -- never assume either safe case.
"""

_NEXTCLOUD_RECOVERY_NOTE = """
This service (Nextcloud) floats on a registry-resolved version via a plain Compose file -- a \
compose-level rollback of the file alone would just float right back onto the same new version, so \
any fix here means redeploying a specific prior image digest instead. Nextcloud's Postgres database \
runs its own migrations automatically on startup (via occ upgrade), with no automatic way back. \
Check specifically whether the new version's app container actually started and began running \
before failing (migration-related log lines, container start time vs. failure time, whether the \
web UI ever became reachable).

If no migration ran: the automated fix is redeploying the last known-good image digest, data \
untouched.

If a migration DID run: this pipeline already runs a fresh pg_dump immediately before every \
update, so a genuinely fresh dump already exists under this service's compose directory, dated \
right before this update started. The automated fix in that case restores that dump into a freshly \
recreated database (app containers stopped, Postgres itself never touched) and redeploys the \
matching old image digest, wrapped in occ maintenance:mode on/off.

End your report with exactly one of these three lines:

NEXTCLOUD RECOVERY: redeploy-safe
NEXTCLOUD RECOVERY: restore-db-and-redeploy
NEXTCLOUD RECOVERY: unknown -- <one-sentence reason>

Only say "redeploy-safe" if you found real evidence the new version never got far enough to touch \
the database. Only say "restore-db-and-redeploy" if a migration genuinely ran and a fresh pg_dump \
should exist. If genuinely unsure, say "unknown" -- never assume either safe case.
"""

_DISCOURSE_RECOVERY_NOTE = """
This service (Discourse) deploys via `./launcher rebuild app` -- a locally-built image, no pinned \
tag or digest to roll back to, and no occ-equivalent repair command. There IS, however, a real, \
already-tested restore mechanism for this exact situation: Discourse's own native backup/restore \
tooling (`discourse backup`/`discourse restore <filename>`), with backups already pulled daily to \
mgmt1 and a fresh one taken automatically right before this update ran. Check whether this failure \
looks like something a restore would actually fix (a bad migration, broken data state, the app \
never coming back healthy) versus something else entirely (e.g. a transient network blip, a \
problem with the VM itself) that a restore wouldn't help with.

End your report with exactly one of these two lines:

DISCOURSE RECOVERY: restore-recommended
DISCOURSE RECOVERY: unknown -- <one-sentence reason>

Only say "restore-recommended" if you found real evidence this update meaningfully changed \
Discourse's data/state and a restore to just before this update is the right fix. If the failure \
looks unrelated to data/migrations, or you're genuinely unsure, say "unknown" -- a restore is not a \
free action (it reverts every real post/upload since the backup), so this must not be suggested \
casually.
"""


def _build_investigate_prompt(ctx: dict) -> str:
    self_host = ctx.get("self_ssh_host", "")
    self_user = ctx.get("self_ssh_user", "")
    self_dir = ctx.get("self_install_dir", "")
    if self_host and self_user and self_dir:
        bot_host_note = (
            f"\nThe update bot itself runs on {self_user}@{self_host}, installed at "
            f"{self_dir} (config.yaml, services.yaml, state.db). If the failure might "
            f"trace back to the bot's own config rather than the affected service, SSH "
            f"there and check the live files directly -- don't rely on this repo's git "
            f"history or example files (services.example.yaml etc.) as a stand-in for "
            f"what's actually deployed; the real services.yaml is gitignored and can "
            f"drift from the example.\n"
        )
    else:
        bot_host_note = ""

    repair_plan_note = _REPAIR_PLAN_NOTE if ctx.get("supports_repair") else ""
    rollback_safety_note = _ROLLBACK_SAFETY_NOTE if ctx.get("supports_rollback") else ""
    mass_recovery_note = _MASS_RECOVERY_NOTE if ctx.get("supports_mass_digest_rollback") else ""
    immich_recovery_note = _IMMICH_RECOVERY_NOTE if ctx.get("supports_immich_digest_rollback") else ""
    nextcloud_recovery_note = _NEXTCLOUD_RECOVERY_NOTE if ctx.get("supports_nextcloud_recovery") else ""
    discourse_recovery_note = _DISCOURSE_RECOVERY_NOTE if ctx.get("service") == "discourse" else ""

    return _PROMPT_TEMPLATE.format(
        service=ctx.get("service", "unknown"),
        current_version=ctx.get("current_version", "unknown"),
        new_version=ctx.get("new_version", "unknown"),
        error=ctx.get("error", "(no error text provided)"),
        bot_host_note=bot_host_note,
        repair_plan_note=repair_plan_note,
        rollback_safety_note=rollback_safety_note,
        mass_recovery_note=mass_recovery_note,
        immich_recovery_note=immich_recovery_note,
        nextcloud_recovery_note=nextcloud_recovery_note,
        discourse_recovery_note=discourse_recovery_note,
    )


def _build_security_scan_prompt(ctx: dict) -> str:
    hosts = ctx.get("hosts", [])
    host_lines = []
    compose_dir_notes = []
    for h in hosts:
        line = f"- {h['name']}: ssh_host={h['ssh_host']!r}, ssh_user={h['ssh_user']!r}"
        if h.get("compose_dir"):
            line += f", compose_dir={h['compose_dir']!r}"
            compose_dir_notes.append(f"{h['name']}: {h['compose_dir']}")
        if h.get("note"):
            line += f"\n  Extra check for this host: {h['note']}"
        host_lines.append(line)
    host_list = "\n".join(host_lines) if host_lines else "(none provided)"
    compose_dir_note = "; ".join(compose_dir_notes) if compose_dir_notes else "each host's own listing above"

    fortigate = ctx.get("fortigate") or {}
    fortigate_note = ""
    if fortigate.get("api_host") and fortigate.get("token_file"):
        fortigate_note = _FORTIGATE_NOTE_TEMPLATE.format(
            api_host=fortigate["api_host"], token_file=fortigate["token_file"],
        )

    omada = ctx.get("omada") or {}
    omada_note = ""
    if omada.get("config_file"):
        omada_note = _OMADA_NOTE_TEMPLATE.format(config_file=omada["config_file"])

    return _SECURITY_SCAN_PROMPT_TEMPLATE.format(
        host_list=host_list, compose_dir_note=compose_dir_note,
        fortigate_note=fortigate_note, omada_note=omada_note,
    )


_NETWORK_FINDING_PROMPT_TEMPLATE = """The active network monitor flagged a new device and it needs a closer \
look. You are running in read-only plan mode -- investigate only, do not attempt to block, \
disconnect, or change anything on the network. Report findings and a recommendation; \
The owner decides what to do next (e.g. via !trust-device).

Device flagged:
  MAC:      {mac}
  IP:       {ip}
  VLAN:     {vlan}
  Port/AP:  {port}
  Vendor:   {vendor}
  Hostname: {hostname}
  Detected via: {source}
{omada_note}
{fortigate_note}
Consider: does the hostname/vendor/VLAN combination look like a routine, expected kind of \
device (a phone, a smart-home gadget, a game console) landing where you'd expect it, or does \
something about it look inconsistent or concerning? If FortiGate access is available, check \
whether this MAC has an active DHCP lease and whether its traffic (if visible) looks routine.

Report:
1. Your best assessment of what this device most likely is.
2. Whether this looks routine or worth closer manual attention.
3. A clear recommendation -- e.g. "trust it as <label>" or "needs a manual look before trusting."

Keep the report under 300 words -- it gets relayed into a Matrix chat message."""

_DISK_FINDING_PROMPT_TEMPLATE = """A disk/storage health monitor flagged a state change and it needs a \
closer look. You are running in read-only plan mode -- investigate only, do not attempt to \
repair, resilver, or change any storage configuration. Report findings and a recommendation; \
a human decides what to do next (there's no safe automated fix for a physical disk problem).

Finding:
  Disk/volume: {disk_id}
  Source:      {source}
  Health:      {health}
  Life remaining: {wearout}

Full data collected at alert time (includes any per-attribute SMART detail beyond the \
summary above, if the collector gathered it):
{detail_json}

{deeper_access_note}
Report:
1. Your best assessment of severity and likely cause (genuinely failing hardware vs. a \
transient blip vs. something environmental).
2. Whether this needs urgent physical attention (e.g. replace the drive soon) or can wait/\
just needs continued watching.
3. Any other detail worth The owner knowing before deciding what to do.

Keep the report under 300 words -- it gets relayed into a Matrix chat message."""

_NETWORK_FINDING_OMADA_NOTE_TEMPLATE = """You have Omada access: read {config_file} on this machine (KEY=VALUE lines: \
OMADA_BASE_URL, OMADA_CLIENT_ID, OMADA_OMADAC_ID, OMADA_CLIENT_SECRET). Get a token via \
POST $OMADA_BASE_URL/openapi/authorize/token?grant_type=client_credentials (JSON body with \
omadacId/client_id/client_secret, token at .result.accessToken), then use header \
`Authorization: AccessToken=<token>` (not "Bearer"). Look up this specific MAC in the site's \
/clients list (GET .../sites/{{siteId}}/clients) for whatever current detail is available -- \
don't just restate the summary already given above."""

_NETWORK_FINDING_FORTIGATE_NOTE_TEMPLATE = """You have FortiGate access: read the token from {token_file} on this machine (never print \
it or put it in a command argument -- read it into a shell variable instead), then check \
{api_host}/api/v2/monitor/system/dhcp for this specific MAC's current lease detail, using \
`Authorization: Bearer <token>`."""

_NETWORK_ISSUE_OMADA_NOTE_TEMPLATE = """You have Omada access: read {config_file} on this machine (KEY=VALUE lines: \
OMADA_BASE_URL, OMADA_CLIENT_ID, OMADA_OMADAC_ID, OMADA_CLIENT_SECRET). Get a token via \
POST $OMADA_BASE_URL/openapi/authorize/token?grant_type=client_credentials (JSON body with \
omadacId/client_id/client_secret, token at .result.accessToken), then use header \
`Authorization: AccessToken=<token>` (not "Bearer"). This is about OVERALL network health, not \
one device: check every AP's status/online state, per-AP client counts (one overloaded relative \
to others is a real signal), and channel/interference data if the API surfaces it \
(GET .../sites/{{siteId}}/devices for AP status; GET .../sites/{{siteId}}/clients for the \
current client list and which AP each one is on). If the reported problem or the roam history \
above points at a specific device, also look that one up specifically in the client list."""

_NETWORK_ISSUE_FORTIGATE_NOTE_TEMPLATE = """You have FortiGate access: read the token from {token_file} on this machine (never print \
it or put it in a command argument -- read it into a shell variable instead). Check \
{api_host}/api/v2/monitor/system/interface for WAN/uplink status and current throughput, and \
{api_host}/api/v2/monitor/system/dhcp for the current lease list (useful if the reported \
problem points at a specific device), using `Authorization: Bearer <token>`. If the report \
describes two hosts that can't reach each other (e.g. across VLANs), also check \
{api_host}/api/v2/cmdb/firewall/policy for the configured policy table, and \
{api_host}/api/v2/cmdb/system/interface to resolve each policy's srcintf/dstintf interface \
names to the actual VLAN/subnet each host lives on -- then reason about whether an \
enabled policy actually permits that specific src/dst/service combination, or a deny \
(explicit or the implicit catch-all) is the real cause. A `"q_limited_permission": true` \
field on a policy object means the API token can't see its real srcintf/dstintf/srcaddr/ \
dstaddr/service/action (they come back as empty/placeholder values) -- say so plainly \
rather than treating a redacted policy as if it were a real "deny" or guessing further. \
You can also check real live sessions (confirmed live 2026-10-02 -- note the plural, \
`sessions` not `session`): \
{api_host}/api/v2/monitor/firewall/sessions?ip_version=ipboth&start=0&count=1000&summary=true&vdom=root \
-- each entry has srcintf/saddr/sport, dstintf/daddr/dport, proto, policyid (the exact \
policy that matched this specific flow -- more reliable than reasoning about the policy \
table alone, since NAT/matching can be non-obvious), sentbyte/rcvdbyte, duration, and app \
identification. Useful for confirming whether a specific flow is actually happening right \
now, which policy really matched it, or what's consuming bandwidth."""

_PMX_SMART_NOTE_TEMPLATE = """This disk is on Proxmox node {node}, device {device}. The full per-attribute SMART \
data (reallocated/pending sector counts etc, not just the coarse health/wearout summary) is \
already included in the finding detail above -- the disk health monitor collects it directly \
every cycle now, so it's at most a few hours stale, not worth a live re-check for data that \
only moves on a slow timescale anyway. Interpret it directly: is any sector count nonzero or \
climbing versus what you'd expect for this drive's age/model, and does that change the \
severity assessment versus the coarse health/wearout summary alone?"""

_API_RECHECK_NOTE_TEMPLATE = """No host-level shell access exists for this host from here -- only its own API, which is \
already what collected the summary data above. Re-query it for a fresh reading rather than \
just re-describing the same numbers: {recheck_instructions}"""


def _build_network_finding_prompt(finding: dict, ctx: dict) -> str:
    detail = finding.get("detail") or {}
    omada = ctx.get("omada") or {}
    omada_note = (
        _NETWORK_FINDING_OMADA_NOTE_TEMPLATE.format(config_file=omada["config_file"])
        if omada.get("config_file") else ""
    )
    fortigate = ctx.get("fortigate") or {}
    fortigate_note = (
        _NETWORK_FINDING_FORTIGATE_NOTE_TEMPLATE.format(
            api_host=fortigate["api_host"], token_file=fortigate["token_file"],
        )
        if fortigate.get("api_host") and fortigate.get("token_file") else ""
    )
    return _NETWORK_FINDING_PROMPT_TEMPLATE.format(
        mac=finding.get("subject", "unknown"),
        ip=detail.get("ip") or "(none)",
        vlan=detail.get("vlan") or "(unknown)",
        port=detail.get("port") or "(unknown)",
        vendor=detail.get("vendor") or "Unknown",
        hostname=detail.get("hostname") or "(none)",
        source=detail.get("source", "unknown"),
        omada_note=omada_note,
        fortigate_note=fortigate_note,
    )


def _build_disk_finding_prompt(finding: dict, ctx: dict) -> str:
    detail = finding.get("detail") or {}
    source = detail.get("source", "")
    disk_id = finding.get("subject", "unknown")

    if source == "proxmox":
        node, _, device = disk_id.partition(":")
        deeper_access_note = _PMX_SMART_NOTE_TEMPLATE.format(node=node, device=device)
    elif source == "pbs":
        deeper_access_note = _API_RECHECK_NOTE_TEMPLATE.format(
            recheck_instructions="PBS's own /nodes/localhost/disks/list endpoint, using the "
            "PBS_TOKEN this bot's environment already has configured for it."
        )
    elif source in ("synology_disk", "synology_volume"):
        synology = ctx.get("synology") or {}
        if synology.get("config_file"):
            deeper_access_note = _API_RECHECK_NOTE_TEMPLATE.format(
                recheck_instructions=f"DSM's Storage Manager API, using the credentials in "
                f"{synology['config_file']} on this machine (same SYNO.API.Auth login + "
                f"SYNO.Storage.CGI.Storage load_info flow already confirmed working)."
            )
        else:
            deeper_access_note = "No Synology credential is configured -- work from the summary data above only."
    else:
        deeper_access_note = "No deeper host-level access is available for this source -- work from the summary data above only."

    return _DISK_FINDING_PROMPT_TEMPLATE.format(
        disk_id=disk_id,
        source=source or "unknown",
        health=f"{detail.get('health', 'unknown')} (finding severity: {finding.get('severity', 'unknown')})",
        wearout=(f"{detail['wearout']}% (Proxmox wearout field; 100 = new, i.e. {100 - int(detail['wearout'])}% used)"
                 if isinstance(detail.get("wearout"), (int, float)) else "(n/a)"),
        detail_json=json.dumps(detail, indent=2),
        deeper_access_note=deeper_access_note,
    )


_AP_FLAPPING_FINDING_PROMPT_TEMPLATE = """The active network monitor flagged a client repeatedly roaming between \
access points and it needs a closer look. You are running in read-only plan mode -- \
investigate only, do not attempt to change any AP/WiFi settings (channel, power, WLAN \
Optimization). Report findings and a recommendation; a human decides what to do next.

Client flagged:
  MAC:         {mac}
  Most recent: {detail}
  Rate:        {status}

Full roam history for this MAC in the last 24h (most recent first):
{roam_history}

{omada_note}
{fortigate_note}
Consider: is this consistent with a mobile device (phone/laptop) moving around the house, or \
does the rate/pattern look like an AP problem (one AP flapping its clients, a bad uplink, \
interference)? A low, steady rate from one client is usually nothing; a high rate, or several \
clients doing this at once, points at the AP side instead of the device.

Report:
1. Your best assessment of what's causing this.
2. Whether this looks routine (mobile device behavior) or worth a closer look at the APs \
themselves.
3. A clear recommendation -- e.g. "nothing to do," "keep watching," or a specific AP setting \
worth checking.

Keep the report under 300 words -- it gets relayed into a Matrix chat message."""

_WIREGUARD_FINDING_PROMPT_TEMPLATE = """A new, never-before-seen WireGuard peer connected and it needs a closer look. You \
are running in read-only plan mode -- investigate only, do not attempt to add, remove, or \
change any WireGuard peer configuration. Report findings and a recommendation; a human decides \
what to do next (e.g. via !trust-peer).

Peer flagged:
  Public key:  {pubkey}
  Allowed IPs: {allowed_ips}
  Endpoint:    {endpoint}

There is no deeper live access available for this beyond what's shown above -- no host-level \
shell access to the WireGuard server is wired into this investigation, and the peer's public \
key alone carries no identifying information about whose device it is. Work from the \
Allowed IPs/endpoint shown and what that implies (does the endpoint look like a plausible \
location/ISP, does the allowed-IPs range fit the existing addressing scheme) rather than \
trying to positively identify the device.

Report:
1. Whether anything about the Allowed IPs/endpoint looks inconsistent with a legitimate, \
expected peer.
2. Whether this looks routine (a new device The owner set up himself) or worth a closer manual \
look before trusting it.
3. A clear recommendation -- e.g. "trust it as <label>" or "needs a manual look before \
trusting."

Keep the report under 300 words -- it gets relayed into a Matrix chat message."""

_OPS_HEALTH_FINDING_PROMPT_TEMPLATE = """An ops-health monitor ({check_source}) flagged a state change and it needs a closer \
look. You are running in read-only plan mode -- investigate only, do not attempt to repair, \
retry, or change any backup/storage/certificate configuration. Report findings and a \
recommendation; a human decides what to do next.

Check:    {check_id}
Status:   {status}
Detail:   {detail}

Full data collected at alert time:
{detail_json}

No deeper live host-level access is wired into this investigation beyond what's shown above --
this check's own collector (Proxmox/PBS/Synology API, or a TLS handshake for a cert check) \
already gathered the summary data, at most a few hours stale. Work from it directly rather \
than claiming to re-check a live system you don't actually have a path to.

Report:
1. Your best assessment of severity and likely cause.
2. Whether this needs prompt attention or can wait/just needs continued watching.
3. Any other detail worth The owner knowing before deciding what to do.

Keep the report under 300 words -- it gets relayed into a Matrix chat message."""


_FIREWALL_TRAFFIC_FINDING_PROMPT_TEMPLATE = """The firewall traffic monitor flagged {check_id} and it needs a closer \
look. You are running in read-only plan mode -- investigate only, do not attempt to block an \
IP, change any FortiGate policy, or alter any firewall configuration. This always ends in a \
recommendation for The owner to act on, never an automated block -- live traffic control is \
deliberately the most cautious tier in this project and stays a human decision.

Check:    {check_id}
Status:   {status}

Full data collected at alert time (the specific flagged IPs/countries/counters, if any):
{detail_json}

{fortigate_note}
This check is one of three kinds -- infer which from the check_id prefix and reason \
accordingly: `fw_blocklist_spike:<policyid>` means a packet-count spike against The owner's \
existing geo-BLOCKLIST deny rule for that policy (background internet-wide \
scanning is constant and not itself alarming -- the question is whether this spike looks \
like routine noise or something more targeted/sustained); `fw_exposure_geo:<policyid>` means \
a non-US-sourced session reached a policy that's open to every country (if this \
network's legitimate traffic on these specific policies is normally domestic, so \
treat a real hit here as a genuine anomaly, not routine); `fw_exposure_volume:<policyid>` \
means an unusually high number of distinct source IPs hit one externally-exposed policy in \
one poll window (could be a real scan, or could be legitimate -- e.g. a game server's normal \
matchmaking/relay traffic genuinely uses many IPs via NAT, so look at what the policy's \
dstaddr actually is and whether that volume is plausible for it before calling it suspicious).

Report:
1. Your best assessment of what's actually happening and whether it looks routine or genuinely \
concerning -- connect the raw numbers back to a real likely cause, don't just restate them.
2. Whether this needs prompt attention or can wait/just needs continued watching.
3. A recommendation The owner could act on if he chooses to (e.g. "worth adding this country to \
BLOCKLIST," "worth watching this specific IP") -- framed as his decision, not something this \
investigation does itself.

Keep the report under 300 words -- it gets relayed into a Matrix chat message."""


_USER_REPORT_FINDING_PROMPT_TEMPLATE = """A real person reported an issue through the public outage-report form \
and it needs a closer look. You are running in read-only plan mode -- investigate and diagnose \
only, do not restart, repair, roll back, or change anything. Report findings and a \
recommendation; a human decides what to do next.

This exists specifically to catch what synthetic monitoring (Uptime Kuma's port/HTTP checks) \
can't: a service that answers fine at that level but is actually broken underneath. Don't \
assume the symptom category below is complete or even correct -- it's a routing hint the \
reporter picked from a dropdown, not a diagnosis; weigh it against the free-text description, \
which is what they actually chose to say in their own words.

Service:     {service}
Symptom:     {symptom}
Reporter:    {reporter}
Description, verbatim: "{description}"

You have SSH access to that service's own host to check container status/health \
(`docker ps`, `docker inspect`), resource usage (`docker stats --no-stream`), and recent logs \
(`docker logs --tail 200`) -- that's the most direct way to confirm or rule out what was \
reported. If the symptom suggests missing/incomplete data specifically, also consider whether a \
backup/restore ran recently, or whether a recent update (check this bot's own update history if \
relevant) changed something. Hosts available:
{host_list}

Report:
1. Whether you found concrete evidence the reported problem is real, and what it actually is --
or a clear "looks fine from here" if nothing backs it up (a real possibility; the reporter may
be mistaken, or it may already be self-resolved).
2. Likely cause, if you found one.
3. A recommendation: what's worth doing next, or just continued watching.

Keep the report under 300 words -- it gets relayed into a Matrix chat message."""


_GENERIC_FINDING_PROMPT_TEMPLATE = """A finding was flagged (source: {source}) and it needs a closer look. You are \
running in read-only plan mode -- investigate and diagnose only, do not repair, restart, or \
change any configuration. Report findings and a recommendation; a human decides what to do next.

No source-specific investigation template exists for "{source}" yet -- this is a generic \
fallback, not a bug on your end, so don't assume anything about disk health, SMART data, or any \
other specific shape. Work from exactly what's in the finding below and reason about it on its \
own terms.

Subject:   {subject}
Severity:  {severity}
Summary:   {summary}

Full detail captured at alert time:
{detail_json}

Report:
1. Your best assessment of what this finding actually means and whether it looks genuine.
2. Whether it needs prompt attention or can wait.
3. Any recommendation you can make from the data available -- and separately, flag plainly that \
this source has no dedicated investigation template yet, so a human knows to consider adding one \
(see investigate_wrapper.py's investigate_finding dispatch) rather than relying on this generic \
pass every time.

Keep the report under 300 words -- it gets relayed into a Matrix chat message."""


_CODE_FIX_TRAILER = """

Finally, separately from the report above: if, and only if, you concluded the real fix here is a change to \
rbd_update_bot's OWN source code (this bot's own Python, not a live host/config action) -- e.g. a monitor \
false positive, a parsing bug, a wrong assumption in this bot's own logic -- end your report with one \
additional line in exactly this form, parsed automatically by the bot that invoked you:
CODE_FIX_NEEDED: <path/to/file.py>: <one-sentence summary of the bug and the fix>
Omit this line entirely if the real fix is a live host/config action instead (patch a package, roll back a \
tag, restart a container, etc.) -- that's not this, and most investigations won't need this line at all."""


def _build_generic_finding_prompt(finding: dict, ctx: dict) -> str:
    detail = finding.get("detail") or {}
    return _GENERIC_FINDING_PROMPT_TEMPLATE.format(
        source=finding.get("source", "unknown"),
        subject=finding.get("subject", "unknown"),
        severity=finding.get("severity", "unknown"),
        summary=finding.get("summary", "unknown"),
        detail_json=json.dumps(detail, indent=2),
    )


def _build_user_report_finding_prompt(finding: dict, ctx: dict) -> str:
    detail = finding.get("detail") or {}
    hosts = ctx.get("hosts") or []
    host_lines = [f"- {h['name']}: ssh_host={h['ssh_host']!r}, ssh_user={h['ssh_user']!r}" for h in hosts]
    host_list = "\n".join(host_lines) if host_lines else "(none provided)"
    return _USER_REPORT_FINDING_PROMPT_TEMPLATE.format(
        service=detail.get("service", finding.get("subject", "unknown")),
        symptom=detail.get("symptom", "unknown"),
        reporter=detail.get("reporter", "anonymous"),
        description=detail.get("description", "(no description provided)"),
        host_list=host_list,
    )


def _build_firewall_traffic_finding_prompt(finding: dict, ctx: dict) -> str:
    detail = finding.get("detail") or {}
    fortigate = ctx.get("fortigate") or {}
    fortigate_note = (
        _NETWORK_ISSUE_FORTIGATE_NOTE_TEMPLATE.format(
            api_host=fortigate["api_host"], token_file=fortigate["token_file"],
        )
        if fortigate.get("api_host") and fortigate.get("token_file") else ""
    )
    return _FIREWALL_TRAFFIC_FINDING_PROMPT_TEMPLATE.format(
        check_id=detail.get("check_id", finding.get("subject", "unknown")),
        status=detail.get("status", "unknown"),
        detail_json=json.dumps(detail.get("raw_detail", {}), indent=2),
        fortigate_note=fortigate_note,
    )


def _build_ap_flapping_finding_prompt(finding: dict, ctx: dict) -> str:
    detail = finding.get("detail") or {}
    roams = ctx.get("recent_roams") or []
    roam_history = (
        "\n".join(f"  {r.get('occurred_at')}: {r.get('from_ap')} -> {r.get('to_ap')}" for r in roams)
        if roams else "  (none recorded beyond the alert itself)"
    )
    omada = ctx.get("omada") or {}
    omada_note = (
        _NETWORK_ISSUE_OMADA_NOTE_TEMPLATE.format(config_file=omada["config_file"])
        if omada.get("config_file") else ""
    )
    fortigate = ctx.get("fortigate") or {}
    fortigate_note = (
        _NETWORK_ISSUE_FORTIGATE_NOTE_TEMPLATE.format(
            api_host=fortigate["api_host"], token_file=fortigate["token_file"],
        )
        if fortigate.get("api_host") and fortigate.get("token_file") else ""
    )
    return _AP_FLAPPING_FINDING_PROMPT_TEMPLATE.format(
        mac=finding.get("subject", "unknown"),
        detail=detail.get("detail", "unknown"),
        status=detail.get("status", "unknown"),
        roam_history=roam_history,
        omada_note=omada_note,
        fortigate_note=fortigate_note,
    )


def _build_wireguard_finding_prompt(finding: dict, ctx: dict) -> str:
    detail = finding.get("detail") or {}
    return _WIREGUARD_FINDING_PROMPT_TEMPLATE.format(
        pubkey=finding.get("subject", "unknown"),
        allowed_ips=detail.get("allowed_ips") or "(unknown)",
        endpoint=detail.get("endpoint") or "(none yet)",
    )


def _build_ops_health_finding_prompt(finding: dict, ctx: dict) -> str:
    detail = finding.get("detail") or {}
    return _OPS_HEALTH_FINDING_PROMPT_TEMPLATE.format(
        check_source=detail.get("source", "unknown"),
        check_id=detail.get("check_id", finding.get("subject", "unknown")),
        status=detail.get("status", "unknown"),
        detail=detail.get("detail", "unknown"),
        detail_json=json.dumps(detail, indent=2),
    )


_KUMA_MONITOR_FINDING_PROMPT_TEMPLATE = """Uptime Kuma flagged {monitor_name} as down and it needs a closer \
look. You are running in read-only plan mode -- investigate only, do not restart, repair, or change anything. \
Report findings and a recommendation; a human decides what to do next.

Monitor:  {monitor_name} ({check_id})
Status:   {status}

No restart action exists for this monitor -- either it's a bare native install with no container to restart, \
or it's outside this bot's own tracked fleet entirely. That's why this paged immediately instead of trying an \
auto-restart first; don't flag the lack of a restart action as a gap on its own, it's deliberate.

{proxmox_note}

No deeper live host access is wired into this investigation beyond what's shown above (confirmed live \
2026-11-08: this SSH key isn't accepted on the Proxmox hosts themselves, so don't attempt to SSH into a \
Proxmox node or re-run a Proxmox API call yourself -- work from the data already given).

Report:
1. Your best assessment of what likely caused this -- if the Proxmox data above shows a backup lock or a \
recent backup task whose timing lines up with the down window, lead with that rather than guessing at \
something else.
2. Whether this needs prompt attention or can wait/just needs continued watching.
3. If a Proxmox backup looks like the cause, end by asking The owner directly whether it was a manual run or \
the regular scheduled job -- phrase it as a question for him, not a fact you're telling him.

Keep the report under 300 words -- it gets relayed into a Matrix chat message."""


def _build_kuma_monitor_finding_prompt(finding: dict, ctx: dict) -> str:
    detail = finding.get("detail") or {}
    proxmox = ctx.get("proxmox_backup_context") or {}
    if proxmox:
        last_backup = proxmox.get("last_vm_backup") or {}
        proxmox_note = (
            f"Proxmox backup context for this VM (VMID {proxmox.get('vmid')} on node "
            f"{proxmox.get('node')}), pre-fetched by the bot itself (it already holds the Proxmox API "
            f"token):\n"
            f"  Currently locked for backup (at investigation time): {proxmox.get('currently_locked_for_backup')}\n"
            f"  Most recent vzdump task for this VM: {json.dumps(last_backup) if last_backup else '(none found)'}"
        )
    else:
        proxmox_note = (
            "No Proxmox backup context is available for this monitor (it isn't a services.yaml-tracked VM, "
            "or the lookup failed) -- reason about this from the status/detail above alone, don't assume a "
            "backup was involved."
        )
    return _KUMA_MONITOR_FINDING_PROMPT_TEMPLATE.format(
        monitor_name=detail.get("raw_detail", {}).get("name", finding.get("subject", "unknown")),
        check_id=finding.get("subject", "unknown"),
        status=detail.get("status", "unknown"),
        proxmox_note=proxmox_note,
    )


_SECURITY_SCAN_FINDING_PROMPT_TEMPLATE = """A fleet security scan flagged a specific CVE or open port and it \
needs a closer, single-target look -- the original fleet-wide sweep only had time for a brief pass across \
every host. You are running in read-only plan mode -- investigate only, do not patch, rebuild, restart, or \
change anything.

Finding:
  Host:         {host}
  Type:         {finding_type}
  Identifier:   {identifier}
  Severity:     {severity}
  Scan summary: {detail}

{ssh_note}

{type_specific_note}

Report:
1. What this actually is -- if the identifier starts with "pkg:" there's no real CVE id yet, so re-run \
Trivy on the exact running image/digest (not just the tag) to get the real CVE id(s), the installed/fixed \
versions, and whether a fix is even available upstream yet.
2. Whether the vulnerable code path is realistically reachable here (published ports, what the service \
actually does with that package/library, whether it's internet-facing) -- not just the CVE's abstract score.
3. Urgency: can it wait for the normal update cycle, or does it need attention sooner, and why.
4. A clear recommendation for what to actually do (wait for upstream, pull a newer tag now, restrict \
exposure in the meantime, etc).

Keep the report under 300 words -- it gets relayed into a Matrix chat message, possibly batched together \
with several others from the same scan run."""


def _build_security_scan_finding_prompt(finding: dict, ctx: dict) -> str:
    detail = finding.get("detail") or {}
    host_name = detail.get("host", "unknown")
    finding_type = detail.get("finding_type", "unknown")
    hosts = ctx.get("hosts") or []
    host_entry = next((h for h in hosts if h.get("name") == host_name), None)
    if host_entry:
        ssh_note = (
            f"You have real SSH access from this host (mgmt1) to {host_name}: "
            f"`ssh {host_entry['ssh_user']}@{host_entry['ssh_host']}`."
        )
        if host_entry.get("compose_dir"):
            ssh_note += f" Its compose file is at {host_entry['compose_dir']}."
    else:
        ssh_note = (
            f"No direct SSH host is known for \"{host_name}\" in this context -- work from the scan "
            "summary alone if you can't reach it another way."
        )

    if finding_type == "open_port":
        type_specific_note = (
            "This is an open-port finding, not a CVE -- use `ss -tlnp` (sudo if available) or check "
            "docker's published ports to identify exactly which process/container owns it, then judge "
            "whether it's a known, intentional listener (the service's own webhook/API/reverse-proxy -- "
            "including this bot's own webhook server if the host is rbd-update-bot) or genuinely unexpected."
        )
    else:
        type_specific_note = (
            "This is a CVE finding -- confirm the exact running image reference with "
            "`docker inspect --format='{{.Config.Image}}' <container>`, then run "
            "`/home/rbdroot/.local/bin/trivy image --scanners vuln --severity HIGH,CRITICAL <image-ref>` "
            "against it (locally-built images with no registry to pull from may need the save/scp "
            "workaround documented in this script's fleet-wide security-scan prompt)."
        )

    return _SECURITY_SCAN_FINDING_PROMPT_TEMPLATE.format(
        host=host_name, finding_type=finding_type,
        identifier=detail.get("identifier", finding.get("subject", "unknown")),
        severity=finding.get("severity", "unknown"),
        detail=detail.get("detail", "unknown"),
        ssh_note=ssh_note, type_specific_note=type_specific_note,
    )


_KERNEL_CVE_FINDING_PROMPT_TEMPLATE = """The fleet-wide Linux kernel CVE watch flagged a kernel group and it \
needs a closer, second look. You are running in read-only plan mode -- investigate only, do not patch, upgrade \
packages, or reboot anything. kernel_cve_watch's own loop (orchestrator.py's run_kernel_cve_watch_loop) already \
auto-patches and reboots this exact group unattended, one host at a time, the moment it mechanically confirms a \
real fix via `apt list --upgradable` -- this investigation is a second opinion alongside that pipeline, not a \
substitute for it.

Kernel group:   {distro}, running {kernel_version}
CVE:            {cve_id}
Severity:       {severity}
Fixed version:  {fixed_version}
Source:         {source_url}
Summary:        {summary}
Affected hosts ({host_count}): {host_list}

{status_note}

FIRST, on EACH affected host below, directly confirm real patch status rather than inferring it -- the \
research pass behind this advisory only ever saw a bare `uname -r` string, so it cannot by itself tell a host \
that's already patched apart from one that isn't (a real false alarm already caught live this way once). Run:
  `uname -r` (what's actually loaded and running right now, not just installed)
  `dpkg-query -W -f='${{Version}}' linux-image-$(uname -r)` (the real installed package version behind that \
exact running kernel)
then compare that version against the Fixed version above yourself: `dpkg --compare-versions <installed> ge \
<fixed> && echo ALREADY PATCHED`. If every affected host is already patched, say that plainly and prominently \
as your headline finding -- this alert may simply be stale (the fleet watch itself auto-resolves this case on \
its own next poll cycle once it can see it too, but your report is the faster path to a human knowing now).

Only once that's settled: this advisory came from this bot's own prior two-call web-research pass against the \
distro's official security tracker -- no need to redo that search, just sanity-check it. If the source URL \
above is reachable, `curl -sL` it and confirm it really says what the summary claims (what counts as \
"critical" there is sometimes a CVSS score for a worst-case configuration this fleet doesn't match). For any \
host NOT already patched, judge real exposure -- is the vulnerable subsystem the summary describes \
realistically reachable here (an unauthenticated network-stack bug matters far more on an internet-facing host \
like wg-vpn than an internal-only one), and does `apt list --upgradable 2>/dev/null | grep -i linux-image` \
show a fix closer than the advisory suggests (a distro's security tracker can lag a real backported fix \
already available via apt).

Hosts:
{host_list_detail}

Report:
1. Already-patched status per host, checked directly as above -- lead with this.
2. Whether the advisory itself holds up, or looks overstated/understated for what this fleet actually runs \
and exposes, for whichever hosts aren't already patched.
3. Real exposure for those hosts specifically -- not just the CVE's abstract severity.
4. Whether to keep waiting for the unattended pipeline, or anything worth doing sooner than it will.

Keep the report under 300 words -- it gets relayed into a Matrix chat message."""


def _build_kernel_cve_finding_prompt(finding: dict, ctx: dict) -> str:
    detail = finding.get("detail") or {}
    subject = finding.get("subject", "unknown")
    try:
        _, distro, kernel_version = subject.split(":", 2)
    except ValueError:
        distro, kernel_version = subject, "unknown"

    fleet_hosts = {h["name"]: h for h in (ctx.get("hosts") or [])}
    affected = detail.get("hosts") or []

    def _ssh_line(name: str) -> str:
        h = fleet_hosts.get(name)
        if h:
            return f"- {name}: `ssh {h['ssh_user']}@{h['ssh_host']}`"
        return f"- {name}: (no direct SSH host known for this name in this context)"

    if affected:
        host_count = str(len(affected))
        host_list = ", ".join(affected)
        host_list_detail = "\n".join(_ssh_line(name) for name in affected)
        status_note = (
            "No automated action has been taken for this yet -- kernel_cve_watch is still watching for a "
            "released fix (or, if one's already confirmed, it's about to attempt its own mechanical "
            "apt-confirmation and unattended one-host-at-a-time patch+reboot on an upcoming cycle)."
        )
    else:
        host_count = "unknown"
        host_list = "(not recorded on this specific finding -- see the bot's recent Matrix history for the real host list)"
        host_list_detail = "(no host list recorded on this finding) Full fleet, in case one needs checking directly:\n" + (
            "\n".join(_ssh_line(name) for name in fleet_hosts) or "(none configured)"
        )
        status_note = (
            "This specific finding marks an unattended auto-patch run already STARTING for this kernel "
            "group, not an open decision -- check the bot's recent Matrix history/!findings for whether that "
            "patch+reboot cycle already finished cleanly before treating this as still-open risk."
        )

    return _KERNEL_CVE_FINDING_PROMPT_TEMPLATE.format(
        distro=distro, kernel_version=kernel_version,
        cve_id=detail.get("cve_id") or "(not recorded on this finding)",
        severity=finding.get("severity", "unknown"),
        fixed_version=detail.get("fixed_version") or "(not yet released)",
        source_url=detail.get("source_url") or "(no official source recorded)",
        summary=finding.get("summary", "unknown"),
        host_count=host_count, host_list=host_list, host_list_detail=host_list_detail,
        status_note=status_note,
    )


_PASS_BOT_FINDING_PROMPT_TEMPLATE = """pass-bot (a separate bot on this same fleet, running as a plain systemd \
service on its own LXC, no container to restart) reported one of its own health checks failing via its \
heartbeat to this bot, and it needs a closer look. You are running in read-only plan mode -- investigate \
only, do not restart the service, change any config, or touch any mail rule.

Check:    {check_id}
Detail:   {detail}

pass-bot's heartbeat deliberately strips error detail down to the exception class name only (never the \
real message, which can carry URLs or event titles) -- so "{detail}" above is likely NOT the whole story. \
SSH directly into pass-bot itself to get the real picture:
  {ssh_line}
then `sudo journalctl -u rbd-pass-bot.service --since "-2 hours" --no-pager | tail -100` (or further back if \
this finding is older) for the actual exception message/stack trace around when this started.

{outage_note}

Report:
1. The real error, from pass-bot's own logs -- don't stop at the bare exception class name from the heartbeat.
2. Your best assessment of whether this is a transient/external problem (Graph throttling, an upstream outage, \
a brief network blip) or a genuine local bug/config problem in pass-bot itself.
3. Whether it needs prompt attention or can wait/just needs continued watching.
4. Any recommendation The owner could act on.

Keep the report under 300 words -- it gets relayed into a Matrix chat message."""

_PASS_BOT_OUTAGE_NOTE_TEMPLATE = """This check ({check_id}) is Graph-call-shaped, so before this finding was \
created the bot already ran its own grounded web-search check against Microsoft's real status pages \
(o365_outage_watch.py) -- no need to redo that search, just sanity-check it against what pass-bot's logs \
actually show:
  has_active_outage: {has_active_outage}
  status:            {status}
  affected_workloads: {affected_workloads}
  source:            {source_url}
  summary:           {summary}
If has_active_outage is true, pass-bot's own logs should show errors consistent with that (timeouts, 503s, \
429s) rather than anything pointing at a local cause (expired token, bad credentials, a code bug) -- if they \
don't line up, say so plainly rather than taking the outage advisory on faith. If has_active_outage is \
false, this was promoted to critical specifically because no outage was found -- focus the investigation on \
finding pass-bot's own real cause."""

_PASS_BOT_NO_OUTAGE_CHECK_NOTE = """This check isn't Graph-call-shaped (or the outage-watch feature isn't \
enabled yet), so no Microsoft-status research was done for this finding -- reason about it purely from \
pass-bot's own logs."""


def _build_pass_bot_finding_prompt(finding: dict, ctx: dict) -> str:
    detail = finding.get("detail") or {}
    check_id = finding.get("subject", "unknown")
    fleet_hosts = {h["name"]: h for h in (ctx.get("hosts") or [])}
    h = fleet_hosts.get("pass-bot")
    ssh_line = f"`ssh {h['ssh_user']}@{h['ssh_host']}`" if h else "(no direct SSH host known for pass-bot in this context)"

    advisory = detail.get("o365_outage_advisory")
    if advisory:
        outage_note = _PASS_BOT_OUTAGE_NOTE_TEMPLATE.format(
            check_id=check_id,
            has_active_outage=advisory.get("has_active_outage"),
            status=advisory.get("status", "unknown"),
            affected_workloads=advisory.get("affected_workloads") or "(none named)",
            source_url=advisory.get("source_url") or "(no source recorded)",
            summary=advisory.get("summary", "unknown"),
        )
    else:
        outage_note = _PASS_BOT_NO_OUTAGE_CHECK_NOTE

    return _PASS_BOT_FINDING_PROMPT_TEMPLATE.format(
        check_id=check_id,
        detail=detail.get("detail") or finding.get("summary", "unknown"),
        ssh_line=ssh_line,
        outage_note=outage_note,
    )


_CONFIG_DRIFT_FINDING_PROMPT_TEMPLATE = """The config-drift archive detected a real change to {service}'s deployed \
config that doesn't match any recent bot-triggered update for that service -- it needs a closer \
look. You are running in read-only plan mode -- investigate only, do not revert the change, \
edit the file, or restart/redeploy anything.

Service:      {service}
File:         {file}
Commit:       {commit_hash}
Archived at:  {archived_at}

The real diff that was committed:
{diff}

You have real, working SSH access from this host (mgmt1) directly to {service}'s host: \
`ssh {ssh_target}`. Use it to investigate -- check that host's own auth log (`sudo journalctl \
-u ssh` or `/var/log/auth.log`, whichever exists) for logins around the time this change \
plausibly happened, check `sudo -l`/sudoers history or shell history if relevant, and look at \
the file's own real mtime/ownership on disk for any further corroborating detail beyond what's \
in the diff above.

Report:
1. Your best assessment of what actually happened and who/what likely caused it (a legitimate \
manual edit, a bot mechanism this check doesn't yet know about, or something that looks \
unexplained/concerning).
2. Whether this looks like something The owner did himself and simply didn't mention, or \
something worth him looking into more closely.
3. Any other detail worth knowing before he decides whether this needs any action at all."""


def _build_config_drift_finding_prompt(finding: dict, ctx: dict) -> str:
    detail = finding.get("detail") or {}
    service = detail.get("service") or finding.get("subject", "unknown")
    ssh_target = (
        _CONFIG_ARCHIVE_TARGETS.get(service, (None, None))[0]
        or {"immich": "rbd-immich"}.get(service)
        or "(no direct SSH host known for this service)"
    )
    return _CONFIG_DRIFT_FINDING_PROMPT_TEMPLATE.format(
        service=service,
        file=detail.get("file", "unknown"),
        commit_hash=detail.get("commit_hash", "unknown"),
        archived_at=detail.get("archived_at", "unknown"),
        diff=detail.get("diff") or "(no diff text captured)",
        ssh_target=ssh_target,
    )


_NETWORK_ISSUE_PROMPT_TEMPLATE = """A human reported a network/connectivity problem and it needs real-time triage. You \
are running in read-only plan mode -- investigate and diagnose only, do not attempt to \
change any network configuration, WiFi settings, or service config. Report findings and a \
recommendation; a human decides what to do next (adjusting AP/WiFi settings is deliberately \
not something this investigation does itself).

Reported problem, verbatim: "{description}"

Recent AP roaming history (last 24h, most recent first -- a client bouncing between APs \
repeatedly is a real, already-known issue class here; empty means no roams recorded in \
that window):
{roam_history}

{omada_note}
{fortigate_note}
If the report names or implies a specific service (e.g. a game server, TeamSpeak, a media \
server), you have SSH access to check that service's own host directly for container \
resource usage (`docker stats --no-stream`) and recent logs, and whether anything else is \
currently consuming significant bandwidth (a Kopia backup snapshot, a large transfer) -- \
this project's own upload bandwidth is capped around 40Mbps, so a concurrent backup job is a \
real, plausible cause of a laggy connection, not just a hypothetical to mention. Hosts \
available:
{host_list}

Report:
1. Your best diagnosis of what's actually happening, and whether it's likely on this \
network/homelab side or something external (ISP, the remote service itself).
2. Anything concrete you found (an overloaded AP, a client stuck flapping, high channel \
utilization, a backup running, a host under load) -- or a clear "nothing unusual found" if \
that's genuinely the case.
3. A recommendation: what's worth trying, checking further, or just monitoring.

Keep the report under 300 words -- it gets relayed into a Matrix chat message."""


def _build_network_issue_prompt(ctx: dict) -> str:
    description = ctx.get("description", "(no description provided)")

    roams = ctx.get("recent_roams") or []
    if roams:
        roam_history = "\n".join(
            f"  {r.get('occurred_at')}: {r.get('mac')} {r.get('from_ap')} -> {r.get('to_ap')}"
            for r in roams
        )
    else:
        roam_history = "  (none recorded in the last 24h)"

    omada = ctx.get("omada") or {}
    omada_note = (
        _NETWORK_ISSUE_OMADA_NOTE_TEMPLATE.format(config_file=omada["config_file"])
        if omada.get("config_file") else ""
    )
    fortigate = ctx.get("fortigate") or {}
    fortigate_note = (
        _NETWORK_ISSUE_FORTIGATE_NOTE_TEMPLATE.format(
            api_host=fortigate["api_host"], token_file=fortigate["token_file"],
        )
        if fortigate.get("api_host") and fortigate.get("token_file") else ""
    )

    hosts = ctx.get("hosts") or []
    host_lines = [f"- {h['name']}: ssh_host={h['ssh_host']!r}, ssh_user={h['ssh_user']!r}" for h in hosts]
    host_list = "\n".join(host_lines) if host_lines else "(none provided)"

    return _NETWORK_ISSUE_PROMPT_TEMPLATE.format(
        description=description,
        roam_history=roam_history,
        omada_note=omada_note,
        fortigate_note=fortigate_note,
        host_list=host_list,
    )


_CLUSTER_RESOURCES_PROMPT_TEMPLATE = """A Proxmox cluster resource review was requested. You are running in \
read-only plan mode -- investigate and report only. Do NOT attempt to migrate a VM, change a \
resource allocation (memory/CPU/disk), or alter any Proxmox configuration -- this investigation \
always ends in a recommendation for a human to act on, never an automated change.

Requested focus, verbatim (empty means "standard review -- just look for anything tight or \
worth rebalancing"): "{description}"

Per-node resource status, pulled fresh from the Proxmox API just before this investigation \
started (memory figures in bytes; cpu_fraction is instantaneous, a snapshot at poll time, not \
a sustained average -- a one-off spike from a scan or backup job happening to run right now is \
a real possibility, not necessarily a sign of genuine pressure):
{node_summary}

Every VM/LXC in the cluster, with its current node, status, and resource usage:
{vm_summary}

Hosts this investigation has direct SSH access to, if digging into a specific service's actual \
behavior (not just its reported numbers) would help:
{host_list}

Report:
1. Which node(s), if any, are genuinely under resource pressure right now (not just a momentary \
blip) -- call out memory specifically, since this cluster has a real documented history of \
running close to its memory ceiling.
2. Which specific VM(s)/LXC(s) are the heaviest consumers on any tight node, and whether their \
usage looks normal for what that service actually does or looks like something worth digging \
into further.
3. If anything looks tight: a concrete rebalancing recommendation (e.g. "moving VM X to node Y \
would relieve Z"), clearly labeled as a recommendation for a human to review and carry out --
never something this investigation does itself.
4. If nothing looks tight: say so plainly, don't manufacture a finding.

Keep the report under 300 words -- it gets relayed into a Matrix chat message."""


def _build_cluster_resources_prompt(ctx: dict) -> str:
    description = ctx.get("description") or ""

    node_resources = ctx.get("node_resources") or []
    node_lines = []
    for n in node_resources:
        if n.get("error"):
            node_lines.append(f"  {n.get('node')}: ERROR fetching status -- {n['error']}")
            continue
        mem = n.get("memory") or {}
        mem_total, mem_used = mem.get("total"), mem.get("used")
        mem_pct = f"{mem_used / mem_total * 100:.1f}%" if mem_total else "?"
        cpu_frac = n.get("cpu_fraction")
        cpu_pct = f"{cpu_frac * 100:.1f}%" if isinstance(cpu_frac, (int, float)) else "?"
        loadavg = n.get("loadavg") or []
        node_lines.append(
            f"  {n.get('node')}: memory {mem_pct} ({mem_used}/{mem_total} bytes), "
            f"cpu {cpu_pct}, loadavg {', '.join(loadavg)}, uptime {n.get('uptime')}s"
        )
    node_summary = "\n".join(node_lines) if node_lines else "  (no node data available)"

    vm_resources = ctx.get("vm_resources") or []
    vm_lines = []
    for vm in vm_resources:
        mem_used, mem_total = vm.get("mem"), vm.get("maxmem")
        mem_pct = f"{mem_used / mem_total * 100:.1f}%" if mem_total else "?"
        cpu_frac = vm.get("cpu")
        cpu_pct = f"{cpu_frac * 100:.1f}%" if isinstance(cpu_frac, (int, float)) else "?"
        vm_lines.append(
            f"  [{vm.get('vmid')}] {vm.get('name')} ({vm.get('type')}) on {vm.get('node')}, "
            f"status={vm.get('status')}: mem {mem_pct} ({mem_used}/{mem_total}), cpu {cpu_pct}"
        )
    vm_summary = "\n".join(vm_lines) if vm_lines else "  (no VM data available)"

    hosts = ctx.get("hosts") or []
    host_lines = [f"- {h['name']}: ssh_host={h['ssh_host']!r}, ssh_user={h['ssh_user']!r}" for h in hosts]
    host_list = "\n".join(host_lines) if host_lines else "(none provided)"

    return _CLUSTER_RESOURCES_PROMPT_TEMPLATE.format(
        description=description,
        node_summary=node_summary,
        vm_summary=vm_summary,
        host_list=host_list,
    )


_KNOWN_OUI_PREFIXES = {
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Trading",
}


def _is_randomized_mac(mac: str) -> bool:
    try:
        first_octet = int(mac.replace("-", ":").split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return bool(first_octet & 0x02)


def _guess_vendor(mac: str, omada_vendor: str | None = None) -> str | None:
    if omada_vendor and omada_vendor.lower() != "unknown":
        return omada_vendor
    if _is_randomized_mac(mac):
        return "randomized/private address (not a real hardware ID)"
    prefix = mac.upper().replace("-", ":")[:8]
    return _KNOWN_OUI_PREFIXES.get(prefix)


def _omada_location(c: dict) -> str | None:
    if c.get("wireless"):
        ap = c.get("apName")
        ssid = c.get("ssid")
        if ap and ssid:
            return f"{ap} (SSID: {ssid})"
        return ap or ssid
    switch = c.get("switchName")
    port = c.get("port")
    if switch and port is not None:
        return f"{switch} / port {port}"
    return switch or (str(port) if port is not None else None)


def _collect_omada(config_file: str) -> tuple[list[dict], str | None]:
    try:
        with open(config_file) as f:
            content = f.read()
        cfg = dict(re.findall(r"([A-Z_]+)=(\S+)", content))
        base = cfg["OMADA_BASE_URL"].rstrip("/")
        omadac_id = cfg["OMADA_OMADAC_ID"]

        token_resp = requests.post(
            f"{base}/openapi/authorize/token?grant_type=client_credentials",
            json={
                "omadacId": omadac_id,
                "client_id": cfg["OMADA_CLIENT_ID"],
                "client_secret": cfg["OMADA_CLIENT_SECRET"],
            },
            timeout=15,
        )
        token_resp.raise_for_status()
        token = token_resp.json().get("result", {}).get("accessToken")
        if not token:
            return [], "omada: token request returned no accessToken"

        headers = {"Authorization": f"AccessToken={token}"}
        sites_resp = requests.get(
            f"{base}/openapi/v1/{omadac_id}/sites?page=1&pageSize=100", headers=headers, timeout=15,
        )
        sites_resp.raise_for_status()
        sites_result = sites_resp.json().get("result", [])
        sites = sites_result.get("data", []) if isinstance(sites_result, dict) else sites_result

        devices = []
        for site in sites:
            site_id = site.get("siteId") or site.get("id")
            if not site_id:
                continue
            clients_resp = requests.get(
                f"{base}/openapi/v1/{omadac_id}/sites/{site_id}/clients?page=1&pageSize=100",
                headers=headers, timeout=15,
            )
            if clients_resp.status_code != 200:
                continue
            clients_result = clients_resp.json().get("result", [])
            clients = clients_result.get("data", []) if isinstance(clients_result, dict) else clients_result
            for c in clients:
                mac = c.get("mac") or c.get("macAddress")
                if not mac:
                    continue
                devices.append({
                    "mac": mac,
                    "ip": c.get("ip") or c.get("wanIp"),
                    "hostname": c.get("name") or c.get("hostName") or c.get("hostname"),
                    "vlan": c.get("vid") or c.get("networkName") or c.get("vlanId"),
                    "port": _omada_location(c),
                    "vendor": _guess_vendor(mac, c.get("vendor")),
                    "source": "omada",
                    "raw": c,
                })
        return devices, None
    except Exception as exc:
        return [], f"omada: {exc}"


def _collect_wifi_rf(config_file: str, watched_macs: list[str]) -> tuple[dict, list[str]]:
    radios: list[dict] = []
    neighbors: list[dict] = []
    watched_clients: list[dict] = []
    errors: list[str] = []
    watched = {m.lower().replace("-", ":") for m in watched_macs}

    try:
        with open(config_file) as f:
            content = f.read()
        cfg = dict(re.findall(r"([A-Z_]+)=(\S+)", content))
        base = cfg["OMADA_BASE_URL"].rstrip("/")
        omadac_id = cfg["OMADA_OMADAC_ID"]

        token_resp = requests.post(
            f"{base}/openapi/authorize/token?grant_type=client_credentials",
            json={
                "omadacId": omadac_id,
                "client_id": cfg["OMADA_CLIENT_ID"],
                "client_secret": cfg["OMADA_CLIENT_SECRET"],
            },
            timeout=15,
        )
        token_resp.raise_for_status()
        token = token_resp.json().get("result", {}).get("accessToken")
        if not token:
            return {}, ["wifi_rf: token request returned no accessToken"]
        headers = {"Authorization": f"AccessToken={token}"}

        sites_resp = requests.get(
            f"{base}/openapi/v1/{omadac_id}/sites?page=1&pageSize=100", headers=headers, timeout=15,
        )
        sites_resp.raise_for_status()
        sites_result = sites_resp.json().get("result", [])
        sites = sites_result.get("data", []) if isinstance(sites_result, dict) else sites_result

        for site in sites:
            site_id = site.get("siteId") or site.get("id")
            if not site_id:
                continue

            aps: list[dict] = []
            try:
                interference_resp = requests.get(
                    f"{base}/openapi/v1/{omadac_id}/sites/{site_id}/dashboard/top-interference",
                    headers=headers, timeout=15,
                )
                interference_resp.raise_for_status()
                interference_result = interference_resp.json().get("result", {})
                seen_macs: set[str] = set()
                for entry in interference_result.get("apInterference2g", []) + interference_result.get("apInterference5g", []):
                    mac = entry.get("mac")
                    if mac and mac not in seen_macs:
                        seen_macs.add(mac)
                        aps.append({"mac": mac, "name": entry.get("name")})
            except Exception as exc:
                errors.append(f"wifi_rf: dashboard/top-interference (AP discovery): {exc}")

            for ap in aps:
                ap_mac = ap["mac"]
                ap_name = ap["name"]
                try:
                    radios_resp = requests.get(
                        f"{base}/openapi/v1/{omadac_id}/sites/{site_id}/aps/{ap_mac}/radios",
                        headers=headers, timeout=15,
                    )
                    radios_resp.raise_for_status()
                    radio_result = radios_resp.json().get("result", {}) or {}
                except Exception as exc:
                    errors.append(f"wifi_rf: radios for {ap_name or ap_mac}: {exc}")
                    continue

                try:
                    config_resp = requests.get(
                        f"{base}/openapi/v1/{omadac_id}/sites/{site_id}/aps/{ap_mac}/radio-config",
                        headers=headers, timeout=15,
                    )
                    config_resp.raise_for_status()
                    config_result = config_resp.json().get("result", {}) or {}
                except Exception as exc:
                    errors.append(f"wifi_rf: radio-config for {ap_name or ap_mac}: {exc}")
                    config_result = {}

                for band, wp_key, traffic_key, cfg_key in (
                    ("2g", "wp2g", "radioTraffic2g", "radioSetting2g"),
                    ("5g", "wp5g", "radioTraffic5g", "radioSetting5g"),
                ):
                    wp = radio_result.get(wp_key)
                    if wp is None:
                        continue
                    radios.append({
                        "_ap_name": ap_name,
                        "_ap_mac": ap_mac,
                        "_band": band,
                        **wp,
                        "traffic": radio_result.get(traffic_key) or {},
                        "config": config_result.get(cfg_key) or {},
                    })

            try:
                rogue_resp = requests.get(
                    f"{base}/openapi/v1/{omadac_id}/sites/{site_id}/insight/rogueaps?page=1&pageSize=200",
                    headers=headers, timeout=15,
                )
                rogue_resp.raise_for_status()
                rogue_result = rogue_resp.json().get("result", [])
                neighbors = rogue_result.get("data", []) if isinstance(rogue_result, dict) else (rogue_result or [])
            except Exception as exc:
                errors.append(f"wifi_rf: insight/rogueaps: {exc}")

            if watched:
                try:
                    clients_resp = requests.get(
                        f"{base}/openapi/v1/{omadac_id}/sites/{site_id}/clients?page=1&pageSize=100",
                        headers=headers, timeout=15,
                    )
                    clients_resp.raise_for_status()
                    clients_result = clients_resp.json().get("result", [])
                    clients = clients_result.get("data", []) if isinstance(clients_result, dict) else clients_result
                    for c in clients:
                        mac = (c.get("mac") or "").lower().replace("-", ":")
                        if mac in watched:
                            watched_clients.append(c)
                except Exception as exc:
                    errors.append(f"wifi_rf: clients (watched): {exc}")

    except Exception as exc:
        errors.append(f"wifi_rf: {exc}")

    return (
        {"radios": radios, "neighbors": neighbors, "watched_clients": watched_clients},
        errors,
    )


def _run_wifi_rf_collect(ctx: dict) -> int:
    omada = ctx.get("omada") or {}
    if not omada.get("config_file"):
        print(json.dumps({"radios": [], "neighbors": [], "watched_clients": [], "errors": ["no omada config provided"]}))
        return 0
    data, errors = _collect_wifi_rf(omada["config_file"], ctx.get("watched_macs") or [])
    print(json.dumps({**data, "errors": errors}))
    return 0


def _collect_fortigate_dhcp(api_host: str, token_file: str) -> tuple[list[dict], str | None]:
    try:
        with open(token_file) as f:
            token = f.read().strip()
        resp = requests.get(
            f"{api_host}/api/v2/monitor/system/dhcp",
            headers={"Authorization": f"Bearer {token}"},
            verify=False, timeout=15,
        )
        resp.raise_for_status()
        results = resp.json().get("results", [])
        devices = []
        for d in results:
            mac = d.get("mac")
            if not mac:
                continue
            devices.append({
                "mac": mac,
                "ip": d.get("ip"),
                "hostname": d.get("hostname"),
                "vlan": d.get("interface"),
                "port": None,
                "vendor": _guess_vendor(mac),
                "source": "fortigate_dhcp",
                "raw": d,
            })
        return devices, None
    except Exception as exc:
        return [], f"fortigate: {exc}"


def _collect_firewall_traffic(api_host: str, token_file: str) -> tuple[dict, str | None]:
    try:
        with open(token_file) as f:
            token = f.read().strip()
        headers = {"Authorization": f"Bearer {token}"}

        policy_resp = requests.get(
            f"{api_host}/api/v2/cmdb/firewall/policy",
            headers=headers, verify=False, timeout=15,
        )
        policy_resp.raise_for_status()
        policies = policy_resp.json().get("results", [])

        exposed_ids: dict[int, dict] = {}
        blocklist_ids: dict[int, list[str]] = {}
        iot_egress_ids: dict[int, list[str]] = {}
        for p in policies:
            if p.get("status") != "enable":
                continue
            srcintf = [i.get("name") for i in p.get("srcintf", [])]
            srcaddr = [a.get("name") for a in p.get("srcaddr", [])]
            dstaddr = [a.get("name") for a in p.get("dstaddr", [])]
            dstintf = [i.get("name") for i in p.get("dstintf", [])]
            if p.get("action") == "accept" and "wan1" in srcintf:
                exposed_ids[p["policyid"]] = {"open_to_all": "all" in srcaddr, "dest_names": dstaddr}
            elif p.get("action") == "deny" and "BLOCKLIST" in srcaddr:
                blocklist_ids[p["policyid"]] = dstaddr
            elif p.get("action") == "accept" and "IoT" in srcintf and "wan1" in dstintf:
                iot_egress_ids[p["policyid"]] = dstaddr

        counters_resp = requests.get(
            f"{api_host}/api/v2/monitor/firewall/policy",
            headers=headers, verify=False, timeout=15,
        )
        counters_resp.raise_for_status()
        counters_by_id = {c["policyid"]: c for c in counters_resp.json().get("results", [])}

        sessions_resp = requests.get(
            f"{api_host}/api/v2/monitor/firewall/sessions",
            headers=headers, verify=False, timeout=20,
            params={"ip_version": "ipboth", "start": 0, "count": 1000, "summary": "true", "vdom": "root"},
        )
        sessions_resp.raise_for_status()
        sessions = sessions_resp.json().get("results", {}).get("details", [])

        exposed = []
        for policyid, meta in exposed_ids.items():
            pol_sessions = [s for s in sessions if s.get("policyid") == policyid]
            distinct_ips = sorted({s.get("saddr") for s in pol_sessions if s.get("saddr")})
            non_us = [
                {"saddr": s.get("saddr"), "country": s.get("country"), "dport": s.get("dport")}
                for s in pol_sessions
                if meta["open_to_all"] and s.get("country") not in (None, "United States", "Reserved")
            ]
            session_ports: dict[int, int] = {}
            for s in pol_sessions:
                dport = s.get("dport")
                if dport is not None:
                    session_ports[dport] = session_ports.get(dport, 0) + 1
            session_details = [
                {
                    "dport": s.get("dport"), "duration": s.get("duration"),
                    "sentbyte": s.get("sentbyte"), "rcvdbyte": s.get("rcvdbyte"),
                    "saddr": s.get("saddr"),
                }
                for s in pol_sessions
            ]
            counters = counters_by_id.get(policyid, {})
            exposed.append({
                "policyid": policyid,
                "open_to_all": meta["open_to_all"],
                "dest_names": meta["dest_names"],
                "session_ports": session_ports,
                "session_details": session_details,
                "bytes": counters.get("bytes"),
                "packets": counters.get("packets"),
                "distinct_ip_count": len(distinct_ips),
                "sample_ips": distinct_ips[:10],
                "non_us_sessions": non_us,
            })

        blocklist = []
        for policyid, dest_names in blocklist_ids.items():
            counters = counters_by_id.get(policyid, {})
            blocklist.append({
                "policyid": policyid,
                "dest_names": dest_names,
                "bytes": counters.get("bytes"),
                "packets": counters.get("packets"),
            })

        iot_egress = []
        for policyid, dest_names in iot_egress_ids.items():
            pol_sessions = [s for s in sessions if s.get("policyid") == policyid]
            distinct_dst = sorted({s.get("daddr") for s in pol_sessions if s.get("daddr")})
            distinct_src = sorted({s.get("saddr") for s in pol_sessions if s.get("saddr")})
            counters = counters_by_id.get(policyid, {})
            iot_egress.append({
                "policyid": policyid,
                "dest_names": dest_names,
                "bytes": counters.get("bytes"),
                "packets": counters.get("packets"),
                "distinct_dest_count": len(distinct_dst),
                "sample_dests": distinct_dst[:10],
                "distinct_device_count": len(distinct_src),
            })

        return {"exposed": exposed, "blocklist": blocklist, "iot_egress": iot_egress}, None
    except Exception as exc:
        return {"exposed": [], "blocklist": [], "iot_egress": []}, f"firewall_traffic: {exc}"


def _dsm_login(base: str, cfg: dict, session_name: str) -> tuple[str | None, str | None]:
    login_resp = requests.get(
        f"{base}/webapi/auth.cgi",
        params={
            "api": "SYNO.API.Auth", "version": "6", "method": "login",
            "account": cfg["DSM_USERNAME"], "passwd": cfg["DSM_PASSWORD"],
            "session": session_name, "format": "sid",
        },
        verify=False, timeout=15,
    )
    login_resp.raise_for_status()
    login_body = login_resp.json()
    if not login_body.get("success"):
        return None, f"login failed: {login_body.get('error')}"
    return login_body["data"]["sid"], None


def _collect_synology(config_file: str) -> tuple[list[dict], str | None]:
    try:
        with open(config_file) as f:
            content = f.read()
        cfg = dict(re.findall(r"([A-Z_]+)=(\S+)", content))
        base = cfg["DSM_BASE_URL"].rstrip("/")

        sid, err = _dsm_login(base, cfg, "DiskHealthMonitor")
        if err:
            return [], f"synology: {err}"

        storage_resp = requests.get(
            f"{base}/webapi/entry.cgi",
            params={
                "api": "SYNO.Storage.CGI.Storage", "version": "1",
                "method": "load_info", "_sid": sid,
            },
            verify=False, timeout=15,
        )
        storage_resp.raise_for_status()
        storage_body = storage_resp.json()
        if not storage_body.get("success"):
            return [], f"synology: storage query failed: {storage_body.get('error')}"
        data = storage_body.get("data", {})

        disks = []
        for d in data.get("disks", []):
            disks.append({
                "disk_id": f"synology:{d.get('id')}",
                "source": "synology_disk",
                "model": d.get("model"),
                "health": d.get("smart_status") or d.get("status"),
                "wearout": None,
                "raw": d,
            })
        for v in data.get("volumes", []):
            disks.append({
                "disk_id": f"synology_volume:{v.get('id')}",
                "source": "synology_volume",
                "model": None,
                "health": v.get("status"),
                "wearout": None,
                "raw": v,
            })
        return disks, None
    except Exception as exc:
        return [], f"synology: {exc}"


def _collect_hyperbackup(config_file: str) -> tuple[list[dict], str | None]:
    try:
        with open(config_file) as f:
            content = f.read()
        cfg = dict(re.findall(r"([A-Z_]+)=(\S+)", content))
        base = cfg["DSM_BASE_URL"].rstrip("/")

        sid, err = _dsm_login(base, cfg, "HyperBackupMonitor")
        if err:
            return [], f"synology hyperbackup: {err}"

        list_resp = requests.get(
            f"{base}/webapi/entry.cgi",
            params={"api": "SYNO.Backup.Task", "version": "1", "method": "list", "_sid": sid},
            verify=False, timeout=15,
        )
        list_resp.raise_for_status()
        list_body = list_resp.json()
        if not list_body.get("success"):
            return [], f"synology hyperbackup: task list failed: {list_body.get('error')}"

        jobs = []
        for task in list_body.get("data", {}).get("task_list", []):
            task_id = task.get("task_id")
            status_resp = requests.get(
                f"{base}/webapi/entry.cgi",
                params={
                    "api": "SYNO.Backup.Task", "version": "1", "method": "status",
                    "blOnline": "false",
                    "additional": json.dumps([
                        "last_bkp_time", "next_bkp_time", "last_bkp_result",
                        "is_modified", "last_bkp_progress",
                    ]),
                    "task_id": task_id, "_sid": sid,
                },
                verify=False, timeout=15,
            )
            status_resp.raise_for_status()
            status_body = status_resp.json()
            if not status_body.get("success"):
                jobs.append({
                    "backup_id": f"synology_hyperbackup:{task_id}",
                    "name": task.get("name"),
                    "status": None,
                    "last_end_time": None,
                    "raw": {"task": task, "status_error": status_body.get("error")},
                })
                continue
            status_data = status_body.get("data", {})
            jobs.append({
                "backup_id": f"synology_hyperbackup:{task_id}",
                "name": task.get("name"),
                "status": status_data.get("last_bkp_result"),
                "last_end_time": status_data.get("last_bkp_end_time"),
                "raw": status_data,
            })
        return jobs, None
    except Exception as exc:
        return [], f"synology hyperbackup: {exc}"


def _collect_dsm_system(config_file: str) -> tuple[list[dict], str | None]:
    try:
        with open(config_file) as f:
            content = f.read()
        cfg = dict(re.findall(r"([A-Z_]+)=(\S+)", content))
        base = cfg["DSM_BASE_URL"].rstrip("/")

        sid, err = _dsm_login(base, cfg, "DsmSystemMonitor")
        if err:
            return [], f"synology dsm: {err}"

        checks: list[dict] = []

        info_resp = requests.get(
            f"{base}/webapi/entry.cgi",
            params={"api": "SYNO.Core.System", "version": "3", "method": "info", "_sid": sid},
            verify=False, timeout=15,
        )
        info_resp.raise_for_status()
        info_body = info_resp.json()
        current_version = info_body.get("data", {}).get("firmware_ver") if info_body.get("success") else None

        upgrade_resp = requests.get(
            f"{base}/webapi/entry.cgi",
            params={"api": "SYNO.Core.Upgrade.Server", "version": "4", "method": "check", "_sid": sid},
            verify=False, timeout=15,
        )
        upgrade_resp.raise_for_status()
        upgrade_body = upgrade_resp.json()
        if not upgrade_body.get("success"):
            return checks, f"synology dsm: update check failed: {upgrade_body.get('error')}"
        update = upgrade_body.get("data", {}).get("update", {})
        available = bool(update.get("available"))
        checks.append({
            "check_id": "dsm:update", "source": "dsm_system",
            "status": "update available" if available else "up to date",
            "detail": (
                f"current: {current_version}; available: {update.get('version')} "
                f"(reboot: {update.get('reboot')})" if available
                else f"current: {current_version}, no update available"
            ),
            "is_bad": available,
        })

        storage_resp = requests.get(
            f"{base}/webapi/entry.cgi",
            params={"api": "SYNO.Storage.CGI.Storage", "version": "1", "method": "load_info", "_sid": sid},
            verify=False, timeout=15,
        )
        storage_resp.raise_for_status()
        storage_body = storage_resp.json()
        if not storage_body.get("success"):
            return checks, f"synology dsm: storage query failed: {storage_body.get('error')}"
        for p in storage_body.get("data", {}).get("storagePools", []):
            is_scheduled = bool(p.get("is_scheduled"))
            last_done = p.get("last_done_time") or 0
            next_sched = p.get("next_schedule_time") or 0
            last_done_str = (
                "never" if not last_done
                else datetime.fromtimestamp(last_done, tz=timezone.utc).strftime("%Y-%m-%d")
            )
            next_sched_str = (
                "none" if not next_sched
                else datetime.fromtimestamp(next_sched, tz=timezone.utc).strftime("%Y-%m-%d")
                + (" (stale -- schedule is currently off)" if not is_scheduled else "")
            )

            scrub_status = p.get("scrubbingStatus") or ""
            progress = p.get("progress") or {}
            percent = progress.get("percent")
            remaining = progress.get("remaining_time") or 0
            is_running = scrub_status not in ("", "ready") and percent is not None

            if is_running:
                status_text = f"running ({percent}%)"
                progress_note = f", currently running: {percent}% complete"
                if remaining:
                    progress_note += f" (~{remaining / 3600:.1f}h remaining)"
            else:
                status_text = "scheduled" if is_scheduled else "not scheduled"
                progress_note = ""

            checks.append({
                "check_id": f"dsm:scrubbing:{p.get('id')}", "source": "dsm_system",
                "status": status_text,
                "detail": (
                    f"{p.get('desc') or p.get('pool_path')}: scheduled={is_scheduled}, "
                    f"last completed run={last_done_str}, "
                    f"next/last-known schedule date={next_sched_str}{progress_note}"
                ),
                "is_bad": not is_scheduled,
            })

        return checks, None
    except Exception as exc:
        return [], f"synology dsm: {exc}"


def _run_hyperbackup_collect(ctx: dict) -> int:
    requests.packages.urllib3.disable_warnings()

    backups: list[dict] = []
    dsm_system: list[dict] = []
    errors: list[str] = []

    synology = ctx.get("synology") or {}
    if synology.get("config_file"):
        found, err = _collect_hyperbackup(synology["config_file"])
        backups.extend(found)
        if err:
            errors.append(err)

        dsm_found, dsm_err = _collect_dsm_system(synology["config_file"])
        dsm_system.extend(dsm_found)
        if dsm_err:
            errors.append(dsm_err)

    print(json.dumps({"backups": backups, "dsm_system": dsm_system, "errors": errors}))
    return 0


_WG_AGO_RE = re.compile(
    r"(?:(\d+)\s+days?)?,?\s*(?:(\d+)\s+hours?)?,?\s*(?:(\d+)\s+minutes?)?,?\s*(?:(\d+)\s+seconds?)?\s*ago"
)


def _parse_wg_handshake_age(text: str) -> float | None:
    match = _WG_AGO_RE.search(text)
    if not match:
        return None
    days, hours, minutes, seconds = (int(g) if g else 0 for g in match.groups())
    return float(days * 86400 + hours * 3600 + minutes * 60 + seconds)


def _parse_wg_show(output: str) -> list[dict]:
    peers: list[dict] = []
    current: dict | None = None
    for line in output.splitlines():
        peer_match = re.match(r"^peer:\s*(\S+)", line)
        if peer_match:
            if current is not None:
                peers.append(current)
            current = {
                "pubkey": peer_match.group(1), "endpoint": None,
                "allowed_ips": None, "handshake_age_seconds": None,
            }
            continue
        if current is None:
            continue
        endpoint_match = re.match(r"^\s*endpoint:\s*(\S+)", line)
        if endpoint_match:
            current["endpoint"] = endpoint_match.group(1)
            continue
        allowed_match = re.match(r"^\s*allowed ips:\s*(\S+)", line)
        if allowed_match:
            current["allowed_ips"] = allowed_match.group(1)
            continue
        handshake_match = re.match(r"^\s*latest handshake:\s*(.+)$", line)
        if handshake_match:
            current["handshake_age_seconds"] = _parse_wg_handshake_age(handshake_match.group(1))
            continue
    if current is not None:
        peers.append(current)
    return peers


def _collect_wireguard(wg_ssh_host: str, wg_ssh_user: str) -> tuple[list[dict], str | None]:
    try:
        proc = subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes",
             f"{wg_ssh_user}@{wg_ssh_host}", "sudo -n wg show"],
            capture_output=True, text=True, timeout=15,
        )
        if proc.returncode != 0:
            return [], f"wireguard: ssh/wg show failed: {_ssh_err(proc.stderr) or proc.stdout.strip()}"
        now = datetime.now(timezone.utc)
        peers = []
        for p in _parse_wg_show(proc.stdout):
            age = p["handshake_age_seconds"]
            peers.append({
                "pubkey": p["pubkey"],
                "endpoint": p["endpoint"],
                "allowed_ips": p["allowed_ips"],
                "last_handshake_at": (now - timedelta(seconds=age)).isoformat() if age is not None else None,
            })
        return peers, None
    except Exception as exc:
        return [], f"wireguard: {exc}"


def _collect_ollama_version(ssh_host: str, ssh_user: str) -> tuple[str | None, str | None]:
    try:
        proc = subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes",
             f"{ssh_user}@{ssh_host}", "ollama --version"],
            capture_output=True, text=True, timeout=15,
        )
        if proc.returncode != 0:
            return None, f"ollama: ssh/version check failed: {_ssh_err(proc.stderr) or proc.stdout.strip()}"
        match = re.search(r"(\d+\.\d+\.\d+)", proc.stdout)
        if not match:
            return None, f"ollama: couldn't parse version from: {proc.stdout.strip()!r}"
        return match.group(1), None
    except Exception as exc:
        return None, f"ollama: {exc}"


def _run_ssh_agent_status(ctx: dict) -> int:
    try:
        probe = subprocess.run(
            ["ssh-add", "-l"], capture_output=True, text=True, timeout=5,
            env={**os.environ, "SSH_AUTH_SOCK": _MGMT1_SSH_AGENT_SOCK},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(json.dumps({"state": "unknown", "keys": 0, "errors": [f"ssh-add -l failed: {exc}"]}))
        return 0
    state = {0: "loaded", 1: "empty", 2: "no_agent"}.get(probe.returncode, "unknown")
    keys = len([l for l in probe.stdout.splitlines() if l.strip()]) if probe.returncode == 0 else 0
    print(json.dumps({"state": state, "keys": keys, "socket": _MGMT1_SSH_AGENT_SOCK, "errors": []}))
    return 0


def _run_ollama_version_check(ctx: dict) -> int:
    ollama = ctx.get("ollama") or {}
    errors: list[str] = []
    version = None
    if (ollama.get("ssh_host"), ollama.get("ssh_user")) != _OLLAMA_TARGET:
        errors.append(f"ollama: {ollama.get('ssh_user')}@{ollama.get('ssh_host')} is not the pinned Ollama host")
    elif ollama.get("ssh_host") and ollama.get("ssh_user"):
        version, err = _collect_ollama_version(ollama["ssh_host"], ollama["ssh_user"])
        if err:
            errors.append(err)
    else:
        errors.append("ollama: no ssh_host/ssh_user provided")
    print(json.dumps({"installed_version": version, "errors": errors}))
    return 0


_OLLAMA_CHAT_MODEL_RE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
_OLLAMA_CHAT_MAX_BYTES = 200_000


def _run_ollama_chat(ctx: dict) -> int:
    chat = ctx.get("chat") or {}
    model = chat.get("model")
    messages = chat.get("messages")
    if not (isinstance(model, str) and _OLLAMA_CHAT_MODEL_RE.match(model)):
        print(json.dumps({"ok": False, "errors": ["ollama_chat: bad or missing model"]}))
        return 0
    if not (isinstance(messages, list) and messages and all(
            isinstance(m, dict) and m.get("role") in ("system", "user")
            and isinstance(m.get("content"), str) for m in messages)):
        print(json.dumps({"ok": False, "errors": ["ollama_chat: messages must be system/user strings"]}))
        return 0
    body: dict = {"model": model, "messages": [{"role": m["role"], "content": m["content"]} for m in messages],
                  "stream": False, "think": False}
    if isinstance(chat.get("format"), dict):
        body["format"] = chat["format"]
    num_ctx = chat.get("num_ctx")
    if isinstance(num_ctx, int) and 2048 <= num_ctx <= 32768:
        body["options"] = {"num_ctx": num_ctx}
    payload = json.dumps(body)
    if len(payload) > _OLLAMA_CHAT_MAX_BYTES:
        print(json.dumps({"ok": False, "errors": [f"ollama_chat: request too large ({len(payload)} bytes)"]}))
        return 0
    timeout = min(max(float(chat.get("timeout") or 300), 30.0), 900.0)
    ssh_host, ssh_user = _OLLAMA_TARGET
    try:
        proc = subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes", f"{ssh_user}@{ssh_host}",
             f"curl -s -m {int(timeout)} http://127.0.0.1:11435/api/chat -d @-"],
            input=payload, capture_output=True, text=True, timeout=timeout + 20,
        )
    except subprocess.TimeoutExpired:
        print(json.dumps({"ok": False, "errors": ["ollama_chat: timed out"]}))
        return 0
    try:
        resp = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print(json.dumps({"ok": False, "errors": [
            f"ollama_chat: no JSON from Ollama (rc={proc.returncode}): {(proc.stderr or proc.stdout)[:300]}"]}))
        return 0
    if resp.get("error"):
        print(json.dumps({"ok": False, "errors": [f"ollama_chat: {resp['error']}"[:500]]}))
        return 0
    print(json.dumps({"ok": True, "content": (resp.get("message") or {}).get("content") or "",
                      "model": resp.get("model"), "prompt_tokens": resp.get("prompt_eval_count"),
                      "output_tokens": resp.get("eval_count"),
                      "seconds": round((resp.get("total_duration") or 0) / 1e9, 1)}))
    return 0


_OLLAMA_STAGING_SCRIPT = "/home/rbdroot/ollama-install-staging/install.sh"
_OLLAMA_INSTALL_HELPER = "/usr/local/sbin/rbd-ollama-install"


def _run_ollama_apply_update(ctx: dict) -> int:
    ollama = ctx.get("ollama") or {}
    ssh_host, ssh_user = ollama.get("ssh_host"), ollama.get("ssh_user")
    if not (ssh_host and ssh_user):
        print(json.dumps({"ok": False, "installed_version": None, "output": "", "errors": ["ollama: no ssh_host/ssh_user provided"]}))
        return 0
    if (ssh_host, ssh_user) != _OLLAMA_TARGET:
        print(json.dumps({"ok": False, "installed_version": None, "output": "",
                          "errors": [f"ollama: {ssh_user}@{ssh_host} is not the pinned Ollama host"]}))
        return 0

    def _ssh(command: str, timeout: float) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes",
             f"{ssh_user}@{ssh_host}", command],
            capture_output=True, text=True, timeout=timeout,
        )

    try:
        has_helper = _ssh(f"test -x {_OLLAMA_INSTALL_HELPER}", timeout=15).returncode == 0
    except Exception:
        has_helper = False
    install_cmd = (f"sudo -n {_OLLAMA_INSTALL_HELPER}" if has_helper
                   else f"sudo -n /usr/bin/sh {_OLLAMA_STAGING_SCRIPT}")

    if not has_helper:
        try:
            download = _ssh(
                f"mkdir -p $(dirname {_OLLAMA_STAGING_SCRIPT}) "
                f"&& curl -fsSL https://ollama.com/install.sh -o {_OLLAMA_STAGING_SCRIPT} "
                f"&& chmod +x {_OLLAMA_STAGING_SCRIPT}",
                timeout=60,
            )
            if download.returncode != 0:
                print(json.dumps({
                    "ok": False, "installed_version": None,
                    "output": (download.stdout + download.stderr).strip()[-2000:],
                    "errors": ["ollama: failed to download the installer script"],
                }))
                return 0
        except Exception as exc:
            print(json.dumps({"ok": False, "installed_version": None, "output": "", "errors": [f"ollama: {exc}"]}))
            return 0

    try:
        proc = _ssh(install_cmd, timeout=300)
        output = (proc.stdout + proc.stderr).strip()
        if proc.returncode != 0:
            print(json.dumps({
                "ok": False, "installed_version": None, "output": output[-4000:],
                "errors": [f"ollama: installer exited {proc.returncode}"],
            }))
            return 0
    except Exception as exc:
        print(json.dumps({"ok": False, "installed_version": None, "output": "", "errors": [f"ollama: {exc}"]}))
        return 0

    version, err = _collect_ollama_version(ssh_host, ssh_user)
    print(json.dumps({
        "ok": err is None and version is not None,
        "installed_version": version,
        "output": output[-4000:],
        "errors": [err] if err else [],
    }))
    return 0


_SSH_EXEC_ALLOWED_TARGETS = {
    ("192.168.10.101", "rbdroot"),
    ("192.168.30.19", "rbdroot"),
    ("192.168.30.201", "rbdroot"),
}
_SSH_EXEC_ENFORCE = True
_OLLAMA_TARGET = ("192.168.10.101", "rbdroot")
_WIREGUARD_TARGET = ("192.168.50.253", "rbdroot")
_SSH_EXEC_AUDIT_LOG = os.path.expanduser("~/.local/state/rbd-update-bot/ssh_exec_audit.jsonl")

_N = r"[A-Za-z0-9][A-Za-z0-9_.-]*"
_P = r"/(?!.*\.\.)[A-Za-z0-9_./-]+"
_IMG = r"[a-z0-9][a-z0-9._/-]*"
_TAG = r"[A-Za-z0-9_][A-Za-z0-9_.-]*"


def _lit(s: str) -> str:
    return re.escape(s)


_SSH_EXEC_PATTERNS: dict[str, re.Pattern] = {name: re.compile(rx, re.DOTALL) for name, rx in {
    "true": _lit("true"),
    "who": _lit("who"),
    "reboot": _lit("sudo systemctl reboot"),
    "apt_full_upgrade": _lit("sudo apt-get update && sudo apt-get -y full-upgrade"),
    "apt_upgradable": _lit("apt list --upgradable 2>/dev/null"),
    "reboot_required": _lit("test -e /var/run/reboot-required && echo REBOOT_REQUIRED || echo OK"),
    "installed_kernels": _lit(
        "dpkg-query -W -f='${db:Status-Abbrev} ${Package} ${Version}\\n' 'linux-image-*' 2>/dev/null "
        "| awk '$1==\"ii\"{print $2, $3}'"),
    "kernel_info": _lit(
        'echo "KERNEL:$(uname -r)"; . /etc/os-release 2>/dev/null; echo "DISTRO:$PRETTY_NAME"; '
        'echo "VIRT:$(systemd-detect-virt --container 2>/dev/null)"; '
        'echo "PKGVER:$(dpkg-query -W -f=\'${Version}\' linux-image-$(uname -r) 2>/dev/null)"'),
    "docker_prune": _lit(
        "command -v docker >/dev/null 2>&1 && { docker image prune -f; docker builder prune -f; } "
        "|| echo 'no docker on this host'"),
    "guest_resources": (
        _lit("free -b | awk '/^Mem:/{print \"MEM_TOTAL:\"$2; print \"MEM_USED:\"$3}"
             "/^Swap:/{print \"SWAP_TOTAL:\"$2}'; "
             "echo \"LOAD1:$(cut -d' ' -f1 /proc/loadavg)\"; "
             "echo \"NPROC:$(nproc)\"; "
             "echo \"DISK_PCT:$(df -P / | awk 'NR==2{print $5}' | tr -d '%')\"; "
             "OOM_RAW=$(journalctl -k --since '-")
        + r"\d+\.\d" + _lit(" hours' --no-pager 2>&1); "
             'echo "OOM_STATUS:$?"; '
             'echo "OOM:$(echo "$OOM_RAW" | grep -iE \'out of memory|oom-kill\' | tail -3 | base64 -w0)"')
        + "(?:" + _lit('; echo "DB_UNIT_STATE:$(systemctl is-active ') + _N + _lit(' 2>&1)"') + ")?"),
    "cat_file": r"cat " + _P,
    "compose_image_grep": r"grep -m1 'image: " + _IMG + r":' " + _P,
    "ollama_auth_gate": (
        _lit("for p in 11434 11435; do printf '%s:' $p; curl -s -o /dev/null -w '%{http_code}' -m 5 http://")
        + r"\d{1,3}(?:\.\d{1,3}){3}" + _lit(":$p/api/tags; echo; done; true")),
    "unit_ctl": r"sudo systemctl (?:restart|stop|start) " + _N,
    "unit_show": r"systemctl show " + _N + _lit(" --property=NRestarts,ActiveState --value"),
    "unit_journal_n": r"journalctl -u " + _N + r" --no-pager -n \d+",
    "unit_journal_since": r"journalctl -u " + _N + r" --since '\d+ seconds ago' --no-pager",
    "container_ctl": r"docker (?:restart|stop|start) " + _N,
    "container_logs_tail": r"docker logs --timestamps --tail \d+ " + _N,
    "container_logs_since": r"docker logs --since [0-9A-Za-z:.+-]+ " + _N,
    "container_id": _lit("docker inspect --format='{{.Id}}' ") + _N,
    "container_health": _lit("docker inspect --format='{{.Id}}|{{.State.Health.Status}}' ") + _N,
    "container_restarts": _lit("docker inspect --format='{{.RestartCount}} {{.State.Status}}' ") + _N,
    "container_pg_isready": r"docker exec " + _N + _lit(" pg_isready 2>&1"),
    "container_sv_status": r"docker exec " + _N + r" sv status(?: " + _N + ")+",
    "container_supervisorctl": r"docker exec " + _N + _lit(" supervisorctl status"),
    "running_image": _lit("docker ps --format '{{.Image}}' | grep -m1 '^") + _IMG + _lit(":'"),
    "image_digest": r"docker image inspect " + _IMG + ":" + _TAG + _lit(" --format '{{index .RepoDigests 0}}'"),
    "compose_update": (
        r"(?:sed 's\|image: " + _IMG + ":" + r"(?:" + _TAG + r"|\.\*)" + r"\|image: " + _IMG + ":" + _TAG
        + r"\|' (?P<f1>" + _P + r") \| sudo tee (?P=f1)\.new > /dev/null && sudo cp (?P=f1)\.new (?P=f1)"
        + r" && sudo rm (?P=f1)\.new && )*"
        + r"cd " + _P + r" && docker compose pull && docker compose up -d(?: --force-recreate(?: " + _N + r")*)?"),
}.items()}

_WEDDING_HUB_DB_PATHS = {"/opt/wedding-hub/wedding_hub.db"}
_WEDDING_HUB_QUERY = (
    "SELECT COUNT(*) FROM guests g "
    "JOIN guest_members gm ON gm.guest_id = g.id "
    "WHERE trim(coalesce(gm.wedding_role, '')) != '' "
    "AND (lower(g.email) = lower(?) OR lower(coalesce(gm.email, '')) = lower(?))"
)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _wedding_hub_script(db_path: str) -> str:
    return ("import sqlite3,sys;"
            f"conn = sqlite3.connect('file:{db_path}?mode=ro', uri=True);"
            f"row = conn.execute({_WEDDING_HUB_QUERY!r}, (sys.argv[1], sys.argv[1])).fetchone();"
            "print(1 if row and row[0] > 0 else 0)")


def _match_ssh_exec_command(command: str) -> str | None:
    for name, rx in _SSH_EXEC_PATTERNS.items():
        if rx.fullmatch(command):
            return name
    try:
        import shlex
        argv = shlex.split(command)
    except ValueError:
        return None
    if (len(argv) == 4 and argv[:2] == ["python3", "-c"]
            and any(argv[2] == _wedding_hub_script(p) for p in _WEDDING_HUB_DB_PATHS)
            and _EMAIL_RE.fullmatch(argv[3])):
        return "wedding_hub_contact_lookup"
    return None


def _audit_ssh_exec(entry: dict) -> None:
    try:
        os.makedirs(os.path.dirname(_SSH_EXEC_AUDIT_LOG), exist_ok=True)
        with open(_SSH_EXEC_AUDIT_LOG, "a") as f:
            f.write(json.dumps({"ts": datetime.now(timezone.utc).isoformat(), **entry}) + "\n")
    except OSError:
        pass


def _run_ssh_exec(ctx: dict) -> int:
    ssh_host, ssh_user = ctx.get("ssh_host"), ctx.get("ssh_user")
    command = ctx.get("command")
    timeout = float(ctx.get("timeout") or 30.0)
    if not (ssh_host and ssh_user and command):
        print(json.dumps({"ok": False, "output": "ssh_exec: missing ssh_host/ssh_user/command"}))
        return 0
    if (ssh_host, ssh_user) not in _SSH_EXEC_ALLOWED_TARGETS:
        _audit_ssh_exec({"decision": "deny_target", "host": ssh_host, "user": ssh_user, "command": command})
        print(json.dumps({"ok": False, "output": f"ssh_exec: {ssh_user}@{ssh_host} is not an allowed relay target"}))
        return 0
    matched = _match_ssh_exec_command(command)
    if matched is None:
        _audit_ssh_exec({"decision": "deny" if _SSH_EXEC_ENFORCE else "would_deny",
                         "host": ssh_host, "command": command})
        if _SSH_EXEC_ENFORCE:
            print(json.dumps({"ok": False, "output": "ssh_exec: command not in the relay allowlist"}))
            return 0
    else:
        _audit_ssh_exec({"decision": "allow", "host": ssh_host, "rule": matched})
    try:
        proc = subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes",
             "-o", "ConnectTimeout=3", f"{ssh_user}@{ssh_host}", command],
            capture_output=True, text=True, timeout=timeout,
        )
        print(json.dumps({"ok": proc.returncode == 0, "output": (proc.stdout + proc.stderr).strip()}))
    except subprocess.TimeoutExpired:
        print(json.dumps({"ok": False, "output": "ssh_exec: timed out"}))
    except Exception as exc:
        print(json.dumps({"ok": False, "output": f"ssh_exec: {exc}"}))
    return 0


def _run_wg_collect(ctx: dict) -> int:
    peers: list[dict] = []
    errors: list[str] = []

    wg = ctx.get("wireguard") or {}
    if wg.get("ssh_host") and (wg.get("ssh_host"), wg.get("ssh_user")) != _WIREGUARD_TARGET:
        errors.append(f"wireguard: {wg.get('ssh_user')}@{wg.get('ssh_host')} is not the pinned WireGuard host")
    elif wg.get("ssh_host") and wg.get("ssh_user"):
        found, err = _collect_wireguard(wg["ssh_host"], wg["ssh_user"])
        peers.extend(found)
        if err:
            errors.append(err)

    print(json.dumps({"peers": peers, "errors": errors}))
    return 0


def _run_disk_health_collect(ctx: dict) -> int:
    requests.packages.urllib3.disable_warnings()

    disks: list[dict] = []
    errors: list[str] = []

    synology = ctx.get("synology") or {}
    if synology.get("config_file"):
        found, err = _collect_synology(synology["config_file"])
        disks.extend(found)
        if err:
            errors.append(err)

    print(json.dumps({"disks": disks, "errors": errors}))
    return 0


def _run_network_collect(ctx: dict) -> int:
    requests.packages.urllib3.disable_warnings()

    devices: list[dict] = []
    errors: list[str] = []

    omada = ctx.get("omada") or {}
    if omada.get("config_file"):
        found, err = _collect_omada(omada["config_file"])
        devices.extend(found)
        if err:
            errors.append(err)

    fortigate = ctx.get("fortigate") or {}
    if fortigate.get("api_host") and fortigate.get("token_file"):
        found, err = _collect_fortigate_dhcp(fortigate["api_host"], fortigate["token_file"])
        devices.extend(found)
        if err:
            errors.append(err)

    for dev in devices:
        if dev.get("mac"):
            dev["mac"] = dev["mac"].lower().replace("-", ":")

    print(json.dumps({"devices": devices, "errors": errors}))
    return 0


def _run_firewall_traffic_collect(ctx: dict) -> int:
    requests.packages.urllib3.disable_warnings()

    fortigate = ctx.get("fortigate") or {}
    if not (fortigate.get("api_host") and fortigate.get("token_file")):
        print(json.dumps({"exposed": [], "blocklist": [], "iot_egress": [], "errors": ["no fortigate config provided"]}))
        return 0

    data, err = _collect_firewall_traffic(fortigate["api_host"], fortigate["token_file"])
    errors = [err] if err else []
    print(json.dumps({
        "exposed": data["exposed"], "blocklist": data["blocklist"],
        "iot_egress": data["iot_egress"], "errors": errors,
    }))
    return 0


def _run_fortigate_policy_list(ctx: dict) -> int:
    requests.packages.urllib3.disable_warnings()
    fortigate = ctx.get("fortigate") or {}
    if not (fortigate.get("api_host") and fortigate.get("token_file")):
        print(json.dumps({"policies": [], "errors": ["no fortigate config provided"]}))
        return 0
    try:
        with open(fortigate["token_file"]) as f:
            token = f.read().strip()
        resp = requests.get(
            f"{fortigate['api_host']}/api/v2/cmdb/firewall/policy",
            headers={"Authorization": f"Bearer {token}"}, verify=False, timeout=15,
        )
        resp.raise_for_status()
        policies = []
        for p in resp.json().get("results", []):
            policies.append({
                "policyid": p.get("policyid"), "name": p.get("name"),
                "status": p.get("status"), "action": p.get("action"),
                "srcintf": [i.get("name") for i in p.get("srcintf", [])],
                "dstintf": [i.get("name") for i in p.get("dstintf", [])],
                "srcaddr": [a.get("name") for a in p.get("srcaddr", [])],
                "dstaddr": [a.get("name") for a in p.get("dstaddr", [])],
                "service": [s.get("name") for s in p.get("service", [])],
            })
        print(json.dumps({"policies": policies, "errors": []}))
    except Exception as exc:
        print(json.dumps({"policies": [], "errors": [str(exc)]}))
    return 0


def _run_fortigate_object_lookup(ctx: dict) -> int:
    requests.packages.urllib3.disable_warnings()
    fortigate = ctx.get("fortigate") or {}
    cmdb_path = ctx.get("cmdb_path") or ""
    name_filter = ctx.get("name")
    if not (fortigate.get("api_host") and fortigate.get("token_file") and cmdb_path):
        print(json.dumps({"objects": [], "errors": ["missing fortigate config or cmdb_path"]}))
        return 0
    try:
        with open(fortigate["token_file"]) as f:
            token = f.read().strip()
        url = f"{fortigate['api_host']}/api/v2/cmdb/{cmdb_path}"
        if name_filter:
            url += f"/{name_filter}"
        resp = requests.get(url, headers={"Authorization": f"Bearer {token}"}, verify=False, timeout=15)
        resp.raise_for_status()
        print(json.dumps({"objects": resp.json().get("results", []), "errors": []}))
    except Exception as exc:
        print(json.dumps({"objects": [], "errors": [str(exc)]}))
    return 0


_CONFIG_ARCHIVE_DIR = "/mnt/logarchive/compose-configs"
_CONFIG_ARCHIVE_TARGETS = {
    "joplin": ("rbd-joplin", "/opt/joplin-server/docker-compose.yml"),
    "matrix": ("rbd-matrix", "/opt/matrix/docker-compose.yml"),
    "nextcloud": ("rbd-nextcloud", "/opt/nextcloud/docker-compose.yml"),
    "mass": ("rbd-mass", "/opt/music-assistant/docker-compose.yml"),
    "discourse": ("rbd-discourse", "/var/discourse/containers/app.yml"),
    "enshrouded": ("192.168.30.19", "/opt/enshrouded/docker-compose.yml"),
}


def _run_config_archive_collect(ctx: dict) -> int:
    os.makedirs(_CONFIG_ARCHIVE_DIR, exist_ok=True)
    if not os.path.isdir(os.path.join(_CONFIG_ARCHIVE_DIR, ".git")):
        subprocess.run(["git", "init", "-q", _CONFIG_ARCHIVE_DIR], check=False)

    errors: list[str] = []

    for service, (ssh_target, remote_path) in _CONFIG_ARCHIVE_TARGETS.items():
        try:
            proc = subprocess.run(
                ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes",
                 ssh_target, f"cat {remote_path}"],
                capture_output=True, text=True, timeout=20,
            )
            if proc.returncode != 0:
                errors.append(f"{service}: {_ssh_err(proc.stderr) or 'fetch failed'}")
                continue
            with open(os.path.join(_CONFIG_ARCHIVE_DIR, f"{service}.yml"), "w") as f:
                f.write(proc.stdout)
        except subprocess.TimeoutExpired:
            errors.append(f"{service}: timed out")
        except Exception as exc:
            errors.append(f"{service}: {exc}")

    immich_content = ctx.get("immich_stack_content")
    if immich_content:
        with open(os.path.join(_CONFIG_ARCHIVE_DIR, "immich.yml"), "w") as f:
            f.write(immich_content)
    else:
        errors.append("immich: no stack content provided by the caller")

    subprocess.run(["git", "-C", _CONFIG_ARCHIVE_DIR, "add", "-A"], check=False)
    status = subprocess.run(
        ["git", "-C", _CONFIG_ARCHIVE_DIR, "status", "--porcelain"],
        capture_output=True, text=True,
    ).stdout
    changed_files = [line[3:] for line in status.splitlines() if line.strip()]

    commit_hash = None
    diffs: dict[str, str] = {}
    if changed_files:
        for f in changed_files:
            diffs[f] = subprocess.run(
                ["git", "-C", _CONFIG_ARCHIVE_DIR, "diff", "HEAD", "--", f],
                capture_output=True, text=True,
            ).stdout
        subprocess.run(
            ["git", "-C", _CONFIG_ARCHIVE_DIR,
             "-c", "user.name=rbd-update-bot", "-c", "user.email=rbd-update-bot@example.com",
             "commit", "-q", "-m", f"config snapshot: {', '.join(changed_files)}"],
            check=False,
        )
        commit_hash = subprocess.run(
            ["git", "-C", _CONFIG_ARCHIVE_DIR, "rev-parse", "HEAD"],
            capture_output=True, text=True,
        ).stdout.strip()

    print(json.dumps({
        "committed": bool(changed_files), "commit_hash": commit_hash,
        "changed_files": changed_files, "diffs": diffs, "errors": errors,
    }))
    return 0


_KB_REGISTRATION_TOKEN_REPO = "/srv/kb-site"
_KB_REGISTRATION_TOKEN_FILE = "src/content/docs/matrix/restricted/registration-token.md"
_KB_REGISTRATION_TOKEN_LINE_RE = re.compile(r"^(\s*)`[0-9a-zA-Z]{16,}`\s*$", re.MULTILINE)


def _run_kb_registration_token_update(ctx: dict) -> int:
    new_token = (ctx.get("new_token") or "").strip()
    if not new_token:
        print(json.dumps({"ok": False, "detail": "missing new_token"}))
        return 0

    file_path = os.path.join(_KB_REGISTRATION_TOKEN_REPO, _KB_REGISTRATION_TOKEN_FILE)
    try:
        with open(file_path) as f:
            content = f.read()
    except OSError as exc:
        print(json.dumps({"ok": False, "detail": f"couldn't read {file_path}: {exc}"}))
        return 0

    new_content, count = _KB_REGISTRATION_TOKEN_LINE_RE.subn(
        lambda m: f"{m.group(1)}`{new_token}`", content, count=1,
    )
    if count == 0:
        print(json.dumps({
            "ok": False,
            "detail": "couldn't find the registration-token line to replace -- page format may have changed",
        }))
        return 0

    with open(file_path, "w") as f:
        f.write(new_content)

    subprocess.run(
        ["git", "-C", _KB_REGISTRATION_TOKEN_REPO, "add", _KB_REGISTRATION_TOKEN_FILE], check=False,
    )
    status = subprocess.run(
        ["git", "-C", _KB_REGISTRATION_TOKEN_REPO, "status", "--porcelain", "--", _KB_REGISTRATION_TOKEN_FILE],
        capture_output=True, text=True,
    ).stdout
    if not status.strip():
        print(json.dumps({"ok": True, "detail": "file already matched the new token, nothing to commit"}))
        return 0

    commit = subprocess.run(
        ["git", "-C", _KB_REGISTRATION_TOKEN_REPO,
         "-c", "user.name=rbd-update-bot", "-c", "user.email=rbd-update-bot@example.com",
         "commit", "-q", "-m", "Rotate Matrix registration token"],
        capture_output=True, text=True,
    )
    if commit.returncode != 0:
        print(json.dumps({"ok": False, "detail": f"commit failed: {commit.stderr.strip()}"}))
        return 0

    try:
        push = subprocess.run(
            ["git", "-C", _KB_REGISTRATION_TOKEN_REPO, "push"],
            capture_output=True, text=True, timeout=30,
        )
    except subprocess.TimeoutExpired:
        print(json.dumps({"ok": False, "detail": "committed locally but push timed out"}))
        return 0
    if push.returncode != 0:
        print(json.dumps({"ok": False, "detail": f"committed locally but push failed: {push.stderr.strip()}"}))
        return 0

    print(json.dumps({"ok": True, "detail": "KB page updated and pushed"}))
    return 0


_DISCOURSE_BACKUP_DIR = "/mnt/logarchive/discourse-backups"
_DISCOURSE_BACKUP_SSH_TARGET = "rbd-discourse"
_DISCOURSE_BACKUP_REMOTE_DIR = "/var/discourse/shared/standalone/backups/default"
_DISCOURSE_BACKUP_FILENAME_RE = re.compile(r"-(\d{4}-\d{2}-\d{2})-(\d{2})(\d{2})(\d{2})-v")


def _discourse_backup_datetime(filename: str) -> datetime | None:
    m = _DISCOURSE_BACKUP_FILENAME_RE.search(filename)
    if not m:
        return None
    try:
        return datetime.strptime(
            f"{m.group(1)} {m.group(2)}:{m.group(3)}:{m.group(4)}", "%Y-%m-%d %H:%M:%S",
        ).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _run_discourse_backup_pull(ctx: dict) -> int:
    retention_days = ctx.get("retention_days", 90)
    os.makedirs(_DISCOURSE_BACKUP_DIR, exist_ok=True)

    errors: list[str] = []

    list_proc = subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes",
         _DISCOURSE_BACKUP_SSH_TARGET, f"ls -1 {_DISCOURSE_BACKUP_REMOTE_DIR}"],
        capture_output=True, text=True, timeout=20,
    )
    if list_proc.returncode != 0:
        print(json.dumps({
            "pulled": [], "pruned": [], "newest_remote_file": None,
            "newest_remote_age_hours": None,
            "errors": [f"could not list remote backups: {_ssh_err(list_proc.stderr)}"],
        }))
        return 0

    remote_files = sorted(f for f in list_proc.stdout.splitlines() if f.strip().endswith(".tar.gz"))

    newest_remote_file, newest_remote_age_hours = None, None
    for f in remote_files:
        backup_dt = _discourse_backup_datetime(f)
        if backup_dt is None:
            continue
        age_hours = (datetime.now(timezone.utc) - backup_dt).total_seconds() / 3600
        if newest_remote_age_hours is None or age_hours < newest_remote_age_hours:
            newest_remote_age_hours, newest_remote_file = age_hours, f

    existing_local = set(os.listdir(_DISCOURSE_BACKUP_DIR))
    pulled: list[str] = []
    for f in remote_files:
        if f in existing_local:
            continue
        local_path = os.path.join(_DISCOURSE_BACKUP_DIR, f)
        tmp_path = local_path + ".partial"
        scp_proc = subprocess.run(
            ["scp", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes",
             f"{_DISCOURSE_BACKUP_SSH_TARGET}:{_DISCOURSE_BACKUP_REMOTE_DIR}/{f}", tmp_path],
            capture_output=True, text=True, timeout=600,
        )
        if scp_proc.returncode != 0:
            errors.append(f"{f}: scp failed: {_ssh_err(scp_proc.stderr)}")
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            continue
        verify_proc = subprocess.run(["tar", "-tzf", tmp_path], capture_output=True, text=True, timeout=120)
        if verify_proc.returncode != 0:
            errors.append(f"{f}: failed tar -tzf integrity check after pull, discarded")
            os.remove(tmp_path)
            continue
        os.rename(tmp_path, local_path)
        pulled.append(f)

    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    pruned: list[str] = []
    for f in sorted(os.listdir(_DISCOURSE_BACKUP_DIR)):
        backup_dt = _discourse_backup_datetime(f)
        if backup_dt is not None and backup_dt < cutoff:
            os.remove(os.path.join(_DISCOURSE_BACKUP_DIR, f))
            pruned.append(f)

    print(json.dumps({
        "pulled": pulled, "pruned": pruned,
        "newest_remote_file": newest_remote_file,
        "newest_remote_age_hours": newest_remote_age_hours,
        "errors": errors,
    }))
    return 0


_DISCOURSE_BACKUP_FULL_FILENAME_RE = re.compile(r"^[A-Za-z0-9._-]+\.tar\.gz$")


def _validate_discourse_backup_filename(filename: str) -> bool:
    return bool(_DISCOURSE_BACKUP_FULL_FILENAME_RE.match(filename)) and ".." not in filename


def _run_discourse_backup_list(ctx: dict) -> int:
    os.makedirs(_DISCOURSE_BACKUP_DIR, exist_ok=True)
    backups = []
    for f in sorted(os.listdir(_DISCOURSE_BACKUP_DIR)):
        if not f.endswith(".tar.gz"):
            continue
        backup_dt = _discourse_backup_datetime(f)
        full_path = os.path.join(_DISCOURSE_BACKUP_DIR, f)
        try:
            size_bytes = os.path.getsize(full_path)
        except OSError:
            size_bytes = None
        backups.append({
            "filename": f,
            "backup_timestamp": backup_dt.isoformat() if backup_dt else None,
            "size_bytes": size_bytes,
        })
    backups.sort(key=lambda b: b["backup_timestamp"] or "", reverse=True)
    print(json.dumps({"backups": backups}))
    return 0


def _run_discourse_backup_push(ctx: dict) -> int:
    filename = ctx.get("filename", "")
    if not _validate_discourse_backup_filename(filename):
        print(json.dumps({"ok": False, "already_present": False, "error": f"invalid filename: {filename!r}"}))
        return 0

    local_path = os.path.join(_DISCOURSE_BACKUP_DIR, filename)
    if not os.path.isfile(local_path):
        print(json.dumps({"ok": False, "already_present": False, "error": f"not found in archive: {filename}"}))
        return 0

    check_proc = subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes",
         _DISCOURSE_BACKUP_SSH_TARGET, f"test -f {_DISCOURSE_BACKUP_REMOTE_DIR}/{filename}"],
        capture_output=True, text=True, timeout=20,
    )
    if check_proc.returncode == 0:
        print(json.dumps({"ok": True, "already_present": True, "error": None}))
        return 0

    scp_proc = subprocess.run(
        ["scp", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes",
         local_path, f"{_DISCOURSE_BACKUP_SSH_TARGET}:{_DISCOURSE_BACKUP_REMOTE_DIR}/{filename}"],
        capture_output=True, text=True, timeout=600,
    )
    if scp_proc.returncode != 0:
        print(json.dumps({"ok": False, "already_present": False, "error": f"scp failed: {_ssh_err(scp_proc.stderr)}"}))
        return 0

    print(json.dumps({"ok": True, "already_present": False, "error": None}))
    return 0


_LIBRENMS_SSH_TARGET = "rbdroot@192.168.50.15"
_LIBRENMS_RRD_BASE = "/opt/librenms/rrd"

_LIBRENMS_BANDWIDTH_TARGETS: dict[str, tuple[str, int, tuple[str, ...]]] = {
    "192.168.20.11": ("rbd-pmx1", 118, ("rbd-pmx1",)),
    "192.168.20.12": ("rbd-pmx2", 141, ("rbd-pmx2",)),
    "192.168.20.13": ("rbd-pmx3", 159, ("rbd-pmx3",)),
    "192.168.20.14": ("rbd-pmx4", 171, ("rbd-pmx4",)),
    "192.168.20.5": ("rbd-pbs", 202, ("pbs",)),
    "192.168.20.40": ("rbd-nas", 198, ()),
}


def _rrd_fetch_max(host_ip: str, port_id: int, days: int) -> list[tuple[int, float, float]]:
    path = f"{_LIBRENMS_RRD_BASE}/{host_ip}/port-id{port_id}.rrd"
    proc = subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes",
         _LIBRENMS_SSH_TARGET, "rrdtool", "fetch", path, "MAX", "-s", f"-{days}d", "-e", "now"],
        capture_output=True, text=True, timeout=60,
    )
    if proc.returncode != 0:
        return []
    rows: list[tuple[int, float, float]] = []
    for line in proc.stdout.splitlines()[2:]:
        ts_part, _, rest = line.partition(":")
        vals = rest.split()
        if len(vals) < 2:
            continue
        try:
            ts = int(ts_part)
            in_v, out_v = float(vals[0]), float(vals[1])
        except ValueError:
            continue
        if in_v != in_v or out_v != out_v:
            continue
        rows.append((ts, in_v, out_v))
    return rows


def _correlate_backup_check(
    peak_dt: datetime, self_keys: tuple[str, ...], backup_checks: list[dict], window_hours: float = 2.0,
) -> str | None:
    self_match, self_delta = None, None
    any_match, any_delta = None, None
    for check in backup_checks:
        completed_at = check.get("completed_at")
        check_id = check.get("check_id", "")
        if not completed_at or not check_id:
            continue
        try:
            completed_dt = datetime.fromisoformat(completed_at)
        except ValueError:
            continue
        delta_hours = abs((peak_dt - completed_dt).total_seconds()) / 3600
        if delta_hours > window_hours:
            continue
        if any_delta is None or delta_hours < any_delta:
            any_match, any_delta = check_id, delta_hours
        if any(k.lower() in check_id.lower() for k in self_keys) and (self_delta is None or delta_hours < self_delta):
            self_match, self_delta = check_id, delta_hours
    return self_match or any_match


def _run_librenms_bandwidth_trend(ctx: dict) -> int:
    days = ctx.get("days", 7)
    backup_checks = ctx.get("backup_checks", [])

    trend: dict[str, dict] = {}
    for host_ip, (label, port_id, self_keys) in _LIBRENMS_BANDWIDTH_TARGETS.items():
        rows = _rrd_fetch_max(host_ip, port_id, days)
        if not rows:
            trend[label] = {"error": "no RRD data (SSH/rrdtool failed or file missing)"}
            continue

        by_day: dict[str, tuple[int, float, float]] = {}
        for ts, in_v, out_v in rows:
            day = datetime.fromtimestamp(ts, tz=timezone.utc).date().isoformat()
            cur = by_day.get(day)
            if cur is None or (in_v + out_v) > (cur[1] + cur[2]):
                by_day[day] = (ts, in_v, out_v)

        nights = []
        for day, (ts, in_v, out_v) in sorted(by_day.items(), reverse=True):
            peak_dt = datetime.fromtimestamp(ts, tz=timezone.utc)
            entry = {
                "date": day,
                "peak_time_utc": peak_dt.isoformat(),
                "in_mbps": round(in_v * 8 / 1e6, 1),
                "out_mbps": round(out_v * 8 / 1e6, 1),
            }
            likely_cause = _correlate_backup_check(peak_dt, self_keys, backup_checks)
            if likely_cause:
                entry["likely_cause"] = likely_cause
            nights.append(entry)
        trend[label] = {"nights": nights}

    print(json.dumps({"trend": trend}))
    return 0


_BLOCKLIST_ADDRGRP = "RBD-BOT-BLOCK"
_BLOCK_OBJECT_PREFIX = "RBD-BLOCK-"


def _fortigate_write_headers(write_token_file: str) -> dict:
    with open(write_token_file) as f:
        token = f.read().strip()
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


_RFC1918_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def _validate_blockable_ip(ip: str) -> tuple[bool, str]:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False, f"{ip!r} is not a valid IP address"
    if addr.version != 4:
        return False, f"{ip!r} is IPv6 -- only IPv4 is supported today"
    if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
        return False, f"{ip!r} is a loopback/link-local/multicast address -- refusing to block it"
    if any(addr in net for net in _RFC1918_NETWORKS):
        return False, f"{ip!r} is a private (RFC 1918) address -- refusing to block it"
    return True, ""


def _get_blocklist_members(api_host: str, headers: dict) -> list[str]:
    resp = requests.get(
        f"{api_host}/api/v2/cmdb/firewall/addrgrp/{_BLOCKLIST_ADDRGRP}",
        headers=headers, verify=False, timeout=15,
    )
    resp.raise_for_status()
    return [m["name"] for m in resp.json()["results"][0].get("member", [])]


def _set_blocklist_members(api_host: str, headers: dict, members: list[str]) -> None:
    resp = requests.put(
        f"{api_host}/api/v2/cmdb/firewall/addrgrp/{_BLOCKLIST_ADDRGRP}",
        headers=headers, verify=False, timeout=15,
        json={"member": [{"name": m} for m in members]},
    )
    resp.raise_for_status()


def _run_fortigate_wan_ip(ctx: dict) -> int:
    requests.packages.urllib3.disable_warnings()
    fortigate = ctx.get("fortigate") or {}
    api_host = fortigate.get("api_host")
    token_file = fortigate.get("token_file")
    if not (api_host and token_file):
        print(json.dumps({"wan_ip": None, "error": "missing api_host/token_file"}))
        return 0
    try:
        with open(token_file) as f:
            token = f.read().strip()
        resp = requests.get(
            f"{api_host}/api/v2/monitor/system/interface",
            headers={"Authorization": f"Bearer {token}"},
            params={"interface": "wan1"},
            verify=False, timeout=15,
        )
        resp.raise_for_status()
        ip = resp.json()["results"]["wan1"]["ip"]
        print(json.dumps({"wan_ip": ip, "error": None}))
    except Exception as exc:
        print(json.dumps({"wan_ip": None, "error": str(exc)}))
    return 0


def _run_fortigate_status(ctx: dict) -> int:
    requests.packages.urllib3.disable_warnings()
    fortigate = ctx.get("fortigate") or {}
    api_host = fortigate.get("api_host")
    token_file = fortigate.get("token_file")
    if not (api_host and token_file):
        print(json.dumps({"version": None, "error": "missing api_host/token_file"}))
        return 0
    try:
        with open(token_file) as f:
            token = f.read().strip()
        resp = requests.get(
            f"{api_host}/api/v2/monitor/system/status",
            headers={"Authorization": f"Bearer {token}"},
            verify=False, timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        results = data.get("results", {})
        print(json.dumps({
            "version": data.get("version"), "build": data.get("build"),
            "serial": data.get("serial"), "model": results.get("model"),
            "hostname": results.get("hostname"), "error": None,
        }))
    except Exception as exc:
        print(json.dumps({"version": None, "error": str(exc)}))
    return 0


def _run_fortigate_config_backup(ctx: dict) -> int:
    import base64
    requests.packages.urllib3.disable_warnings()
    fortigate = ctx.get("fortigate") or {}
    api_host = fortigate.get("api_host")
    token_file = fortigate.get("token_file")
    if not (api_host and token_file):
        print(json.dumps({"config_b64": None, "error": "missing api_host/token_file"}))
        return 0
    try:
        with open(token_file) as f:
            token = f.read().strip()
        resp = requests.post(
            f"{api_host}/api/v2/monitor/system/config/backup",
            headers={"Authorization": f"Bearer {token}"},
            params={"scope": "global"},
            verify=False, timeout=30,
        )
        resp.raise_for_status()
        print(json.dumps({
            "config_b64": base64.b64encode(resp.content).decode("ascii"), "error": None,
        }))
    except Exception as exc:
        print(json.dumps({"config_b64": None, "error": str(exc)}))
    return 0


def _run_fortigate_blocklist_action(ctx: dict) -> int:
    fortigate = ctx.get("fortigate") or {}
    api_host = fortigate.get("api_host")
    write_token_file = fortigate.get("write_token_file")
    action = ctx.get("action")
    if not (api_host and write_token_file and action):
        print(json.dumps({"ok": False, "detail": "missing api_host/write_token_file/action"}))
        return 0

    try:
        headers = _fortigate_write_headers(write_token_file)

        if action == "list":
            members = _get_blocklist_members(api_host, headers)
            blocked = [m for m in members if m.startswith(_BLOCK_OBJECT_PREFIX)]
            print(json.dumps({"ok": True, "blocked_ips": [
                m[len(_BLOCK_OBJECT_PREFIX):] for m in blocked
            ]}))
            return 0

        ip = ctx.get("ip", "")
        ok, err = _validate_blockable_ip(ip)
        if not ok:
            print(json.dumps({"ok": False, "detail": err}))
            return 0
        object_name = f"{_BLOCK_OBJECT_PREFIX}{ip}"

        if action == "block":
            exists_resp = requests.get(
                f"{api_host}/api/v2/cmdb/firewall/address/{object_name}",
                headers=headers, verify=False, timeout=15,
            )
            if exists_resp.status_code == 404:
                create_resp = requests.post(
                    f"{api_host}/api/v2/cmdb/firewall/address",
                    headers=headers, verify=False, timeout=15,
                    json={
                        "name": object_name, "type": "ipmask", "subnet": f"{ip}/32",
                        "comment": (ctx.get("comment") or "blocked via !block-ip")[:255],
                    },
                )
                create_resp.raise_for_status()
            elif exists_resp.status_code != 200:
                exists_resp.raise_for_status()

            members = _get_blocklist_members(api_host, headers)
            if object_name in members:
                print(json.dumps({"ok": True, "detail": f"{ip} was already blocked"}))
                return 0
            _set_blocklist_members(api_host, headers, members + [object_name])
            print(json.dumps({"ok": True, "detail": f"{ip} added to {_BLOCKLIST_ADDRGRP}"}))
            return 0

        if action == "unblock":
            members = _get_blocklist_members(api_host, headers)
            if object_name not in members:
                print(json.dumps({"ok": True, "detail": f"{ip} wasn't blocked"}))
                return 0
            _set_blocklist_members(api_host, headers, [m for m in members if m != object_name])
            del_resp = requests.delete(
                f"{api_host}/api/v2/cmdb/firewall/address/{object_name}",
                headers=headers, verify=False, timeout=15,
            )
            del_resp.raise_for_status()
            print(json.dumps({"ok": True, "detail": f"{ip} removed from {_BLOCKLIST_ADDRGRP}"}))
            return 0

        print(json.dumps({"ok": False, "detail": f"unknown action {action!r}"}))
    except requests.RequestException as exc:
        print(json.dumps({"ok": False, "detail": f"FortiGate request failed: {exc}"}))
    except Exception as exc:
        print(json.dumps({"ok": False, "detail": f"{exc}"}))
    return 0


def _run_github_issue_create(ctx: dict) -> int:
    github = ctx.get("github") or {}
    repo = github.get("repo")
    token_file = github.get("issue_token_file")
    title = ctx.get("title", "")
    if not (repo and token_file and title):
        print(json.dumps({"ok": False, "detail": "missing repo/issue_token_file/title"}))
        return 0
    try:
        with open(token_file) as f:
            token = f.read().strip()
        resp = requests.post(
            f"https://api.github.com/repos/{repo}/issues",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
            },
            json={
                "title": title, "body": ctx.get("body", ""),
                "labels": ctx.get("labels") or [],
            },
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json()
        print(json.dumps({
            "ok": True, "issue_number": data["number"],
            "detail": f"created issue #{data['number']}: {data['html_url']}",
        }))
    except requests.RequestException as exc:
        print(json.dumps({"ok": False, "detail": f"GitHub request failed: {exc}"}))
    except Exception as exc:
        print(json.dumps({"ok": False, "detail": f"{exc}"}))
    return 0


def _run_mgmt1_patch_collect(ctx: dict) -> int:
    try:
        proc = subprocess.run(
            ["apt", "list", "--upgradable"], capture_output=True, text=True, timeout=60,
        )
        upgradable = [
            line for line in proc.stdout.splitlines()
            if line and not line.startswith("Listing...")
        ]
        reboot_required = os.path.exists("/var/run/reboot-required")
        reboot_pkgs: list[str] = []
        if reboot_required:
            try:
                with open("/var/run/reboot-required.pkgs") as f:
                    reboot_pkgs = [line.strip() for line in f if line.strip()]
            except OSError:
                pass
        kernel_proc = subprocess.run(["uname", "-r"], capture_output=True, text=True, timeout=10)
        print(json.dumps({
            "ok": True,
            "upgradable_count": len(upgradable),
            "reboot_required": reboot_required,
            "reboot_required_pkgs": reboot_pkgs,
            "kernel_running": kernel_proc.stdout.strip(),
        }))
    except Exception as exc:
        print(json.dumps({"ok": False, "detail": f"{exc}"}))
    return 0


def _run_mgmt1_patch_apply(ctx: dict) -> int:
    command = "sudo apt-get update && sudo apt-get -y full-upgrade"
    ok = False
    out = ""
    attempts = 0
    while attempts < 5:
        try:
            proc = subprocess.run(
                ["bash", "-c", command], capture_output=True, text=True, timeout=1800,
            )
            ok = proc.returncode == 0
            out = proc.stdout + proc.stderr
        except Exception as exc:
            ok = False
            out = str(exc)
        if ok or "Could not get lock" not in out:
            break
        attempts += 1
        time.sleep(90)
    print(json.dumps({"ok": ok, "detail": out.strip()[-4000:]}))
    return 0


def main() -> int:
    raw = sys.stdin.read()
    try:
        ctx = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"investigate_wrapper: bad JSON payload on stdin: {exc}", file=sys.stderr)
        return 1

    mode = ctx.get("mode", "investigate")
    if mode == "network_collect":
        return _run_network_collect(ctx)
    if mode == "wifi_rf_collect":
        return _run_wifi_rf_collect(ctx)
    if mode == "disk_health_collect":
        return _run_disk_health_collect(ctx)
    if mode == "hyperbackup_collect":
        return _run_hyperbackup_collect(ctx)
    if mode == "wg_collect":
        return _run_wg_collect(ctx)
    if mode == "ssh_agent_status":
        return _run_ssh_agent_status(ctx)
    if mode == "ollama_version_check":
        return _run_ollama_version_check(ctx)
    if mode == "ollama_apply_update":
        return _run_ollama_apply_update(ctx)
    if mode == "ollama_chat":
        return _run_ollama_chat(ctx)
    if mode == "ssh_exec":
        return _run_ssh_exec(ctx)
    if mode == "firewall_traffic_collect":
        return _run_firewall_traffic_collect(ctx)
    if mode == "config_archive_collect":
        return _run_config_archive_collect(ctx)
    if mode == "kb_registration_token_update":
        return _run_kb_registration_token_update(ctx)
    if mode == "discourse_backup_pull":
        return _run_discourse_backup_pull(ctx)
    if mode == "discourse_backup_list":
        return _run_discourse_backup_list(ctx)
    if mode == "discourse_backup_push":
        return _run_discourse_backup_push(ctx)
    if mode == "librenms_bandwidth_trend":
        return _run_librenms_bandwidth_trend(ctx)
    if mode == "fortigate_blocklist_action":
        return _run_fortigate_blocklist_action(ctx)
    if mode == "github_issue_create":
        return _run_github_issue_create(ctx)
    if mode == "mgmt1_patch_collect":
        return _run_mgmt1_patch_collect(ctx)
    if mode == "mgmt1_patch_apply":
        return _run_mgmt1_patch_apply(ctx)
    if mode == "fortigate_wan_ip":
        return _run_fortigate_wan_ip(ctx)
    if mode == "fortigate_status":
        return _run_fortigate_status(ctx)
    if mode == "fortigate_config_backup":
        return _run_fortigate_config_backup(ctx)
    if mode == "fortigate_policy_list":
        return _run_fortigate_policy_list(ctx)
    if mode == "fortigate_object_lookup":
        return _run_fortigate_object_lookup(ctx)
    if mode == "security_scan":
        prompt = _build_security_scan_prompt(ctx)
        claude_timeout = 1700
    elif mode == "investigate_finding":
        finding = ctx.get("finding") or {}
        source = finding.get("source")
        if source == "network_monitor":
            prompt = _build_network_finding_prompt(finding, ctx)
        elif source == "ap_flapping":
            prompt = _build_ap_flapping_finding_prompt(finding, ctx)
        elif source == "wireguard":
            prompt = _build_wireguard_finding_prompt(finding, ctx)
        elif source == "ops_health":
            prompt = _build_ops_health_finding_prompt(finding, ctx)
        elif source == "kuma_monitor":
            prompt = _build_kuma_monitor_finding_prompt(finding, ctx)
        elif source == "firewall_traffic":
            prompt = _build_firewall_traffic_finding_prompt(finding, ctx)
        elif source == "config_drift":
            prompt = _build_config_drift_finding_prompt(finding, ctx)
        elif source == "user_report":
            prompt = _build_user_report_finding_prompt(finding, ctx)
        elif source == "disk_health":
            prompt = _build_disk_finding_prompt(finding, ctx)
        elif source == "security_scan":
            prompt = _build_security_scan_finding_prompt(finding, ctx)
        elif source == "kernel_cve":
            prompt = _build_kernel_cve_finding_prompt(finding, ctx)
        elif source == "pass_bot":
            prompt = _build_pass_bot_finding_prompt(finding, ctx)
        else:
            prompt = _build_generic_finding_prompt(finding, ctx)
        prompt += _CODE_FIX_TRAILER
        claude_timeout = 840
    elif mode == "investigate_network_issue":
        prompt = _build_network_issue_prompt(ctx)
        claude_timeout = 840
    elif mode == "investigate_cluster_resources":
        prompt = _build_cluster_resources_prompt(ctx)
        claude_timeout = 840
    else:
        prompt = _build_investigate_prompt(ctx)
        claude_timeout = 840

    proc = subprocess.run(
        ["/home/rbdroot/.local/bin/claude", "-p", prompt,
         "--permission-mode", "plan", "--permission-prompts", "none"],
        capture_output=True, text=True, timeout=claude_timeout,
    )
    if proc.returncode != 0:
        print(f"investigate_wrapper: claude exited {proc.returncode}: {proc.stderr}", file=sys.stderr)
        return proc.returncode
    print(proc.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
