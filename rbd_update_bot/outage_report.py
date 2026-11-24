'Public "something\'s not working" report form.'
from __future__ import annotations

import html
import time

SERVICES = [
    "Immich", "Nextcloud", "Joplin", "Matrix / Element", "Discourse",
    "Enshrouded", "StarRupture", "TeamSpeak", "Something else",
]

SYMPTOMS: dict[str, list[str]] = {
    "Immich": [
        "Can't log in", "Can't upload photos/videos", "Some photos/videos missing",
        "All photos/videos missing", "Search isn't working", "Performance is slow",
        "Crashed, currently down", "Crashed, back up now", "Other",
    ],
    "Nextcloud": [
        "Can't log in", "Files aren't syncing", "Some files missing", "All files missing",
        "Calendar/contacts not syncing", "Performance is slow",
        "Crashed, currently down", "Crashed, back up now", "Other",
    ],
    "Joplin": [
        "Can't log in", "Notes aren't syncing", "Some notes missing", "All notes missing",
        "Performance is slow", "Crashed, currently down", "Crashed, back up now", "Other",
    ],
    "Matrix / Element": [
        "Can't log in", "Can't register a new account", "Can't verify a new device",
        "Element call isn't working", "Can't send/receive messages", "Performance is slow",
        "Crashed, currently down", "Crashed, back up now", "Other",
    ],
    "Discourse": [
        "Can't log in", "Can't register a new account", "Posts/replies aren't showing up",
        "Notifications aren't working", "Performance is slow",
        "Crashed, currently down", "Crashed, back up now", "Other",
    ],
    "Enshrouded": [
        "Can't connect to the server", "Game crashes after joining",
        "World/progress data missing or reset", "Performance/lag",
        "Crashed, currently down", "Crashed, back up now", "Other",
    ],
    "StarRupture": [
        "Can't connect to the server", "Game crashes after joining",
        "World/progress data missing or reset", "Performance/lag",
        "Crashed, currently down", "Crashed, back up now", "Other",
    ],
    "TeamSpeak": [
        "Can't connect to the server", "Connected but no audio", "Performance/lag",
        "Crashed, currently down", "Crashed, back up now", "Other",
    ],
    "Something else": [
        "Can't log in", "Some data missing", "All data missing", "Performance is slow",
        "Crashed, currently down", "Crashed, back up now", "Other",
    ],
}

CRITICAL_SYMPTOM = "Crashed, currently down"

_MIN_FILL_SECONDS = 3.0
_MAX_DESCRIPTION_LEN = 2000


def render_form_html() -> str:
    now = time.time()
    options = "\n".join(f'<option value="{html.escape(s)}">{html.escape(s)}</option>' for s in SERVICES)

    symptom_blocks = []
    for service in SERVICES:
        slug = html.escape(service.lower().replace(" / ", "-").replace(" ", "-"))
        symptom_options = "\n".join(
            f'<option value="{html.escape(s)}">{html.escape(s)}</option>' for s in SYMPTOMS[service]
        )
        symptom_blocks.append(
            f'<div class="symptom-block" data-service="{html.escape(service)}" id="symptom-block-{slug}">\n'
            f'  <select name="symptom" aria-label="What\'s going on with {html.escape(service)}?">\n'
            f'    {symptom_options}\n'
            f'  </select>\n'
            f'</div>'
        )
    symptom_html = "\n".join(symptom_blocks)

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Report an issue — Homelab</title>
<style>
  body {{ font-family: system-ui, -apple-system, 'Segoe UI', sans-serif; max-width: 520px;
         margin: 2.5rem auto; padding: 0 1.25rem; color: #1a1a1a; background: #fafafa; }}
  h1 {{ font-size: 1.4rem; margin-bottom: 0.25rem; }}
  p.sub {{ color: #666; margin-top: 0; margin-bottom: 1.5rem; }}
  label {{ display: block; font-weight: 600; margin: 1rem 0 0.3rem; }}
  select, textarea, input[type=text] {{
    width: 100%; box-sizing: border-box; padding: 0.55rem; font-size: 1rem;
    border: 1px solid #ccc; border-radius: 6px; font-family: inherit;
  }}
  textarea {{ min-height: 110px; resize: vertical; }}
  button {{ margin-top: 1.25rem; padding: 0.65rem 1.4rem; font-size: 1rem; font-weight: 600;
            border: none; border-radius: 6px; background: #2563eb; color: white; cursor: pointer; }}
  button:hover {{ background: #1d4ed8; }}
  .honeypot {{ position: absolute; left: -9999px; top: -9999px; }}
  .note {{ font-size: 0.85rem; color: #888; margin-top: 1.5rem; }}
  .symptom-block[hidden] {{ display: none; }}
</style>
</head>
<body>
  <h1>Something not working?</h1>
  <p class="sub">If a service looks up but isn't behaving right — missing
  data, stuck, broken — this goes straight to the person running it.</p>
  <form method="post" action="/report">
    <label for="service">Which service?</label>
    <select id="service" name="service" required onchange="rbdShowSymptoms(this.value)">
      {options}
    </select>
    <label>What's going on?</label>
    {symptom_html}
    <label for="description">Any more detail?</label>
    <textarea id="description" name="description" required maxlength="{_MAX_DESCRIPTION_LEN}"
      placeholder="Whatever else seems relevant — when it started, what you tried, etc."></textarea>
    <label for="reporter">Your name (optional)</label>
    <input type="text" id="reporter" name="reporter" maxlength="80">
    <input class="honeypot" type="text" name="website" tabindex="-1" autocomplete="off">
    <input type="hidden" name="rendered_at" value="{now}">
    <button type="submit">Send report</button>
  </form>
  <p class="note">This isn't a live chat — nobody's necessarily watching
  right now, but it'll be seen.</p>
  <script>
    function rbdShowSymptoms(service) {{
      document.querySelectorAll('.symptom-block').forEach(function (block) {{
        var active = block.dataset.service === service;
        block.hidden = !active;
        block.querySelector('select').disabled = !active;
      }});
    }}
    rbdShowSymptoms(document.getElementById('service').value);
  </script>
</body>
</html>"""


def validate_submission(form: dict) -> tuple[bool, str]:
    if (form.get("website") or "").strip():
        return False, "Something went wrong submitting that -- try again."

    try:
        rendered_at = float(form.get("rendered_at", "0"))
    except ValueError:
        return False, "Something went wrong submitting that -- try again."
    if time.time() - rendered_at < _MIN_FILL_SECONDS:
        return False, "Something went wrong submitting that -- try again."

    service = (form.get("service") or "").strip()
    if service not in SERVICES:
        return False, "Pick a service from the list."

    description = (form.get("description") or "").strip()
    if not description:
        return False, "Description can't be empty."
    if len(description) > _MAX_DESCRIPTION_LEN:
        return False, "That description is too long."

    return True, ""


def resolve_symptom(form: dict, service: str) -> str:
    symptom = (form.get("symptom") or "").strip()
    if symptom in SYMPTOMS.get(service, ()):
        return symptom
    return "Other"
