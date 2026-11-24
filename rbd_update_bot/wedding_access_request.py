'Public "request access" form for the wedding planning app.'
from __future__ import annotations

import html
import time

_MIN_FILL_SECONDS = 3.0
_MAX_REASON_LEN = 500
_MAX_NAME_LEN = 120


def render_form_html() -> str:
    now = time.time()
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Request access — Wedding Planning</title>
<style>
  body {{ font-family: system-ui, -apple-system, 'Segoe UI', sans-serif; max-width: 480px;
         margin: 2.5rem auto; padding: 0 1.25rem; color: #1a1a1a; background: #fafafa; }}
  h1 {{ font-size: 1.4rem; margin-bottom: 0.25rem; }}
  p.sub {{ color: #666; margin-top: 0; margin-bottom: 1.5rem; }}
  label {{ display: block; font-weight: 600; margin: 1rem 0 0.3rem; }}
  textarea, input[type=text], input[type=email] {{
    width: 100%; box-sizing: border-box; padding: 0.55rem; font-size: 1rem;
    border: 1px solid #ccc; border-radius: 6px; font-family: inherit;
  }}
  textarea {{ min-height: 90px; resize: vertical; }}
  button {{ margin-top: 1.25rem; padding: 0.65rem 1.4rem; font-size: 1rem; font-weight: 600;
            border: none; border-radius: 6px; background: #2563eb; color: white; cursor: pointer; }}
  button:hover {{ background: #1d4ed8; }}
  .honeypot {{ position: absolute; left: -9999px; top: -9999px; }}
  .note {{ font-size: 0.85rem; color: #888; margin-top: 1.5rem; }}
</style>
</head>
<body>
  <h1>Request access</h1>
  <p class="sub">The Wedding Planning App is where we're
  tracking venues, the guest list, seating, and the rest of the details
  for the wedding. If you're family or part of the wedding party and
  need to get in, tell us who you are below and we'll take a look.</p>
  <form method="post" action="/wedding-access-request">
    <label for="name">Your name</label>
    <input type="text" id="name" name="name" required maxlength="{_MAX_NAME_LEN}">
    <label for="email">Your email</label>
    <input type="email" id="email" name="email" required maxlength="200">
    <label for="reason">Why do you need access?</label>
    <textarea id="reason" name="reason" required maxlength="{_MAX_REASON_LEN}"
      placeholder="e.g. I'm in the wedding party, I'm a parent, I'm helping coordinate..."></textarea>
    <input class="honeypot" type="text" name="website" tabindex="-1" autocomplete="off">
    <input type="hidden" name="rendered_at" value="{now}">
    <button type="submit">Send request</button>
  </form>
  <p class="note">Usually reviewed within a day. We'll reach out directly
  once you're in — bookmark this page if you ever need to request again
  (e.g. access expires or you're on a new device).</p>
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

    name = (form.get("name") or "").strip()
    if not name:
        return False, "Name can't be empty."
    if len(name) > _MAX_NAME_LEN:
        return False, "That name is too long."

    email = (form.get("email") or "").strip()
    if "@" not in email or "." not in email.split("@", 1)[-1]:
        return False, "That doesn't look like a valid email."

    reason = (form.get("reason") or "").strip()
    if not reason:
        return False, "Tell us why you need access."
    if len(reason) > _MAX_REASON_LEN:
        return False, "That's too long -- keep it brief."

    return True, ""


def render_result_html(ok: bool, message: str) -> str:
    return (
        "<!doctype html><html><body style='font-family:system-ui;max-width:480px;"
        "margin:3rem auto;text-align:center'><h2>"
        + ("Thanks — that's been sent." if ok else "Couldn't send that")
        + "</h2><p>" + html.escape(message) + "</p></body></html>"
    )
