"""Falls back to a local Ollama model for light tasks when the Anthropic API is unavailable."""
from __future__ import annotations

import json
import logging
import re
import subprocess
from types import SimpleNamespace

import anthropic

logger = logging.getLogger(__name__)

_settings: dict = {}

_SPEND_CAP_MARKERS = ("usage limit", "spend limit", "credit balance", "billing")
_REGAIN_RE = re.compile(r"regain access on ([^.]+)", re.IGNORECASE)


def configure(*, model: str, mgmt_host: str, mgmt_user: str, identity_file: str = "") -> None:
    _settings.clear()
    if model and mgmt_host and mgmt_user:
        _settings.update(model=model, mgmt_host=mgmt_host, mgmt_user=mgmt_user, identity_file=identity_file)


def enabled() -> bool:
    return bool(_settings)


def unavailable_reason(exc: BaseException) -> str | None:
    if isinstance(exc, anthropic.APIConnectionError):
        return "outage"
    if isinstance(exc, anthropic.APIStatusError):
        text = str(exc).lower()
        if any(m in text for m in _SPEND_CAP_MARKERS):
            return "spend_cap"
        if exc.status_code in (401, 403, 429) or exc.status_code >= 500:
            return "outage"
    return None


def _notice(reason: str, detail: str) -> str:
    model = _settings.get("model", "local model")
    if reason == "spend_cap":
        m = _REGAIN_RE.search(detail or "")
        when = f" (Anthropic says access returns {m.group(1).strip()})" if m else ""
        return (f"[Local model: {model}] The Anthropic API spend limit has been reached{when}, so this "
                "was written by the local model and is less thorough than usual. Update risk checks and "
                "security research are paused. Full functionality comes back with a credit bump or when "
                "the limit resets next month.")
    return (f"[Local model: {model}] The Anthropic API is unreachable right now, so this was written by "
            "the local model and is less thorough than usual. Full functionality comes back once the "
            "API is available again.")


def notice_for(message) -> str:
    return getattr(message, "local_fallback_notice", "") or ""


def _text_of(content) -> str:
    if isinstance(content, str):
        return content
    return "\n".join(b.get("text", "") if isinstance(b, dict) else getattr(b, "text", "") for b in content or [])


_PROMPT_CHAR_BUDGET = 20_000
_TRIM_MARK = "\n[...trimmed for the local model]"


def _fit_sections(text: str, budget: int) -> str:
    if len(text) <= budget:
        return text
    sections = text.split("\n\n")
    alloc = [0] * len(sections)
    remaining, open_idx = budget, sorted(range(len(sections)), key=lambda i: len(sections[i]))
    while open_idx:
        share = remaining // len(open_idx)
        i = open_idx[0]
        if len(sections[i]) <= share:
            alloc[i] = len(sections[i]); remaining -= alloc[i]; open_idx.pop(0)
        else:
            for j in open_idx:
                alloc[j] = share
            break
    return "\n\n".join(sec if len(sec) <= a else sec[:max(a - len(_TRIM_MARK), 0)].rstrip() + _TRIM_MARK
                        for sec, a in zip(sections, alloc))


def _relay(chat: dict, timeout: float) -> dict:
    ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes"]
    if _settings.get("identity_file"):
        ssh_cmd += ["-i", _settings["identity_file"]]
    ssh_cmd += [f"{_settings['mgmt_user']}@{_settings['mgmt_host']}", "true"]
    proc = subprocess.run(ssh_cmd, input=json.dumps({"mode": "ollama_chat", "chat": chat}),
                          capture_output=True, text=True, timeout=timeout + 60)
    try:
        result = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"local model relay failed: {(proc.stderr or proc.stdout).strip()[:300]}") from exc
    if not result.get("ok"):
        raise RuntimeError("local model: " + "; ".join(result.get("errors") or ["unknown error"]))
    return result


def create_message(*, reason: str, detail: str = "", system=None, messages=None, tools=None,
                   tool_choice=None, **_ignored):
    if not enabled():
        raise RuntimeError("local model fallback is not configured")
    chat_messages = []
    if system:
        chat_messages.append({"role": "system", "content": _text_of(system)})
    for m in messages or []:
        chat_messages.append({"role": "user", "content": _text_of(m.get("content"))})

    sys_chars = len(chat_messages[0]["content"]) if system else 0
    chat_messages[-1]["content"] = _fit_sections(chat_messages[-1]["content"],
                                                 max(_PROMPT_CHAR_BUDGET - sys_chars, 4000))

    tool = None
    if tool_choice and tool_choice.get("type") == "tool":
        tool = next((t for t in tools or [] if t.get("name") == tool_choice.get("name")), None)
        if tool is None:
            raise RuntimeError(f"local model: forced tool {tool_choice.get('name')!r} not in tools")
        chat_messages[-1]["content"] += (
            "\n\nRespond only with a JSON object matching this schema:\n"
            + json.dumps(tool["input_schema"])
        )

    chars = sum(len(m["content"]) for m in chat_messages)
    est_prompt = chars // 3 + 200
    num_ctx = min(32768, max(4096, -(-(est_prompt + 2048) // 4096) * 4096))
    timeout = min(900.0, 90.0 + est_prompt / 30 + (1500 if tool is None else 400) / 8)
    chat = {"model": _settings["model"], "messages": chat_messages, "num_ctx": num_ctx, "timeout": timeout}
    if tool is not None:
        chat["format"] = tool["input_schema"]

    result = _relay(chat, timeout)
    content = (result.get("content") or "").strip()
    logger.info("local model answered (%s): %s prompt / %s output tokens in %ss", reason,
                result.get("prompt_tokens"), result.get("output_tokens"), result.get("seconds"))
    if tool is not None:
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"local model returned non-JSON for {tool['name']}: {content[:200]}") from exc
        missing = [k for k in tool["input_schema"].get("required", []) if k not in data]
        if missing:
            raise RuntimeError(f"local model output missing {missing} for {tool['name']}")
        block = SimpleNamespace(type="tool_use", name=tool["name"], input=data)
    else:
        if not content:
            raise RuntimeError("local model returned no text")
        block = SimpleNamespace(type="text", text=content)
    return SimpleNamespace(
        content=[block], stop_reason="tool_use" if tool is not None else "end_turn",
        model=result.get("model") or _settings["model"],
        local_fallback_notice=_notice(reason, detail),
    )
