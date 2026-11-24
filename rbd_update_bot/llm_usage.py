"""Logs token use and estimated cost for every Anthropic API call, by feature."""
from __future__ import annotations

import logging
import sys

logger = logging.getLogger(__name__)

_PRICES: dict[str, tuple[float, float, float, float, float]] = {
    "claude-sonnet-5-5": (2.00, 10.00, 2.50, 4.00, 0.10),
    "claude-sonnet-5": (2.00, 10.00, 2.50, 4.00, 0.20),
    "claude-opus-5-5": (4.00, 20.00, 5.00, 8.00, 0.20),
    "claude-haiku-5-5": (0.10, 0.50, 0.125, 0.20, 0.01),
}
_HAIKU_LONG = (0.50, 2.50, 0.625, 1.00, 0.05)
_WEB_SEARCH_USD = 10.0 / 1000

_warned_models: set[str] = set()


def _price_for(model: str, prompt_tokens: int) -> tuple[float, ...] | None:
    for key in sorted(_PRICES, key=len, reverse=True):
        if model == key or model.startswith(key + "-"):
            if key == "claude-haiku-5-5" and prompt_tokens > 100_000:
                return _HAIKU_LONG
            return _PRICES[key]
    return None


def usage_row(model: str, usage, feature: str) -> dict:
    g = lambda obj, name: int(getattr(obj, name, 0) or 0)
    inp, out = g(usage, "input_tokens"), g(usage, "output_tokens")
    cw, cr = g(usage, "cache_creation_input_tokens"), g(usage, "cache_read_input_tokens")
    cache_creation = getattr(usage, "cache_creation", None)
    cw_1h = g(cache_creation, "ephemeral_1h_input_tokens") if cache_creation else 0
    stu = getattr(usage, "server_tool_use", None)
    searches = g(stu, "web_search_requests") if stu else 0

    price = _price_for(model, inp + cw + cr)
    if price is None:
        if model not in _warned_models:
            _warned_models.add(model)
            logger.warning("llm_usage: no price for model %r -- logging tokens with cost 0", model)
        cost = searches * _WEB_SEARCH_USD
    else:
        p_in, p_out, p_cw5, p_cw1h, p_cr = price
        cost = (inp * p_in + out * p_out + (cw - cw_1h) * p_cw5 + cw_1h * p_cw1h + cr * p_cr) / 1e6
        cost += searches * _WEB_SEARCH_USD
    return {
        "feature": feature, "model": model, "input_tokens": inp, "output_tokens": out,
        "cache_write_tokens": cw, "cache_read_tokens": cr, "web_searches": searches,
        "cost_usd": round(cost, 6),
    }


def _caller_feature() -> str:
    frame = sys._getframe(2)
    while frame is not None:
        mod = frame.f_globals.get("__name__", "")
        if mod.startswith("rbd_update_bot.") and mod != __name__:
            return f"{mod.rsplit('.', 1)[-1]}.{frame.f_code.co_name}"
        frame = frame.f_back
    return "unknown"


def install(client, store) -> None:
    messages = client.messages
    if getattr(messages.create, "_llm_usage_wrapped", False):
        return
    original = messages.create

    def create(*args, **kwargs):
        feature = _caller_feature()
        response = original(*args, **kwargs)
        try:
            model = getattr(response, "model", None) or kwargs.get("model", "unknown")
            store.record_llm_usage(usage_row(model, response.usage, feature))
        except Exception:
            logger.exception("llm_usage: failed to record usage for %s", feature)
        return response

    create._llm_usage_wrapped = True
    messages.create = create
