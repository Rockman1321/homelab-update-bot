"""Diun webhook receiver and the public form routes."""
from __future__ import annotations

import hmac
import logging
import re
from collections.abc import Awaitable, Callable

from aiohttp import web

from . import outage_report
from . import wedding_access_request
from .config import ServiceConfig

logger = logging.getLogger(__name__)

_SAFE_TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
_SAFE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9/_.-]*$")


def _split_image_tag(image: str) -> tuple[str, str]:
    ref, _, tag = image.rpartition(":")
    ref = ref.removeprefix("docker.io/").removeprefix("library/")
    return ref, tag


_ACCEPTED_STATUSES = {"new", "update"}


def parse_diun_payload(payload: dict) -> dict | None:
    if payload.get("status") not in _ACCEPTED_STATUSES:
        return None

    image_ref, tag = _split_image_tag(payload.get("image", ""))
    digest = payload.get("digest", "")

    if not _SAFE_IMAGE_RE.match(image_ref) or not _SAFE_TAG_RE.match(tag) or not _SAFE_DIGEST_RE.match(digest):
        logger.warning(
            "diun webhook rejected: image/tag/digest doesn't match expected shape "
            "(image=%r, tag=%r, digest=%r) -- possible malformed sender or injection attempt",
            image_ref, tag, digest,
        )
        return None

    return {
        "image": image_ref,
        "tag": tag,
        "digest": digest,
        "diun_entry_id": f"{image_ref}:{tag}@{digest}",
    }


def match_service(image: str, services: dict[str, ServiceConfig]) -> str | None:
    for name, cfg in services.items():
        if image in cfg.images:
            return name
    return None


def build_app(
    on_new_version: Callable[[dict], Awaitable[None]],
    on_outage_report: Callable[[dict, str], Awaitable[tuple[bool, str]]] | None = None,
    on_wedding_access_request: Callable[[dict, str], Awaitable[tuple[bool, str]]] | None = None,
    *,
    webhook_shared_secret: str = "",
) -> web.Application:
    app = web.Application()

    async def handle_diun(request: web.Request) -> web.Response:
        if webhook_shared_secret:
            provided = request.headers.get("X-Webhook-Secret", "")
            if not hmac.compare_digest(provided, webhook_shared_secret):
                logger.warning("diun webhook rejected: missing/invalid X-Webhook-Secret header")
                return web.json_response({"status": "forbidden"}, status=403)
        else:
            logger.warning(
                "diun webhook has no shared secret configured (DIUN_WEBHOOK_SECRET unset) -- "
                "this endpoint is unauthenticated"
            )

        try:
            payload = await request.json()
        except Exception:
            body = await request.text()
            logger.warning("diun webhook: malformed JSON body: %r", body[:500])
            return web.json_response({"status": "ignored"})

        logger.info("diun webhook received: %r", payload)
        parsed = parse_diun_payload(payload)
        if parsed is None:
            logger.info(
                "diun webhook ignored (status=%r, not in %r): image=%r",
                payload.get("status"), _ACCEPTED_STATUSES, payload.get("image"),
            )
            return web.json_response({"status": "ignored"})
        await on_new_version(parsed)
        return web.json_response({"status": "accepted"})

    app.router.add_post("/webhook/diun", handle_diun)

    if on_outage_report is not None:
        async def handle_report_get(request: web.Request) -> web.Response:
            return web.Response(text=outage_report.render_form_html(), content_type="text/html")

        async def handle_report_post(request: web.Request) -> web.Response:
            form = await request.post()
            forwarded_for = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            client_ip = request.headers.get("Cf-Connecting-Ip") or forwarded_for or request.remote or "unknown"
            ok, message = await on_outage_report(dict(form), client_ip)
            status = 200 if ok else 400
            body = (
                "<!doctype html><html><body style='font-family:system-ui;max-width:480px;"
                "margin:3rem auto;text-align:center'><h2>"
                + ("Thanks — that's been sent." if ok else "Couldn't send that")
                + "</h2><p>" + message + "</p></body></html>"
            )
            return web.Response(text=body, content_type="text/html", status=status)

        app.router.add_get("/report", handle_report_get)
        app.router.add_post("/report", handle_report_post)

    if on_wedding_access_request is not None:
        async def handle_access_request_get(request: web.Request) -> web.Response:
            return web.Response(
                text=wedding_access_request.render_form_html(), content_type="text/html"
            )

        async def handle_access_request_post(request: web.Request) -> web.Response:
            form = await request.post()
            forwarded_for = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            client_ip = request.headers.get("Cf-Connecting-Ip") or forwarded_for or request.remote or "unknown"
            ok, message = await on_wedding_access_request(dict(form), client_ip)
            status = 200 if ok else 400
            return web.Response(
                text=wedding_access_request.render_result_html(ok, message),
                content_type="text/html", status=status,
            )

        app.router.add_get("/wedding-access-request", handle_access_request_get)
        app.router.add_post("/wedding-access-request", handle_access_request_post)

        async def handle_access_request_root(request: web.Request) -> web.Response:
            if request.headers.get("Host", "").split(":", 1)[0].lower() == "access.wedding.example.net":
                raise web.HTTPFound("/wedding-access-request")
            raise web.HTTPNotFound()

        app.router.add_get("/", handle_access_request_root)

    return app
