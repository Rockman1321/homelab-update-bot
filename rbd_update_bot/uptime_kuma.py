"""Toggles an Uptime Kuma maintenance window around an update."""
from __future__ import annotations

import logging
import threading
import time

from uptime_kuma_api import UptimeKumaApi, UptimeKumaException

logger = logging.getLogger(__name__)


class _KumaInfoTimeout(UptimeKumaException):
    pass


class _WebsocketKumaApi(UptimeKumaApi):

    def _event_info(self, data) -> None:
        seen = getattr(self, "_info_seen", None)
        if seen is not None:
            seen.set()
        super()._event_info(data)

    def connect(self) -> None:
        self._info_seen = threading.Event()
        try:
            self.sio.connect(f"{self.url}/socket.io/", wait_timeout=self.timeout,
                             headers=self.headers, transports=["websocket"])
        except Exception:
            raise UptimeKumaException("unable to connect")
        if not self._info_seen.wait(self.timeout):
            try:
                self.sio.disconnect()
            except Exception:
                pass
            raise _KumaInfoTimeout("connected but Kuma never sent info")


def _is_timeout(exc: Exception) -> bool:
    return isinstance(exc, _KumaInfoTimeout) or type(exc).__name__ in ("TimeoutError", "Timeout")


def connect_and_login(base_url: str, username: str, password: str, *, attempts: int = 2) -> UptimeKumaApi:
    for attempt in range(1, attempts + 1):
        api = None
        try:
            api = _WebsocketKumaApi(base_url, timeout=10)
            api.login(username, password)
            return api
        except Exception as exc:
            if api is not None:
                try:
                    api.disconnect()
                except Exception:
                    pass
            if attempt == attempts or not _is_timeout(exc):
                raise
            logger.info("uptime kuma login timed out (attempt %d/%d), retrying", attempt, attempts)
            time.sleep(2)
    raise AssertionError("unreachable")


def _toggle(base_url: str, username: str, password: str, maintenance_id: int, *, turn_on: bool) -> tuple[bool, str]:
    api = None
    try:
        api = connect_and_login(base_url, username, password)
        if turn_on:
            api.resume_maintenance(maintenance_id)
        else:
            api.pause_maintenance(maintenance_id)
        return True, "ok"
    except Exception as exc:
        detail = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
        logger.warning("uptime_kuma toggle (maintenance_id=%s, turn_on=%s) failed: %s",
                        maintenance_id, turn_on, detail)
        return False, detail
    finally:
        if api is not None:
            try:
                api.disconnect()
            except Exception:
                pass


def begin_maintenance(base_url: str, username: str, password: str, maintenance_id: int) -> tuple[bool, str]:
    return _toggle(base_url, username, password, maintenance_id, turn_on=True)


def end_maintenance(base_url: str, username: str, password: str, maintenance_id: int) -> tuple[bool, str]:
    return _toggle(base_url, username, password, maintenance_id, turn_on=False)


def is_maintenance_active(base_url: str, username: str, password: str, maintenance_id: int) -> bool | None:
    api = None
    try:
        api = connect_and_login(base_url, username, password)
        return bool(api.get_maintenance(maintenance_id).get("active"))
    except Exception as exc:
        detail = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
        logger.warning("uptime_kuma is_maintenance_active (maintenance_id=%s) failed: %s", maintenance_id, detail)
        return None
    finally:
        if api is not None:
            try:
                api.disconnect()
            except Exception:
                pass
