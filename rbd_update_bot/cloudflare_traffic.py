"""Cloudflare zone traffic and Tunnel connector health monitor."""
from __future__ import annotations

import requests

_GRAPHQL_URL = "https://api.cloudflare.com/client/v4/graphql"
_API_BASE = "https://api.cloudflare.com/client/v4"

_5XX_RATE_WARN_THRESHOLD = 0.05

_KNOWN_PATHS_BY_HOST: dict[str, list[str]] = {
    "example.com": ["/.well-known/matrix/server", "/.well-known/matrix/client"],
}

_HOSTNAME_TO_SERVICE: dict[str, str] = {
    "nextcloud.example.com": "nextcloud",
    "immich.example.com": "immich",
    "joplin.example.com": "joplin",
    "matrix.example.com": "matrix",
}

_TRAFFIC_QUERY = """
query($zoneTag: String!, $since: Time!, $until: Time!) {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      byHost: httpRequestsAdaptiveGroups(
        limit: 1000,
        filter: {datetime_geq: $since, datetime_leq: $until, requestSource: "eyeball"}
      ) {
        count
        dimensions { clientRequestHTTPHost clientCountryName edgeResponseStatus }
      }
    }
  }
}
"""


def _headers(api_token: str) -> dict:
    return {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}


def collect_hostname_traffic(
    api_token: str, zone_id: str, hostnames: list[str], since_iso: str, until_iso: str,
) -> tuple[dict, str | None]:
    try:
        resp = requests.post(
            _GRAPHQL_URL, headers=_headers(api_token), timeout=20,
            json={
                "query": _TRAFFIC_QUERY,
                "variables": {"zoneTag": zone_id, "since": since_iso, "until": until_iso},
            },
        )
        resp.raise_for_status()
        body = resp.json()
        if body.get("errors"):
            return {}, f"GraphQL errors: {body['errors']}"
        groups = body["data"]["viewer"]["zones"][0]["byHost"]
    except requests.RequestException as exc:
        return {}, f"Cloudflare traffic request failed: {exc}"
    except (KeyError, IndexError, TypeError) as exc:
        return {}, f"unexpected Cloudflare traffic response shape: {exc}"

    per_host: dict[str, dict] = {h: {"total": 0, "status_5xx": 0, "countries": {}} for h in hostnames}
    for g in groups:
        dims = g.get("dimensions", {})
        host = (dims.get("clientRequestHTTPHost") or "").split(":")[0]
        if host not in per_host:
            continue
        count = g.get("count", 0)
        status = dims.get("edgeResponseStatus") or 0
        country = dims.get("clientCountryName") or "XX"
        per_host[host]["total"] += count
        if 500 <= status < 600:
            per_host[host]["status_5xx"] += count
        per_host[host]["countries"][country] = per_host[host]["countries"].get(country, 0) + count

    return per_host, None


_KNOWN_PATH_QUERY = """
query($zoneTag: String!, $since: Time!, $until: Time!, $host: String!) {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      byPath: httpRequestsAdaptiveGroups(
        limit: 100,
        filter: {
          datetime_geq: $since, datetime_leq: $until, clientRequestHTTPHost: $host,
          requestSource: "eyeball"
        }
      ) {
        count
        dimensions { clientRequestPath edgeResponseStatus }
      }
    }
  }
}
"""


def collect_known_path_health(
    api_token: str, zone_id: str, host: str, paths: list[str], since_iso: str, until_iso: str,
) -> tuple[dict, str | None]:
    try:
        resp = requests.post(
            _GRAPHQL_URL, headers=_headers(api_token), timeout=20,
            json={
                "query": _KNOWN_PATH_QUERY,
                "variables": {"zoneTag": zone_id, "since": since_iso, "until": until_iso, "host": host},
            },
        )
        resp.raise_for_status()
        body = resp.json()
        if body.get("errors"):
            return {}, f"GraphQL errors: {body['errors']}"
        groups = body["data"]["viewer"]["zones"][0]["byPath"]
    except requests.RequestException as exc:
        return {}, f"Cloudflare known-path request failed: {exc}"
    except (KeyError, IndexError, TypeError) as exc:
        return {}, f"unexpected Cloudflare known-path response shape: {exc}"

    per_path: dict[str, dict] = {p: {"total": 0, "status_5xx": 0} for p in paths}
    for g in groups:
        path = g.get("dimensions", {}).get("clientRequestPath") or ""
        if path not in per_path:
            continue
        count = g.get("count", 0)
        status = g.get("dimensions", {}).get("edgeResponseStatus") or 0
        per_path[path]["total"] += count
        if 500 <= status < 600:
            per_path[path]["status_5xx"] += count

    return per_path, None


def collect_tunnel_health(api_token: str, account_id: str, tunnel_ids: dict[str, str]) -> tuple[dict, list[str]]:
    headers = _headers(api_token)
    result: dict[str, dict] = {}
    errors: list[str] = []
    for service_name, tunnel_id in tunnel_ids.items():
        try:
            resp = requests.get(
                f"{_API_BASE}/accounts/{account_id}/cfd_tunnel/{tunnel_id}/connections",
                headers=headers, timeout=15,
            )
            resp.raise_for_status()
            body = resp.json()
            if not body.get("success"):
                errors.append(f"{service_name}: {body.get('errors')}")
                continue
            connectors = body.get("result") or []
            total_conns = sum(len(c.get("conns", [])) for c in connectors)
            versions = sorted({c["version"] for c in connectors if c.get("version")})
            result[service_name] = {
                "connector_count": len(connectors), "connection_count": total_conns, "versions": versions,
            }
        except requests.RequestException as exc:
            errors.append(f"{service_name}: {exc}")
    return result, errors


def _parse_cloudflared_version(v: str) -> tuple[int, ...] | None:
    try:
        return tuple(int(p) for p in v.split("."))
    except (ValueError, AttributeError):
        return None


def get_latest_cloudflared_version() -> tuple[str | None, str | None]:
    try:
        resp = requests.get(
            "https://api.github.com/repos/cloudflare/cloudflared/releases/latest", timeout=15,
        )
        resp.raise_for_status()
        tag = resp.json().get("tag_name")
        return (tag, None) if tag else (None, "no tag_name in response")
    except requests.RequestException as exc:
        return None, str(exc)


_SECURITY_EVENTS_QUERY = """
query($zoneTag: String!, $since: Time!, $until: Time!) {
  viewer {
    zones(filter: {zoneTag: $zoneTag}) {
      firewallEventsAdaptive(
        limit: 1000, filter: {datetime_geq: $since, datetime_leq: $until}
      ) {
        action
        clientRequestHTTPHost
        clientRequestPath
        clientCountryName
        source
      }
    }
  }
}
"""


def collect_security_events(
    api_token: str, zone_id: str, hostnames: list[str], since_iso: str, until_iso: str,
) -> tuple[dict, str | None]:
    try:
        resp = requests.post(
            _GRAPHQL_URL, headers=_headers(api_token), timeout=20,
            json={
                "query": _SECURITY_EVENTS_QUERY,
                "variables": {"zoneTag": zone_id, "since": since_iso, "until": until_iso},
            },
        )
        resp.raise_for_status()
        body = resp.json()
        if body.get("errors"):
            return {}, f"GraphQL errors: {body['errors']}"
        events = body["data"]["viewer"]["zones"][0]["firewallEventsAdaptive"]
    except requests.RequestException as exc:
        return {}, f"Cloudflare security events request failed: {exc}"
    except (KeyError, IndexError, TypeError) as exc:
        return {}, f"unexpected Cloudflare security events response shape: {exc}"

    per_host: dict[str, dict] = {h: {"total": 0, "actions": {}, "countries": {}, "sample_paths": []} for h in hostnames}
    for e in events:
        host = (e.get("clientRequestHTTPHost") or "").split(":")[0]
        if host not in per_host:
            continue
        action = e.get("action") or "unknown"
        country = e.get("clientCountryName") or "XX"
        per_host[host]["total"] += 1
        per_host[host]["actions"][action] = per_host[host]["actions"].get(action, 0) + 1
        per_host[host]["countries"][country] = per_host[host]["countries"].get(country, 0) + 1
        if len(per_host[host]["sample_paths"]) < 10:
            path = e.get("clientRequestPath")
            if path and path not in per_host[host]["sample_paths"]:
                per_host[host]["sample_paths"].append(path)

    return per_host, None


def build_checks(
    traffic: dict,
    tunnel_health: dict,
    known_path_health: dict | None = None,
    security_events: dict | None = None,
    recent_activity: dict[str, bool] | None = None,
    latest_cloudflared_version: str | None = None,
) -> list[dict]:
    known_path_health = known_path_health or {}
    recent_activity = recent_activity or {}
    checks: list[dict] = []

    for hostname, data in traffic.items():
        total = data["total"]
        checks.append({
            "check_id": f"cf_traffic_volume:{hostname}",
            "source": "cloudflare_traffic",
            "status": f"{total} request(s) this interval",
            "detail": f"{hostname}: {total} request(s)",
            "raw_detail": {"hostname": hostname, "total": total, "countries": data["countries"]},
            "is_bad": False,
        })

        service_name = _HOSTNAME_TO_SERVICE.get(hostname)
        was_active = bool(service_name and recent_activity.get(service_name))

        if hostname in known_path_health:
            for path, path_data in known_path_health[hostname].items():
                p_total = path_data["total"]
                p_rate = (path_data["status_5xx"] / p_total) if p_total else 0
                is_bad = p_total > 0 and p_rate > _5XX_RATE_WARN_THRESHOLD
                detail = f"{hostname}{path}: {p_rate:.1%} of {p_total} request(s) returned a 5xx error"
                if is_bad and was_active:
                    detail += f" -- but {service_name} had a bot-driven update active during this window, not alerting"
                    is_bad = False
                checks.append({
                    "check_id": f"cf_known_path_health:{hostname}{path}",
                    "source": "cloudflare_traffic",
                    "status": f"{path_data['status_5xx']}/{p_total} request(s) to {path} returned 5xx",
                    "detail": detail,
                    "raw_detail": {"hostname": hostname, "path": path, "update_active": was_active, **path_data},
                    "is_bad": is_bad,
                })
        else:
            rate_5xx = (data["status_5xx"] / total) if total else 0
            is_bad = total > 0 and rate_5xx > _5XX_RATE_WARN_THRESHOLD
            detail = f"{hostname}: {rate_5xx:.1%} of {total} request(s) returned a 5xx error"
            if is_bad and was_active:
                detail += f" -- but {service_name} had a bot-driven update active during this window, not alerting"
                is_bad = False
            checks.append({
                "check_id": f"cf_5xx_rate:{hostname}",
                "source": "cloudflare_traffic",
                "status": f"{data['status_5xx']}/{total} request(s) returned 5xx this interval",
                "detail": detail,
                "raw_detail": {
                    "hostname": hostname, "status_5xx": data["status_5xx"], "total": total,
                    "update_active": was_active,
                },
                "is_bad": is_bad,
            })

        non_us = {c: n for c, n in data["countries"].items() if c not in ("US", "XX")}
        checks.append({
            "check_id": f"cf_exposure_geo:{hostname}",
            "source": "cloudflare_traffic",
            "status": (
                f"{sum(non_us.values())} non-US request(s) this interval" if non_us
                else "all requests US-sourced"
            ),
            "detail": f"{hostname}: {non_us if non_us else 'no non-US traffic'}",
            "raw_detail": {"hostname": hostname, "non_us_countries": non_us},
            "is_bad": False,
        })

        if security_events and hostname in security_events:
            sec = security_events[hostname]
            checks.append({
                "check_id": f"cf_security_events:{hostname}",
                "source": "cloudflare_traffic",
                "status": f"{sec['total']} WAF/firewall event(s) this interval",
                "detail": (
                    f"{hostname}: {sec['total']} event(s), actions={sec['actions']}, "
                    f"top countries={dict(sorted(sec['countries'].items(), key=lambda kv: -kv[1])[:5])}, "
                    f"sample paths={sec['sample_paths']}"
                ),
                "raw_detail": {"hostname": hostname, **sec},
                "is_bad": False,
            })

    for service_name, health in tunnel_health.items():
        down = health["connector_count"] == 0 or health["connection_count"] == 0
        was_active = bool(recent_activity.get(service_name))
        detail = (
            f"{service_name}'s Tunnel: {health['connector_count']} connector(s), "
            f"{health['connection_count']} connection(s)"
        )
        if down and was_active:
            detail += " -- but a bot-driven update was active during this window (e.g. a reboot bouncing the connector), not alerting"
            down = False
        checks.append({
            "check_id": f"cf_tunnel_health:{service_name}",
            "source": "cloudflare_traffic",
            "status": f"{health['connector_count']} connector(s), {health['connection_count']} connection(s)",
            "detail": detail,
            "raw_detail": {**health, "update_active": was_active},
            "is_bad": down,
        })

        if latest_cloudflared_version is not None:
            versions = health.get("versions") or []
            latest_parsed = _parse_cloudflared_version(latest_cloudflared_version)
            parsed = [(_parse_cloudflared_version(v), v) for v in versions]
            parsed = [(p, v) for p, v in parsed if p is not None]
            if parsed and latest_parsed is not None:
                oldest_parsed, oldest_str = min(parsed)
                behind = oldest_parsed < latest_parsed
                status = (
                    oldest_str if not behind
                    else f"{oldest_str} (latest: {latest_cloudflared_version})"
                )
                detail = f"{service_name}'s cloudflared connector is on {oldest_str}"
                if behind:
                    detail += f", behind the latest release ({latest_cloudflared_version})"
                if len(versions) > 1:
                    detail += f" -- mixed versions across connectors: {versions}"
                checks.append({
                    "check_id": f"cf_cloudflared_version:{service_name}",
                    "source": "cloudflare_traffic",
                    "status": status,
                    "detail": detail,
                    "raw_detail": {"service": service_name, "versions": versions, "latest": latest_cloudflared_version},
                    "is_bad": behind,
                })

    return checks
