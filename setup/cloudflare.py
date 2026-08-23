"""Cloudflare API helpers for DNS record management."""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
import json
from dataclasses import dataclass

API_BASE = "https://api.cloudflare.com/client/v4"


@dataclass
class CloudflareConfig:
    api_token: str
    zone_name: str = ""
    zone_id: str = ""
    proxied: bool = False


class CloudflareError(Exception):
    pass


def _request(cfg: CloudflareConfig, method: str, path: str, body: dict | None = None) -> dict:
    url = f"{API_BASE}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {cfg.api_token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise CloudflareError(f"Cloudflare API HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise CloudflareError(f"Cloudflare API unreachable: {exc.reason}") from exc

    if not payload.get("success"):
        errors = payload.get("errors") or payload
        raise CloudflareError(f"Cloudflare API error: {errors}")
    return payload


def verify_token(cfg: CloudflareConfig) -> tuple[bool, str]:
    try:
        result = _request(cfg, "GET", "/user/tokens/verify")
        status = result.get("result", {}).get("status")
        if status == "active":
            return True, "Cloudflare API token is valid."
        return False, f"Token status: {status}"
    except CloudflareError as exc:
        return False, str(exc)


def resolve_zone_id(cfg: CloudflareConfig) -> str:
    if cfg.zone_id:
        return cfg.zone_id
    if not cfg.zone_name:
        raise CloudflareError("Cloudflare zone name or zone ID is required.")

    name = cfg.zone_name.strip().lower().rstrip(".")
    result = _request(cfg, "GET", f"/zones?name={urllib.parse.quote(name)}")
    zones = result.get("result") or []
    if not zones:
        raise CloudflareError(f"No Cloudflare zone found for '{name}'.")
    return zones[0]["id"]


def _record_name(zone_name: str, hostname: str) -> str:
    zone = zone_name.strip().lower().rstrip(".")
    host = hostname.strip().lower().rstrip(".")
    if host == zone:
        return zone
    if host.endswith(f".{zone}"):
        return host[: -(len(zone) + 1)]
    return host


def upsert_a_record(cfg: CloudflareConfig, zone_id: str, hostname: str, ip: str, proxied: bool | None = None) -> str:
    zone_name = cfg.zone_name.strip().lower().rstrip(".")
    record_name = _record_name(zone_name, hostname)
    use_proxied = cfg.proxied if proxied is None else proxied

    existing = _request(
        cfg,
        "GET",
        f"/zones/{zone_id}/dns_records?type=A&name={urllib.parse.quote(record_name)}",
    )
    records = existing.get("result") or []
    body = {
        "type": "A",
        "name": record_name,
        "content": ip,
        "ttl": 1,
        "proxied": use_proxied,
    }

    if records:
        record_id = records[0]["id"]
        _request(cfg, "PUT", f"/zones/{zone_id}/dns_records/{record_id}", body)
        return f"Updated A record {record_name}.{zone_name} → {ip} (proxied={use_proxied})"

    _request(cfg, "POST", f"/zones/{zone_id}/dns_records", body)
    return f"Created A record {record_name}.{zone_name} → {ip} (proxied={use_proxied})"


def setup_deployment_dns(cfg: CloudflareConfig, vps_ip: str, hostnames: list[str], log) -> list[str]:
    """Create/update A records for deployment hostnames. Returns log messages."""
    if not cfg.api_token:
        return []

    zone_id = resolve_zone_id(cfg)
    messages = [f"Using Cloudflare zone ID: {zone_id}"]

    for hostname in hostnames:
        host = hostname.strip().lower()
        if not host or host in ("localhost", "127.0.0.1"):
            continue
        # WireGuard UDP cannot use Cloudflare proxy — disable for wg.* hostnames
        proxied = cfg.proxied
        if host.startswith("wg.") or "wireguard" in host:
            proxied = False
        msg = upsert_a_record(cfg, zone_id, host, vps_ip, proxied=proxied)
        messages.append(msg)
        log(msg)

    return messages
