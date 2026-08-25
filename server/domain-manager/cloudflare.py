"""Cloudflare DNS helpers for domain-manager (runtime)."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request

API_BASE = "https://api.cloudflare.com/client/v4"


def _enabled() -> bool:
    return bool(os.environ.get("CLOUDFLARE_API_TOKEN"))


def _cfg():
    return {
        "token": os.environ["CLOUDFLARE_API_TOKEN"],
        "zone_id": os.environ.get("CLOUDFLARE_ZONE_ID", ""),
        "zone_name": os.environ.get("CLOUDFLARE_ZONE_NAME", ""),
        "vps_ip": os.environ.get("VPS_HOST", ""),
        "proxied": os.environ.get("CLOUDFLARE_PROXIED", "true").lower() == "true",
    }


def _request(method: str, path: str, body: dict | None = None) -> dict:
    cfg = _cfg()
    url = f"{API_BASE}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {cfg['token']}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        payload = json.loads(resp.read().decode())
    if not payload.get("success"):
        raise RuntimeError(f"Cloudflare API error: {payload.get('errors')}")
    return payload


def _zone_id() -> str:
    cfg = _cfg()
    if cfg["zone_id"]:
        return cfg["zone_id"]
    name = cfg["zone_name"].strip().lower().rstrip(".")
    result = _request("GET", f"/zones?name={urllib.parse.quote(name)}")
    zones = result.get("result") or []
    if not zones:
        raise RuntimeError(f"No Cloudflare zone for '{name}'")
    return zones[0]["id"]


def _record_name(zone_name: str, hostname: str) -> str:
    zone = zone_name.strip().lower().rstrip(".")
    host = hostname.strip().lower().rstrip(".")
    if host == zone:
        return zone
    if host.endswith(f".{zone}"):
        return host[: -(len(zone) + 1)]
    return host


def upsert_domain_a_record(domain: str) -> str | None:
    if not _enabled():
        return None
    cfg = _cfg()
    if not cfg["vps_ip"]:
        raise RuntimeError("VPS_HOST not configured for Cloudflare DNS")

    zone_id = _zone_id()
    record_name = _record_name(cfg["zone_name"], domain)
    existing = _request(
        "GET",
        f"/zones/{zone_id}/dns_records?type=A&name={urllib.parse.quote(record_name)}",
    )
    body = {
        "type": "A",
        "name": record_name,
        "content": cfg["vps_ip"],
        "ttl": 1,
        "proxied": cfg["proxied"],
    }
    records = existing.get("result") or []
    if records:
        _request("PUT", f"/zones/{zone_id}/dns_records/{records[0]['id']}", body)
        return f"Updated Cloudflare A record for {domain}"
    _request("POST", f"/zones/{zone_id}/dns_records", body)
    return f"Created Cloudflare A record for {domain}"


def delete_domain_a_record(domain: str) -> str | None:
    if not _enabled():
        return None
    cfg = _cfg()
    zone_id = _zone_id()
    record_name = _record_name(cfg["zone_name"], domain)
    existing = _request(
        "GET",
        f"/zones/{zone_id}/dns_records?type=A&name={urllib.parse.quote(record_name)}",
    )
    records = existing.get("result") or []
    if not records:
        return None
    _request("DELETE", f"/zones/{zone_id}/dns_records/{records[0]['id']}")
    return f"Removed Cloudflare A record for {domain}"
