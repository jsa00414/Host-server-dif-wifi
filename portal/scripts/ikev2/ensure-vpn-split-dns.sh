#!/usr/bin/env bash
# Rewrite VPN-gated hostnames to the VPS OpenVPN/tun IP so IKEv2 (and other
# VPN) clients hit Caddy via the tunnel source IP (10.10.0.x / 10.9.0.x / …).
#
# Why: phones/Windows exclude the VPN gateway public IP from the tunnel to
# avoid routing loops. If DNS returns 74.208.76.213, HTTPS to portal goes
# over cellular/Wi-Fi WAN → Caddy @vpn_clients → 403 Forbidden.
#
# Only AdGuard (VPN DNS) is rewritten; public DNS is unchanged.
set -euo pipefail

export ADGUARD_API="${ADGUARD_API:-http://127.0.0.1:3000}"
export VPN_INTERNAL_IP="${VPN_INTERNAL_IP:-10.9.0.1}"

echo "==> AdGuard VPN split-DNS → ${VPN_INTERNAL_IP}"

# IKEv2 clients must reach host INPUT (sslh on 10.9.0.1:443)
if command -v ufw >/dev/null 2>&1; then
  if ! ufw status 2>/dev/null | grep -F 'Anywhere                   ALLOW       10.10.0.0/24' | grep -q 'IKEv2 clients to host'; then
    ufw allow from 10.10.0.0/24 comment 'IKEv2 clients to host' >/dev/null 2>&1 || true
    echo "  ufw: allow from 10.10.0.0/24"
  fi
fi

python3 - <<'PY'
import json
import os
import urllib.error
import urllib.request

api = os.environ["ADGUARD_API"].rstrip("/")
want_ip = os.environ["VPN_INTERNAL_IP"]
hosts = [
    "portal.vpstruelord.com",
    "vpn.vpstruelord.com",
    "grafana.vpstruelord.com",
    "proxmox.vpstruelord.com",
    "router.vpstruelord.com",
    "buffalo.vpstruelord.com",
    "files.vpstruelord.com",
    "dns.vpstruelord.com",
    "pihole.vpstruelord.com",
]


def req(method: str, path: str, body=None):
    data = None if body is None else json.dumps(body).encode()
    headers = {"Content-Type": "application/json"} if data is not None else {}
    request = urllib.request.Request(
        api + path, data=data, method=method, headers=headers
    )
    with urllib.request.urlopen(request, timeout=8) as resp:
        raw = resp.read()
        return json.loads(raw) if raw else None


existing = req("GET", "/control/rewrite/list") or []
for row in list(existing):
    domain = (row.get("domain") or "").strip().lower()
    if domain in hosts:
        try:
            req(
                "POST",
                "/control/rewrite/delete",
                {"domain": row["domain"], "answer": row["answer"]},
            )
            print(f"  removed {domain} -> {row.get('answer')}")
        except urllib.error.HTTPError as exc:
            print(f"  warn delete {domain}: {exc}")

for host in hosts:
    req("POST", "/control/rewrite/add", {"domain": host, "answer": want_ip})
    print(f"  + {host} -> {want_ip}")

final = req("GET", "/control/rewrite/list") or []
ours = [r for r in final if (r.get("domain") or "").lower() in hosts]
print(f"OK {len(ours)} VPN split-DNS rewrites")
for row in ours:
    print(f"  {row.get('domain')} -> {row.get('answer')}")
PY

if command -v dig >/dev/null 2>&1; then
  echo "==> dig @10.42.42.44 portal.vpstruelord.com"
  dig @10.42.42.44 portal.vpstruelord.com +short || true
fi

echo "Done. Reconnect VPN (or flush DNS) on the phone, then open https://portal.vpstruelord.com"
