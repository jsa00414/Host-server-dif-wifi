#!/usr/bin/env bash
# Rewrite VPN-gated hostnames to an internal lo VIP (10.11.0.1) so IKEv2 and
# OpenVPN clients hit Caddy via the tunnel with their VPN source IP.
#
# Why not the public IP: phones/Windows exclude the VPN gateway public IP from
# the tunnel; HTTPS then arrives from WAN → Caddy @vpn_clients → 403.
# Why not 10.9.0.1: IKEv2 clients time out on tun0's POINTOPOINT address.
#
# Only AdGuard (VPN DNS) is rewritten; public DNS is unchanged.
set -euo pipefail

export ADGUARD_API="${ADGUARD_API:-http://127.0.0.1:3000}"
# 10.11.0.1 = lo VIP (see ensure-ikev2-forward.sh). Do NOT use 10.9.0.1 —
# IKEv2 clients time out reaching tun0's POINTOPOINT address.
export VPN_INTERNAL_IP="${VPN_INTERNAL_IP:-10.11.0.1}"

echo "==> AdGuard VPN split-DNS → ${VPN_INTERNAL_IP}"

# Ensure VIP exists before clients resolve to it
if [[ -x /opt/ikev2/ensure-ikev2-forward.sh ]]; then
  PORTAL_VIP="${VPN_INTERNAL_IP}" bash /opt/ikev2/ensure-ikev2-forward.sh >/dev/null || true
elif ! ip -4 addr show dev lo 2>/dev/null | grep -q "inet ${VPN_INTERNAL_IP}/"; then
  ip addr add "${VPN_INTERNAL_IP}/32" dev lo 2>/dev/null || true
fi

# IKEv2 clients must reach host INPUT (sslh on VIP:443)
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
    # portal.vpstruelord.com stays on the public A record for VPN DNS too.
    # Rewriting it to 10.11.0.1 made OpenVPN/Windows time out (VIP not on the
    # client path); Caddy sticky WAN ACL covers gateway-IP exclusion → 403.
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
    print(f"  + rewrite {host} -> {want_ip}")

# Exclusive answers (avoid dual A: rewrite + public IP)
status = req("GET", "/control/filtering/status") or {}
rules = list(status.get("user_rules") or [])
rules = [
    r
    for r in rules
    if not any(h in r and "dnsrewrite" in r for h in hosts)
]
for host in hosts:
    rules.append(f"||{host}^$dnsrewrite=NOERROR;A;{want_ip}")
req("POST", "/control/filtering/set_rules", {"rules": rules})
print(f"OK dnsrewrite rules for {len(hosts)} hosts -> {want_ip}")
PY

if command -v dig >/dev/null 2>&1; then
  echo "==> dig @10.42.42.44 portal.vpstruelord.com"
  dig @10.42.42.44 portal.vpstruelord.com +short || true
fi

echo "Done. Reconnect VPN (or flush DNS) on the phone, then open https://portal.vpstruelord.com"
