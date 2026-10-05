#!/usr/bin/env bash
# Route Flint LAN HTTPS to the VPS through OpenVPN so Caddy sees 10.9.0.2
# (in @vpn_clients) instead of campus WAN 192.81.235.246 (@denied_wan abort
# → Chrome ERR_HTTP2_PROTOCOL_ERROR).
#
# Flint WAN is school WiFi (shared campus NAT). GL.iNet policy routing also
# forces the VPS public IP via WAN so OpenVPN does not loop. Key-bound LAN
# /32s resolve/DNAT portal/router to VIP 10.11.0.1 over ovpnclient1.
# Non-circle LAN is REJECT'd to the VIP so DNAT cannot bypass lan-circle.
set -euo pipefail

FLINT_HOST="${FLINT_LAN_IP:-192.168.8.1}"
VPS_IP="${VPS_PUBLIC_IP:-74.208.76.213}"
OVPN_GW="${OVPN_VPS_VPN_IP:-10.9.0.1}"
PORTAL_VIP="${VPN_INTERNAL_IP:-10.11.0.1}"
TABLE="${FLINT_PORTAL_ROUTE_TABLE:-100}"
ENV_FILE="${PORTAL_ENV_FILE:-/opt/wireguard/port-forward-ui.env}"
ALLOWLIST_PATH="${VPN_ALLOWLIST_FILE:-/opt/servermanager/panel/vpn-allowlist.json}"

PASS=""
if [[ -f "$ENV_FILE" ]]; then
  PASS="$(
    python3 - <<'PY'
import base64
from pathlib import Path
p = Path("/opt/wireguard/port-forward-ui.env")
for line in p.read_text().splitlines():
    if line.startswith("ROUTER_PASS_B64="):
        print(base64.b64decode(line.split("=", 1)[1].strip().strip('"').strip("'")).decode())
        break
PY
  )"
fi
if [[ -z "$PASS" ]]; then
  echo "flint-portal-via-ovpn: no ROUTER_PASS_B64"
  exit 0
fi

if grep -q '^flint,' /var/log/openvpn-status.log 2>/dev/null; then
  ip route replace 192.168.8.0/24 via 10.9.0.2 dev tun0 metric 5 2>/dev/null || true
  ip route replace 10.0.0.0/24 via 10.9.0.2 dev tun0 metric 5 2>/dev/null || true
fi

# Key-bound / sealed LAN /32s only — never DNAT the whole /24 (circle bypass).
LAN_ALLOW_CSV="$(
  ALLOWLIST_PATH="$ALLOWLIST_PATH" python3 - <<'PY'
import json, os
from pathlib import Path
p = Path(os.environ.get("ALLOWLIST_PATH", "/opt/servermanager/panel/vpn-allowlist.json"))
ips = []
if p.is_file():
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        data = {}
    for row in data.get("allowed") or []:
        if not isinstance(row, dict):
            continue
        ip = str(row.get("ip") or "").split("/", 1)[0].strip()
        if not ip.startswith("192.168.8."):
            continue
        if row.get("sealed") or str(row.get("pubkey") or "").strip():
            ips.append(ip)
print(",".join(sorted(set(ips))))
PY
)"

export SSHPASS="$PASS"

REMOTE_B64="$(
  VPS_IP="$VPS_IP" OVPN_GW="$OVPN_GW" PORTAL_VIP="$PORTAL_VIP" TABLE="$TABLE" \
  LAN_ALLOW_CSV="$LAN_ALLOW_CSV" python3 - <<'PY'
import base64
import os

vps = os.environ["VPS_IP"]
gw = os.environ["OVPN_GW"]
vip = os.environ["PORTAL_VIP"]
table = os.environ["TABLE"]
lan_csv = os.environ.get("LAN_ALLOW_CSV", "")
lan_ips = [x.strip() for x in lan_csv.split(",") if x.strip()]
lan_list = " ".join(lan_ips)
remote = f"""set +e
VPS="{vps}"
GW="{gw}"
VIP="{vip}"
TABLE="{table}"
LAN_IPS="{lan_list}"

if ! ip -4 addr show ovpnclient1 2>/dev/null | grep -q "inet 10.9.0.2"; then
  echo "flint-portal-via-ovpn: ovpnclient1 not up"
  exit 0
fi

ip route replace "$VIP"/32 via "$GW" dev ovpnclient1
ip route replace "$VPS"/32 via "$GW" dev ovpnclient1 table "$TABLE"
ip route replace "$VIP"/32 via "$GW" dev ovpnclient1 table "$TABLE" 2>/dev/null || true

while ip rule del iif br-lan to "$VPS" lookup "$TABLE" 2>/dev/null; do :; done
while ip rule del from 192.168.8.0/24 to "$VPS" lookup "$TABLE" 2>/dev/null; do :; done
ip rule add iif br-lan to "$VPS"/32 lookup "$TABLE" priority 35 2>/dev/null || true
ip rule add from 192.168.8.0/24 to "$VPS"/32 lookup "$TABLE" priority 36 2>/dev/null || true

# Clear prior SM-PORTAL rules then re-add per key-bound LAN /32 only
while iptables -t nat -S PREROUTING 2>/dev/null | grep -q SM-PORTAL-VIA-OVPN; do
  line="$(iptables -t nat -S PREROUTING | grep SM-PORTAL-VIA-OVPN | head -1)"
  eval "iptables -t nat ${{line/-A/-D}}" 2>/dev/null || break
done
while iptables -t filter -S 2>/dev/null | grep -q SM-PORTAL-VIA-OVPN; do
  line="$(iptables -t filter -S | grep SM-PORTAL-VIA-OVPN | head -1)"
  eval "iptables -t filter ${{line/-A/-D}}" 2>/dev/null || break
done
while iptables -t nat -S POSTROUTING 2>/dev/null | grep -q SM-PORTAL-VIA-OVPN; do
  line="$(iptables -t nat -S POSTROUTING | grep SM-PORTAL-VIA-OVPN | head -1)"
  eval "iptables -t nat ${{line/-A/-D}}" 2>/dev/null || break
done

iptables -t nat -C POSTROUTING -o ovpnclient1 -j MASQUERADE 2>/dev/null || \\
  iptables -t nat -A POSTROUTING -o ovpnclient1 -j MASQUERADE

# Default deny LAN → VIP :80/:443 (circle gate for DNAT path)
if iptables -t filter -L forwarding_rule -n >/dev/null 2>&1; then
  FWD=forwarding_rule
else
  FWD=FORWARD
fi
iptables -t filter -I "$FWD" 1 -s 192.168.8.0/24 -d "$VIP"/32 -p tcp -m multiport --dports 80,443 -m comment --comment SM-PORTAL-VIA-OVPN -j REJECT --reject-with tcp-reset

count=0
for ip in $LAN_IPS; do
  [ -n "$ip" ] || continue
  count=$((count+1))
  iptables -t nat -I PREROUTING 1 -s "$ip"/32 -d "$VPS"/32 -p tcp --dport 443 -m comment --comment SM-PORTAL-VIA-OVPN -j DNAT --to-destination "$VIP":443
  iptables -t nat -I PREROUTING 1 -s "$ip"/32 -d "$VPS"/32 -p tcp --dport 80 -m comment --comment SM-PORTAL-VIA-OVPN -j DNAT --to-destination "$VIP":80
  iptables -t nat -I POSTROUTING 1 -s "$ip"/32 -d "$VIP"/32 -o ovpnclient1 -m comment --comment SM-PORTAL-VIA-OVPN -j MASQUERADE
  iptables -t filter -I "$FWD" 1 -s "$ip"/32 -d "$VIP"/32 -o ovpnclient1 -m comment --comment SM-PORTAL-VIA-OVPN -j ACCEPT
done

mkdir -p /tmp/dnsmasq.d
cat >/tmp/dnsmasq.d/sm-portal-via-ovpn.conf <<EOF
# Managed by ensure-flint-portal-via-ovpn.sh
address=/portal.vpstruelord.com/$VIP
address=/router.vpstruelord.com/$VIP
# keys must stay on the VPS public IP (campus phones enroll here). Never VIP.
address=/keys.vpstruelord.com/$VPS
# Chrome/Edge Secure DNS canary — NXDOMAIN disables DoH so Windows cannot
# bypass portal→VIP rewrite (public/campus path times out on the PC).
server=/use-application-dns.net/
local=/use-application-dns.net/
server=/mask.icloud.com/
local=/mask.icloud.com/
server=/mask-h2.icloud.com/
local=/mask-h2.icloud.com/
EOF

if command -v uci >/dev/null 2>&1; then
  uci -q delete dhcp.sm_portal
  uci set dhcp.sm_portal=domain
  uci set dhcp.sm_portal.name="portal.vpstruelord.com"
  uci set dhcp.sm_portal.ip="$VIP"
  uci -q delete dhcp.sm_router
  uci set dhcp.sm_router=domain
  uci set dhcp.sm_router.name="router.vpstruelord.com"
  uci set dhcp.sm_router.ip="$VIP"
  uci -q delete dhcp.sm_keys
  uci set dhcp.sm_keys=domain
  uci set dhcp.sm_keys.name="keys.vpstruelord.com"
  uci set dhcp.sm_keys.ip="$VPS"
  uci commit dhcp
fi

killall -HUP dnsmasq 2>/dev/null || true

# Force LAN DNS through local dnsmasq (catches apps that ignore DHCP DNS).
while iptables -t nat -S PREROUTING 2>/dev/null | grep -q SM-DNS-FORCE; do
  line="$(iptables -t nat -S PREROUTING | grep SM-DNS-FORCE | head -1)"
  eval "iptables -t nat ${{line/-A/-D}}" 2>/dev/null || break
done
iptables -t nat -I PREROUTING 1 -i br-lan -p udp --dport 53 -m comment --comment SM-DNS-FORCE -j REDIRECT --to-ports 53
iptables -t nat -I PREROUTING 1 -i br-lan -p tcp --dport 53 -m comment --comment SM-DNS-FORCE -j REDIRECT --to-ports 53

conntrack -D -d "$VPS" >/dev/null 2>&1 || true
conntrack -D -d "$VIP" >/dev/null 2>&1 || true

echo "flint-portal-via-ovpn: $count key-bound LAN /32s → VIP $VIP via ovpn; others REJECT"
curl -sk -o /dev/null -w "ovpn_portal=%{{http_code}}\\n" --interface ovpnclient1 --connect-timeout 8 https://portal.vpstruelord.com/ || echo ovpn_portal=fail
curl -sk -o /dev/null -w "vip_portal=%{{http_code}}\\n" --connect-timeout 8 --resolve portal.vpstruelord.com:443:$VIP https://portal.vpstruelord.com/ || echo vip_portal=fail
nslookup portal.vpstruelord.com 127.0.0.1 2>/dev/null | head -6 || true
nslookup use-application-dns.net 127.0.0.1 2>&1 | head -6 || true
"""
print(base64.b64encode(remote.encode()).decode())
PY
)"

# Dropbear can hang mid-session; never block the systemd timer for tens of minutes.
echo "$REMOTE_B64" | base64 -d | timeout 45 sshpass -e ssh -o StrictHostKeyChecking=no \
  -o PreferredAuthentications=password -o PubkeyAuthentication=no \
  -o ConnectTimeout=12 -o ServerAliveInterval=5 -o ServerAliveCountMax=3 \
  "root@${FLINT_HOST}" sh -s
rc=$?
if [[ "$rc" -eq 124 ]]; then
  echo "flint-portal-via-ovpn: ssh timed out after 45s"
  exit 1
fi
exit "$rc"
