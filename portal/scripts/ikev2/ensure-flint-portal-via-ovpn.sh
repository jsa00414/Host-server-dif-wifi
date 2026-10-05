#!/usr/bin/env bash
# Route Flint LAN HTTPS to the VPS through OpenVPN so Caddy sees 10.9.0.2
# (in @vpn_clients) instead of campus WAN 192.81.235.246 (@denied_wan abort
# → Chrome ERR_HTTP2_PROTOCOL_ERROR).
#
# Flint WAN is school WiFi (shared campus NAT). GL.iNet policy routing also
# forces the VPS public IP via WAN so OpenVPN does not loop. LAN browsers must
# either resolve portal/router to VIP 10.11.0.1, or have DNAT rewrite public
# :80/:443 to that VIP — both paths go over ovpnclient1.
set -euo pipefail

FLINT_HOST="${FLINT_LAN_IP:-192.168.8.1}"
VPS_IP="${VPS_PUBLIC_IP:-74.208.76.213}"
OVPN_GW="${OVPN_VPS_VPN_IP:-10.9.0.1}"
PORTAL_VIP="${VPN_INTERNAL_IP:-10.11.0.1}"
TABLE="${FLINT_PORTAL_ROUTE_TABLE:-100}"
ENV_FILE="${PORTAL_ENV_FILE:-/opt/wireguard/port-forward-ui.env}"

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

export SSHPASS="$PASS"

REMOTE_B64="$(
  VPS_IP="$VPS_IP" OVPN_GW="$OVPN_GW" PORTAL_VIP="$PORTAL_VIP" TABLE="$TABLE" python3 - <<'PY'
import base64
import os

vps = os.environ["VPS_IP"]
gw = os.environ["OVPN_GW"]
vip = os.environ["PORTAL_VIP"]
table = os.environ["TABLE"]
remote = f"""set +e
VPS="{vps}"
GW="{gw}"
VIP="{vip}"
TABLE="{table}"

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

# DNAT public VPS :80/:443 → VIP so Windows DNS cache / DoH still works
iptables -t nat -D PREROUTING -s 192.168.8.0/24 -d "$VPS"/32 -p tcp --dport 443 -m comment --comment SM-PORTAL-VIA-OVPN -j DNAT --to-destination "$VIP":443 2>/dev/null
iptables -t nat -D PREROUTING -s 192.168.8.0/24 -d "$VPS"/32 -p tcp --dport 80 -m comment --comment SM-PORTAL-VIA-OVPN -j DNAT --to-destination "$VIP":80 2>/dev/null
iptables -t nat -I PREROUTING 1 -s 192.168.8.0/24 -d "$VPS"/32 -p tcp --dport 443 -m comment --comment SM-PORTAL-VIA-OVPN -j DNAT --to-destination "$VIP":443
iptables -t nat -I PREROUTING 1 -s 192.168.8.0/24 -d "$VPS"/32 -p tcp --dport 80 -m comment --comment SM-PORTAL-VIA-OVPN -j DNAT --to-destination "$VIP":80

iptables -t nat -C POSTROUTING -s 192.168.8.0/24 -d "$VIP"/32 -o ovpnclient1 -j MASQUERADE 2>/dev/null || \\
  iptables -t nat -I POSTROUTING 1 -s 192.168.8.0/24 -d "$VIP"/32 -o ovpnclient1 -j MASQUERADE
iptables -t nat -C POSTROUTING -o ovpnclient1 -j MASQUERADE 2>/dev/null || \\
  iptables -t nat -A POSTROUTING -o ovpnclient1 -j MASQUERADE

if iptables -t filter -L forwarding_rule -n >/dev/null 2>&1; then
  iptables -t filter -C forwarding_rule -s 192.168.8.0/24 -d "$VIP"/32 -o ovpnclient1 -j ACCEPT 2>/dev/null || \\
    iptables -t filter -I forwarding_rule 1 -s 192.168.8.0/24 -d "$VIP"/32 -o ovpnclient1 -j ACCEPT
else
  iptables -t filter -C FORWARD -s 192.168.8.0/24 -d "$VIP"/32 -o ovpnclient1 -j ACCEPT 2>/dev/null || \\
    iptables -t filter -I FORWARD 1 -s 192.168.8.0/24 -d "$VIP"/32 -o ovpnclient1 -j ACCEPT
fi

mkdir -p /tmp/dnsmasq.d
cat >/tmp/dnsmasq.d/sm-portal-via-ovpn.conf <<EOF
# Managed by ensure-flint-portal-via-ovpn.sh
address=/portal.vpstruelord.com/$VIP
address=/router.vpstruelord.com/$VIP
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
  uci commit dhcp
fi

killall -HUP dnsmasq 2>/dev/null || true

conntrack -D -d "$VPS" >/dev/null 2>&1 || true
conntrack -D -d "$VIP" >/dev/null 2>&1 || true

echo "flint-portal-via-ovpn: DNS+DNAT portal/router->$VIP via ovpn (school WAN bypass)"
curl -sk -o /dev/null -w "ovpn_portal=%{{http_code}}\\n" --interface ovpnclient1 --connect-timeout 8 https://portal.vpstruelord.com/ || echo ovpn_portal=fail
curl -sk -o /dev/null -w "vip_portal=%{{http_code}}\\n" --connect-timeout 8 --resolve portal.vpstruelord.com:443:$VIP https://portal.vpstruelord.com/ || echo vip_portal=fail
nslookup portal.vpstruelord.com 127.0.0.1 2>/dev/null | head -6 || true
"""
print(base64.b64encode(remote.encode()).decode())
PY
)"

echo "$REMOTE_B64" | base64 -d | sshpass -e ssh -o StrictHostKeyChecking=no \
  -o PreferredAuthentications=password -o PubkeyAuthentication=no \
  -o ConnectTimeout=12 "root@${FLINT_HOST}" sh -s
