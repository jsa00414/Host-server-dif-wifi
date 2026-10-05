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

# Clear prior SM-PORTAL / SM-PORTAL-RELAY rules then re-add per key-bound LAN /32 only
while iptables -t nat -S PREROUTING 2>/dev/null | grep -qE 'SM-PORTAL-VIA-OVPN|SM-PORTAL-RELAY|SM-SURFACE-RELAY'; do
  line="$(iptables -t nat -S PREROUTING | grep -E 'SM-PORTAL-VIA-OVPN|SM-PORTAL-RELAY|SM-SURFACE-RELAY' | head -1)"
  eval "iptables -t nat ${{line/-A/-D}}" 2>/dev/null || break
done
while iptables -t filter -S 2>/dev/null | grep -qE 'SM-PORTAL-VIA-OVPN|SM-PORTAL-RELAY|SM-SURFACE'; do
  line="$(iptables -t filter -S | grep -E 'SM-PORTAL-VIA-OVPN|SM-PORTAL-RELAY|SM-SURFACE' | head -1)"
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
# Kill HTTP/3 (QUIC) to portal VIP/VPS — cached Alt-Svc otherwise hangs on UDP/443.
iptables -t filter -C "$FWD" -s 192.168.8.0/24 -d "$VIP"/32 -p udp --dport 443 -m comment --comment SM-NOH3-LAN -j REJECT --reject-with icmp-port-unreachable 2>/dev/null || \
  iptables -t filter -A "$FWD" -s 192.168.8.0/24 -d "$VIP"/32 -p udp --dport 443 -m comment --comment SM-NOH3-LAN -j REJECT --reject-with icmp-port-unreachable
iptables -t filter -C "$FWD" -s 192.168.8.0/24 -d "$VPS"/32 -p udp --dport 443 -m comment --comment SM-NOH3-LAN -j REJECT --reject-with icmp-port-unreachable 2>/dev/null || \
  iptables -t filter -A "$FWD" -s 192.168.8.0/24 -d "$VPS"/32 -p udp --dport 443 -m comment --comment SM-NOH3-LAN -j REJECT --reject-with icmp-port-unreachable

# Windows OpenVPN/IKEv2 often leaves DNS=10.11.0.1; answer via Flint dnsmasq when
# those queries still traverse br-lan (portal→VIP override).
iptables -t nat -C PREROUTING -i br-lan -d "$VIP"/32 -p udp --dport 53 -m comment --comment SM-DNS-VIP -j REDIRECT --to-ports 53 2>/dev/null || \
  iptables -t nat -I PREROUTING 1 -i br-lan -d "$VIP"/32 -p udp --dport 53 -m comment --comment SM-DNS-VIP -j REDIRECT --to-ports 53
iptables -t nat -C PREROUTING -i br-lan -d "$VIP"/32 -p tcp --dport 53 -m comment --comment SM-DNS-VIP -j REDIRECT --to-ports 53 2>/dev/null || \
  iptables -t nat -I PREROUTING 1 -i br-lan -d "$VIP"/32 -p tcp --dport 53 -m comment --comment SM-DNS-VIP -j REDIRECT --to-ports 53

# Local TCP relay: key-bound LAN → VIP/public:443 REDIRECT to socat → VIP.
# DNAT+FORWARD over OVPN stalls TLS (MSS/MTU → ERR_CONNECTION_TIMED_OUT on Windows).
# Relay keeps LAN↔Flint at 1500 MTU; Flint↔VIP uses the path curl already proves works.
RELAY_PORT=9443
if command -v socat >/dev/null 2>&1; then
  if ! netstat -lntp 2>/dev/null | grep -q ":${{RELAY_PORT}} "; then
    pkill -f "TCP-LISTEN:${{RELAY_PORT}}" 2>/dev/null || true
    socat TCP-LISTEN:${{RELAY_PORT}},bind=0.0.0.0,fork,reuseaddr,keepalive TCP:${{VIP}}:443,keepalive >/tmp/sm-portal-relay.log 2>&1 &
    echo $! >/tmp/sm-portal-relay.pid
  fi
  iptables -t filter -C INPUT -i br-lan -p tcp --dport ${{RELAY_PORT}} -m comment --comment SM-PORTAL-RELAY -j ACCEPT 2>/dev/null || \
    iptables -t filter -I INPUT 1 -i br-lan -p tcp --dport ${{RELAY_PORT}} -m comment --comment SM-PORTAL-RELAY -j ACCEPT
  # OVPN MSS/MTU: OUTPUT clamp is required for socat→VIP (locally originated).
  iptables -t mangle -C OUTPUT -o ovpnclient1 -p tcp --tcp-flags SYN,RST SYN -m comment --comment SM-PORTAL-MSS -j TCPMSS --set-mss 1000 2>/dev/null || \
    iptables -t mangle -I OUTPUT 1 -o ovpnclient1 -p tcp --tcp-flags SYN,RST SYN -m comment --comment SM-PORTAL-MSS -j TCPMSS --set-mss 1000
  iptables -t mangle -C FORWARD -o ovpnclient1 -p tcp --tcp-flags SYN,RST SYN -m comment --comment SM-PORTAL-MSS -j TCPMSS --set-mss 1000 2>/dev/null || \
    iptables -t mangle -I FORWARD 1 -o ovpnclient1 -p tcp --tcp-flags SYN,RST SYN -m comment --comment SM-PORTAL-MSS -j TCPMSS --set-mss 1000
  ip link set ovpnclient1 mtu 1280 2>/dev/null || true
  # Persist keep-alive (values baked in; cron restarts socat if it dies)
  mkdir -p /etc/firewall.user.d
  printf '%s\n' \
    '#!/bin/sh' \
    "# baked by ensure-flint-portal-via-ovpn.sh" \
    "RELAY=${{RELAY_PORT}}" \
    "VIP=${{VIP}}" \
    'if command -v socat >/dev/null 2>&1; then' \
    '  if ! netstat -lntp 2>/dev/null | grep -q ":$RELAY "; then' \
    '    socat TCP-LISTEN:$RELAY,bind=0.0.0.0,fork,reuseaddr,keepalive TCP:$VIP:443,keepalive >/tmp/sm-portal-relay.log 2>&1 &' \
    '    echo $! >/tmp/sm-portal-relay.pid' \
    '  fi' \
    'fi' \
    'iptables -w -C INPUT -i br-lan -p tcp --dport $RELAY -m comment --comment SM-PORTAL-RELAY -j ACCEPT 2>/dev/null || iptables -w -I INPUT 1 -i br-lan -p tcp --dport $RELAY -m comment --comment SM-PORTAL-RELAY -j ACCEPT' \
    'iptables -w -t mangle -C OUTPUT -o ovpnclient1 -p tcp --tcp-flags SYN,RST SYN -m comment --comment SM-PORTAL-MSS -j TCPMSS --set-mss 1000 2>/dev/null || iptables -w -t mangle -I OUTPUT 1 -o ovpnclient1 -p tcp --tcp-flags SYN,RST SYN -m comment --comment SM-PORTAL-MSS -j TCPMSS --set-mss 1000' \
    'iptables -w -t mangle -C FORWARD -o ovpnclient1 -p tcp --tcp-flags SYN,RST SYN -m comment --comment SM-PORTAL-MSS -j TCPMSS --set-mss 1000 2>/dev/null || iptables -w -t mangle -I FORWARD 1 -o ovpnclient1 -p tcp --tcp-flags SYN,RST SYN -m comment --comment SM-PORTAL-MSS -j TCPMSS --set-mss 1000' \
    'ip link set ovpnclient1 mtu 1280 2>/dev/null || true' \
    'iptables -w -t nat -C PREROUTING -i br-lan -d $VIP/32 -p udp --dport 53 -m comment --comment SM-DNS-VIP -j REDIRECT --to-ports 53 2>/dev/null || iptables -w -t nat -I PREROUTING 1 -i br-lan -d $VIP/32 -p udp --dport 53 -m comment --comment SM-DNS-VIP -j REDIRECT --to-ports 53' \
    'iptables -w -t nat -C PREROUTING -i br-lan -d $VIP/32 -p tcp --dport 53 -m comment --comment SM-DNS-VIP -j REDIRECT --to-ports 53 2>/dev/null || iptables -w -t nat -I PREROUTING 1 -i br-lan -d $VIP/32 -p tcp --dport 53 -m comment --comment SM-DNS-VIP -j REDIRECT --to-ports 53' \
    >/etc/firewall.user.d/sm-portal-relay.sh
  chmod +x /etc/firewall.user.d/sm-portal-relay.sh
  grep -q sm-portal-relay /etc/firewall.user 2>/dev/null || \
    echo '[ -f /etc/firewall.user.d/sm-portal-relay.sh ] && . /etc/firewall.user.d/sm-portal-relay.sh' >> /etc/firewall.user
  grep -q sm-portal-relay /etc/crontabs/root 2>/dev/null || \
    echo '* * * * * sh /etc/firewall.user.d/sm-portal-relay.sh' >> /etc/crontabs/root
  /etc/init.d/cron reload 2>/dev/null || true
fi

count=0
for ip in $LAN_IPS; do
  [ -n "$ip" ] || continue
  count=$((count+1))
  # HTTPS via local relay (not DNAT+FORWARD) — fixes Surface/Windows TLS timeout
  if command -v socat >/dev/null 2>&1; then
    iptables -t nat -I PREROUTING 1 -s "$ip"/32 -d "$VIP"/32 -p tcp --dport 443 -m comment --comment SM-PORTAL-RELAY -j REDIRECT --to-ports ${{RELAY_PORT}}
    iptables -t nat -I PREROUTING 1 -s "$ip"/32 -d "$VPS"/32 -p tcp --dport 443 -m comment --comment SM-PORTAL-RELAY -j REDIRECT --to-ports ${{RELAY_PORT}}
  else
    iptables -t nat -I PREROUTING 1 -s "$ip"/32 -d "$VPS"/32 -p tcp --dport 443 -m comment --comment SM-PORTAL-VIA-OVPN -j DNAT --to-destination "$VIP":443
  fi
  iptables -t nat -I PREROUTING 1 -s "$ip"/32 -d "$VPS"/32 -p tcp --dport 80 -m comment --comment SM-PORTAL-VIA-OVPN -j DNAT --to-destination "$VIP":80
  iptables -t nat -I POSTROUTING 1 -s "$ip"/32 -d "$VIP"/32 -o ovpnclient1 -m comment --comment SM-PORTAL-VIA-OVPN -j MASQUERADE
  # ACCEPT must NOT require -o ovpnclient1 — that footgun REJECT'd approved LAN when
  # FORWARD saw a different out-iface. Allow VIP + public VPS TCP for key-bound /32s.
  iptables -t filter -I "$FWD" 1 -s "$ip"/32 -d "$VIP"/32 -p tcp -m multiport --dports 80,443 -m comment --comment SM-PORTAL-VIA-OVPN -j ACCEPT
  iptables -t filter -I "$FWD" 1 -s "$ip"/32 -d "$VPS"/32 -p tcp -m multiport --dports 80,443 -m comment --comment SM-PORTAL-VIA-OVPN -j ACCEPT
done
# Default deny other LAN → VIP :80/:443 AFTER per-IP ACCEPTs (insert at end of our block).
iptables -t filter -A "$FWD" -s 192.168.8.0/24 -d "$VIP"/32 -p tcp -m multiport --dports 80,443 -m comment --comment SM-PORTAL-VIA-OVPN -j REJECT --reject-with tcp-reset

mkdir -p /tmp/dnsmasq.d
cat >/tmp/dnsmasq.d/sm-portal-via-ovpn.conf <<EOF
# Managed by ensure-flint-portal-via-ovpn.sh
address=/portal.vpstruelord.com/$VIP
address=/router.vpstruelord.com/$VIP
# keys must stay on the VPS public IP (campus phones enroll here). Never VIP.
address=/keys.vpstruelord.com/$VPS
# Chrome/Edge/Windows Secure DNS — NXDOMAIN canaries + DoH hostnames so
# clients use router DNS (portal→VIP). Do not REDIRECT :53 (breaks Windows).
server=/use-application-dns.net/
local=/use-application-dns.net/
server=/cloudflare-dns.com/
local=/cloudflare-dns.com/
server=/mozilla.cloudflare-dns.com/
local=/mozilla.cloudflare-dns.com/
server=/dns.google/
local=/dns.google/
server=/dns.google.com/
local=/dns.google.com/
server=/doh.opendns.com/
local=/doh.opendns.com/
server=/dns.quad9.net/
local=/dns.quad9.net/
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
  # Pin LAN DHCP DNS to the router so Windows does not keep a stale resolver.
  if ! uci -q get dhcp.lan.dhcp_option 2>/dev/null | grep -qE '(^|,| )6,'; then
    uci add_list dhcp.lan.dhcp_option='6,192.168.8.1'
  fi
  uci commit dhcp
fi

killall -HUP dnsmasq 2>/dev/null || true

# Drop any prior DNS REDIRECT experiments (they caused Windows DNS_PROBE failures).
while iptables -t nat -S PREROUTING 2>/dev/null | grep -q SM-DNS-FORCE; do
  line="$(iptables -t nat -S PREROUTING | grep SM-DNS-FORCE | head -1)"
  eval "iptables -t nat ${{line/-A/-D}}" 2>/dev/null || break
done

conntrack -D -d "$VPS" >/dev/null 2>&1 || true
conntrack -D -d "$VIP" >/dev/null 2>&1 || true

echo "flint-portal-via-ovpn: $count key-bound LAN /32s → VIP $VIP via relay/ovpn; others REJECT"
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
