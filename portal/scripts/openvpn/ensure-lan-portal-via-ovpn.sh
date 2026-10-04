#!/bin/bash
# Route home LAN → VPS public IP through Flint OpenVPN so Caddy sees 10.9.0.2
# (campus WAN is @denied_wan / not in @vpn_clients).
set -euo pipefail
ENV_FILE="${PORTAL_ENV_FILE:-/opt/wireguard/port-forward-ui.env}"
OVPN_GW="${OVPN_FLINT_IP:-10.9.0.2}"
VPS_IP="${VPS_PUBLIC_IP:-74.208.76.213}"
set -a
[ -f "$ENV_FILE" ] && . "$ENV_FILE"
set +a
PASS="${ROUTER_PASS:-}"
if [ -z "$PASS" ] && [ -n "${ROUTER_PASS_B64:-}" ]; then
  PASS="$(ROUTER_PASS_B64="$ROUTER_PASS_B64" python3 -c 'import os,base64;print(base64.b64decode(os.environ["ROUTER_PASS_B64"]).decode())' 2>/dev/null || true)"
fi
[ -n "$PASS" ] || { echo "no router pass"; exit 0; }
command -v sshpass >/dev/null || exit 0
export SSHPASS="$PASS"
sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "root@${OVPN_GW}" \
  VPS_IP="$VPS_IP" sh -s <<'REMOTE'
VPS="${VPS_IP:-74.208.76.213}"
TABLE=1024
ip link show ovpnclient1 >/dev/null 2>&1 || { echo "ovpn down"; exit 0; }
ip route replace 10.9.0.0/24 dev ovpnclient1 proto static scope link table "$TABLE" 2>/dev/null || true
ip route replace "$VPS/32" via 10.9.0.1 dev ovpnclient1 proto static table "$TABLE" 2>/dev/null || true
ip rule del to "$VPS" lookup main priority 50 2>/dev/null || true
ip rule del iif br-lan to "$VPS" lookup "$TABLE" 2>/dev/null || true
ip rule del from 192.168.8.0/24 to "$VPS" lookup "$TABLE" 2>/dev/null || true
ip rule del from 172.16.0.0/16 to "$VPS" lookup main 2>/dev/null || true
ip rule del from 10.9.0.2 to "$VPS" lookup main 2>/dev/null || true
ip rule add iif br-lan to "$VPS" lookup "$TABLE" priority 40 2>/dev/null || true
ip rule add from 192.168.8.0/24 to "$VPS" lookup "$TABLE" priority 41 2>/dev/null || true
ip rule add from 172.16.0.0/16 to "$VPS" lookup main priority 42 2>/dev/null || true
ip rule add from 10.9.0.2 to "$VPS" lookup main priority 43 2>/dev/null || true
ip rule add to "$VPS" lookup main priority 50 2>/dev/null || true
iptables -t nat -C POSTROUTING -s 192.168.8.0/24 -o ovpnclient1 -j MASQUERADE 2>/dev/null || \
  iptables -t nat -I POSTROUTING 1 -s 192.168.8.0/24 -o ovpnclient1 -j MASQUERADE 2>/dev/null || true
# persist on flint
cat > /etc/sm-lan-vps-via-ovpn.sh <<EOF
#!/bin/sh
VPS=$VPS
TABLE=1024
ip link show ovpnclient1 >/dev/null 2>&1 || exit 0
ip route replace 10.9.0.0/24 dev ovpnclient1 proto static scope link table "\$TABLE" 2>/dev/null || true
ip route replace "\$VPS/32" via 10.9.0.1 dev ovpnclient1 proto static table "\$TABLE" 2>/dev/null || true
ip rule del to "\$VPS" lookup main priority 50 2>/dev/null || true
ip rule del iif br-lan to "\$VPS" lookup "\$TABLE" 2>/dev/null || true
ip rule del from 192.168.8.0/24 to "\$VPS" lookup "\$TABLE" 2>/dev/null || true
ip rule del from 172.16.0.0/16 to "\$VPS" lookup main 2>/dev/null || true
ip rule del from 10.9.0.2 to "\$VPS" lookup main 2>/dev/null || true
ip rule add iif br-lan to "\$VPS" lookup "\$TABLE" priority 40 2>/dev/null || true
ip rule add from 192.168.8.0/24 to "\$VPS" lookup "\$TABLE" priority 41 2>/dev/null || true
ip rule add from 172.16.0.0/16 to "\$VPS" lookup main priority 42 2>/dev/null || true
ip rule add from 10.9.0.2 to "\$VPS" lookup main priority 43 2>/dev/null || true
ip rule add to "\$VPS" lookup main priority 50 2>/dev/null || true
iptables -t nat -C POSTROUTING -s 192.168.8.0/24 -o ovpnclient1 -j MASQUERADE 2>/dev/null || \
  iptables -t nat -I POSTROUTING 1 -s 192.168.8.0/24 -o ovpnclient1 -j MASQUERADE 2>/dev/null || true
EOF
chmod +x /etc/sm-lan-vps-via-ovpn.sh
mkdir -p /etc/hotplug.d/iface
cat > /etc/hotplug.d/iface/99-sm-lan-vps-ovpn <<'H'
[ "\$ACTION" = "ifup" ] || exit 0
case "\$INTERFACE\$DEVICE" in *ovpn*) /etc/sm-lan-vps-via-ovpn.sh ;; esac
H
echo "lan→VPS via OVPN ok ($(ip route get "$VPS" from 192.168.8.243 iif br-lan 2>/dev/null | head -1))"
REMOTE
