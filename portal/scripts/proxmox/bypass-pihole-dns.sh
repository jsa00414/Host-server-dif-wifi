#!/bin/bash
# Configure Flint so Proxmox (192.168.8.160) DNS skips AdGuard → Pi-hole.
# Safe to re-run. Requires ROUTER_HOST + ROUTER_PASS (or ROUTER_PASS_B64).
set -euo pipefail

PVE_IP="${PVE_IP:-192.168.8.160}"
PVE_DNS="${PVE_DNS:-1.1.1.1}"
PVE_DNS2="${PVE_DNS2:-8.8.8.8}"
TAG="${TAG:-proxmox_nopihole}"
NAME="${NAME:-pve}"

ROUTER_HOST="${ROUTER_HOST:-${1:-}}"
ROUTER_USER="${ROUTER_USER:-root}"
ROUTER_PASS="${ROUTER_PASS:-}"
ROUTER_PASS_B64="${ROUTER_PASS_B64:-}"

if [[ -z "$ROUTER_HOST" ]]; then
  echo "ROUTER_HOST required (Flint VPN IP, e.g. 10.9.0.2)" >&2
  exit 1
fi
if [[ -z "$ROUTER_PASS" && -n "$ROUTER_PASS_B64" ]]; then
  ROUTER_PASS="$(printf '%s' "$ROUTER_PASS_B64" | base64 -d)"
fi
if [[ -z "$ROUTER_PASS" ]]; then
  echo "ROUTER_PASS or ROUTER_PASS_B64 required" >&2
  exit 1
fi

# shellcheck disable=SC2087
sshpass -p "$ROUTER_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=15 \
  "${ROUTER_USER}@${ROUTER_HOST}" \
  PVE_IP="$PVE_IP" PVE_DNS="$PVE_DNS" PVE_DNS2="$PVE_DNS2" TAG="$TAG" NAME="$NAME" \
  bash -s <<'EOS'
set -euo pipefail

MAC=$(awk -v ip="$PVE_IP" '$1==ip{print toupper($4); exit}' /proc/net/arp || true)
if [ -z "${MAC:-}" ] || [ "$MAC" = "00:00:00:00:00:00" ]; then
  echo "WARN: no ARP for $PVE_IP — DHCP host may use previous MAC" >&2
  MAC=""
fi

IDX=""
i=0
while uci -q get "dhcp.@host[$i]" >/dev/null 2>&1; do
  ip=$(uci -q get "dhcp.@host[$i].ip" || true)
  name=$(uci -q get "dhcp.@host[$i].name" || true)
  mac=$(uci -q get "dhcp.@host[$i].mac" || true)
  mac_up=$(echo "${mac:-}" | tr 'a-z' 'A-Z')
  if [ "$ip" = "$PVE_IP" ] || [ "$name" = "$NAME" ] || { [ -n "$MAC" ] && [ "$mac_up" = "$MAC" ]; }; then
    IDX=$i
    break
  fi
  i=$((i + 1))
done
if [ -z "$IDX" ]; then
  uci add dhcp host >/dev/null
  IDX=$(uci show dhcp | sed -n 's/.*@host\[\([0-9]*\)\]=host$/\1/p' | tail -1)
fi
uci set "dhcp.@host[$IDX].name=$NAME"
uci set "dhcp.@host[$IDX].ip=$PVE_IP"
[ -n "$MAC" ] && uci set "dhcp.@host[$IDX].mac=$MAC"
uci set "dhcp.@host[$IDX].tag=$TAG"
uci set "dhcp.@host[$IDX].dns=1"
uci commit dhcp

mkdir -p /etc/dnsmasq.d
if [ -n "$MAC" ]; then
  cat > /etc/dnsmasq.d/proxmox-nopihole.conf <<EOF
# Proxmox: public DNS (skip AdGuard → Pi-hole)
dhcp-host=${MAC},${PVE_IP},${NAME},set:${TAG}
dhcp-option=tag:${TAG},option:dns-server,${PVE_DNS},${PVE_DNS2}
EOF
fi

cat > /etc/firewall.user.proxmox-nopihole <<FW
#!/bin/sh
# Proxmox DNS bypass — do not force through AdGuard/Pi-hole
PVE=${PVE_IP}
DNS=${PVE_DNS}
iptables -t nat -C dns_dispatcher -s \$PVE/32 -j RETURN 2>/dev/null || \\
  iptables -t nat -I dns_dispatcher 1 -s \$PVE/32 -j RETURN
for proto in udp tcp; do
  iptables -t nat -C PREROUTING -s \$PVE/32 -p \$proto --dport 53 -m comment --comment SM-PVE-NOPIHOLE -j DNAT --to-destination \$DNS:53 2>/dev/null || \\
    iptables -t nat -I PREROUTING 1 -s \$PVE/32 -p \$proto --dport 53 -m comment --comment SM-PVE-NOPIHOLE -j DNAT --to-destination \$DNS:53
done
iptables -t nat -C POSTROUTING -s \$PVE/32 -d \$DNS/32 -p udp --dport 53 -m comment --comment SM-PVE-NOPIHOLE -j MASQUERADE 2>/dev/null || \\
  iptables -t nat -I POSTROUTING 1 -s \$PVE/32 -d \$DNS/32 -p udp --dport 53 -m comment --comment SM-PVE-NOPIHOLE -j MASQUERADE
iptables -t nat -C POSTROUTING -s \$PVE/32 -d \$DNS/32 -p tcp --dport 53 -m comment --comment SM-PVE-NOPIHOLE -j MASQUERADE 2>/dev/null || \\
  iptables -t nat -I POSTROUTING 1 -s \$PVE/32 -d \$DNS/32 -p tcp --dport 53 -m comment --comment SM-PVE-NOPIHOLE -j MASQUERADE
iptables -C forwarding_rule -s \$PVE/32 -d \$DNS/32 -p udp --dport 53 -m comment --comment SM-PVE-NOPIHOLE -j ACCEPT 2>/dev/null || \\
  iptables -I forwarding_rule 1 -s \$PVE/32 -d \$DNS/32 -p udp --dport 53 -m comment --comment SM-PVE-NOPIHOLE -j ACCEPT
iptables -C forwarding_rule -s \$PVE/32 -d \$DNS/32 -p tcp --dport 53 -m comment --comment SM-PVE-NOPIHOLE -j ACCEPT 2>/dev/null || \\
  iptables -I forwarding_rule 1 -s \$PVE/32 -d \$DNS/32 -p tcp --dport 53 -m comment --comment SM-PVE-NOPIHOLE -j ACCEPT
FW
chmod +x /etc/firewall.user.proxmox-nopihole
touch /etc/firewall.user
grep -q 'firewall.user.proxmox-nopihole' /etc/firewall.user || \
  echo '[ -x /etc/firewall.user.proxmox-nopihole ] && /etc/firewall.user.proxmox-nopihole' >> /etc/firewall.user
/etc/firewall.user.proxmox-nopihole
/etc/init.d/dnsmasq restart >/dev/null 2>&1 || true
echo "OK pve=$PVE_IP mac=${MAC:-unknown} dns=$PVE_DNS"
EOS
