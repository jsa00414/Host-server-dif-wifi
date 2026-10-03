#!/usr/bin/env bash
# Ensure IKEv2 clients (10.10.0.0/24) can reach the internet + AdGuard DNS,
# and can hit portal/admin via an internal VIP (not tun0 10.9.0.1).
#
# Why a VIP: Windows/iPhone IKEv2 tunnels to 10.9.0.1 often black-hole
# (POINTOPOINT tun0 + policy routing). 10.11.0.1 on lo is reachable from
# both IKEv2 and OpenVPN; sslh on 0.0.0.0:443 accepts it.
set -euo pipefail

IKEV2_POOL="${IKEV2_POOL:-10.10.0.0/24}"
ADGUARD_DNS="${ADGUARD_DNS:-10.42.42.44}"
WAN_IF="${WAN_IF:-ens6}"
DNS_NET="${DNS_NET:-10.42.42.0/24}"
PORTAL_VIP="${PORTAL_VIP:-10.11.0.1}"
VPS_IP="${VPS_IP:-$(ip -4 -o addr show dev "$WAN_IF" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)}"
VPS_IP="${VPS_IP:-74.208.76.213}"

echo "ikev2 forward: pool=${IKEV2_POOL} wan=${WAN_IF} dns=${ADGUARD_DNS} vip=${PORTAL_VIP} vps=${VPS_IP}"

# Internal VIP for split-DNS portal/admin (shared by IKEv2 + OpenVPN)
if ! ip -4 addr show dev lo 2>/dev/null | grep -q "inet ${PORTAL_VIP}/"; then
  ip addr add "${PORTAL_VIP}/32" dev lo
  echo "  added ${PORTAL_VIP}/32 on lo"
fi
# Prefer main/local for VIP (avoid table 220 surprises)
ip rule del to "${PORTAL_VIP}/32" lookup main priority 110 2>/dev/null || true
ip rule add to "${PORTAL_VIP}/32" lookup main priority 110 2>/dev/null || true
# Also keep 10.10 return path via strongSwan table 220 (no override)

# Do NOT MASQUERADE VPN→VPS-public-IP (hairpin). Otherwise Caddy sees
# client_ip=74.208.76.213 and VPN-only sites return 403 while speedtests
# correctly show the VPS egress IP.
iptables -t nat -C POSTROUTING -s "$IKEV2_POOL" -d "${VPS_IP}/32" -m comment --comment SM-IKEV2-NO-HAIRPIN-MASQ -j RETURN 2>/dev/null \
  || iptables -t nat -I POSTROUTING 1 -s "$IKEV2_POOL" -d "${VPS_IP}/32" -m comment --comment SM-IKEV2-NO-HAIRPIN-MASQ -j RETURN

# Internet egress
iptables -t nat -C POSTROUTING -s "$IKEV2_POOL" -o "$WAN_IF" -m comment --comment SM-IKEV2-MASQ -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s "$IKEV2_POOL" -o "$WAN_IF" -m comment --comment SM-IKEV2-MASQ -j MASQUERADE

iptables -C FORWARD -s "$IKEV2_POOL" -m comment --comment SM-IKEV2-FWD -j ACCEPT 2>/dev/null \
  || iptables -I FORWARD 1 -s "$IKEV2_POOL" -m comment --comment SM-IKEV2-FWD -j ACCEPT
iptables -C FORWARD -d "$IKEV2_POOL" -m comment --comment SM-IKEV2-FWD -j ACCEPT 2>/dev/null \
  || iptables -I FORWARD 1 -d "$IKEV2_POOL" -m comment --comment SM-IKEV2-FWD -j ACCEPT

# DNS: send IKEv2 client DNS queries to AdGuard, with path allowed
iptables -t nat -C PREROUTING -s "$IKEV2_POOL" -p udp --dport 53 -m comment --comment SM-IKEV2-DNS -j DNAT --to-destination "${ADGUARD_DNS}:53" 2>/dev/null \
  || iptables -t nat -I PREROUTING 1 -s "$IKEV2_POOL" -p udp --dport 53 -m comment --comment SM-IKEV2-DNS -j DNAT --to-destination "${ADGUARD_DNS}:53"
iptables -t nat -C PREROUTING -s "$IKEV2_POOL" -p tcp --dport 53 -m comment --comment SM-IKEV2-DNS -j DNAT --to-destination "${ADGUARD_DNS}:53" 2>/dev/null \
  || iptables -t nat -I PREROUTING 1 -s "$IKEV2_POOL" -p tcp --dport 53 -m comment --comment SM-IKEV2-DNS -j DNAT --to-destination "${ADGUARD_DNS}:53"
iptables -t nat -C POSTROUTING -s "$IKEV2_POOL" -d "$DNS_NET" -m comment --comment SM-IKEV2-DNS -j MASQUERADE 2>/dev/null \
  || iptables -t nat -I POSTROUTING 1 -s "$IKEV2_POOL" -d "$DNS_NET" -m comment --comment SM-IKEV2-DNS -j MASQUERADE
iptables -C FORWARD -s "$IKEV2_POOL" -d "$DNS_NET" -m comment --comment SM-IKEV2-DNS -j ACCEPT 2>/dev/null \
  || iptables -I FORWARD 1 -s "$IKEV2_POOL" -d "$DNS_NET" -m comment --comment SM-IKEV2-DNS -j ACCEPT
iptables -C FORWARD -s "$DNS_NET" -d "$IKEV2_POOL" -m comment --comment SM-IKEV2-DNS -j ACCEPT 2>/dev/null \
  || iptables -I FORWARD 1 -s "$DNS_NET" -d "$IKEV2_POOL" -m comment --comment SM-IKEV2-DNS -j ACCEPT
# Docker raw-isolation DROP would otherwise black-hole direct queries to AdGuard
iptables -t raw -C PREROUTING -s "$IKEV2_POOL" -d "${ADGUARD_DNS}/32" -m comment --comment SM-VPN-DNS-ALLOW -j ACCEPT 2>/dev/null \
  || iptables -t raw -I PREROUTING 1 -s "$IKEV2_POOL" -d "${ADGUARD_DNS}/32" -m comment --comment SM-VPN-DNS-ALLOW -j ACCEPT

# Host INPUT for IKEv2 clients (sslh / portal VIP)
if command -v ufw >/dev/null 2>&1; then
  ufw allow from "$IKEV2_POOL" comment 'IKEv2 clients to host' >/dev/null 2>&1 || true
fi

# Persist VIP across reboot
mkdir -p /etc/systemd/system
cat >/etc/systemd/system/sm-portal-vip.service <<EOF
[Unit]
Description=ServerManager portal VIP ${PORTAL_VIP} on lo
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/ip addr add ${PORTAL_VIP}/32 dev lo
ExecStart=/sbin/ip rule add to ${PORTAL_VIP}/32 lookup main priority 110
ExecStop=/sbin/ip addr del ${PORTAL_VIP}/32 dev lo
ExecStop=/sbin/ip rule del to ${PORTAL_VIP}/32 lookup main priority 110
# idempotent
ExecStartPre=-/sbin/ip addr del ${PORTAL_VIP}/32 dev lo
ExecStartPre=-/sbin/ip rule del to ${PORTAL_VIP}/32 lookup main priority 110

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now sm-portal-vip.service >/dev/null 2>&1 || true

# Persist iptables best-effort
if command -v netfilter-persistent >/dev/null 2>&1; then
  netfilter-persistent save >/dev/null 2>&1 || true
elif command -v iptables-save >/dev/null 2>&1 && [[ -d /etc/iptables ]]; then
  iptables-save >/etc/iptables/rules.v4 2>/dev/null || true
fi

echo "--- VIP ---"
ip -4 addr show dev lo | grep -F "$PORTAL_VIP" || true
echo "--- NAT ---"
iptables -t nat -L POSTROUTING -n -v --line-numbers | grep -E 'SM-IKEV2|10\.10\.0' || true
iptables -t nat -L PREROUTING -n -v --line-numbers | grep -E 'SM-IKEV2|10\.10\.0' || true
echo "--- FORWARD ---"
iptables -L FORWARD -n -v --line-numbers | grep -E 'SM-IKEV2|10\.10\.0' || true
echo "ikev2 forward rules OK — reconnect ServerManager IKEv2"
