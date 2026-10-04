#!/usr/bin/env bash
# Ensure IKEv2 clients (10.10.0.0/24) can reach the internet + DNS,
# and can hit portal/admin via an internal VIP (not tun0 10.9.0.1).
#
# DNS model:
#   - Pool-wide default → guest NXDOMAIN resolver (VPN_GUEST_DNS, 10.42.42.45)
#     so unapproved peers never see AdGuard admin rewrites / portal A records.
#   - Trusted VIPs are upgraded to AdGuard by ensure-vpn-client-gate.sh.
#
# Why a VIP: Windows/iPhone IKEv2 tunnels to 10.9.0.1 often black-hole
# (POINTOPOINT tun0 + policy routing). 10.11.0.1 on lo is reachable from
# both IKEv2 and OpenVPN; sslh on 0.0.0.0:443 accepts it.
set -euo pipefail

ENV_FILE="${PORTAL_ENV_FILE:-/opt/wireguard/port-forward-ui.env}"
# shellcheck disable=SC1090
set -a
[ -f "$ENV_FILE" ] && . "$ENV_FILE"
set +a

IKEV2_POOL="${IKEV2_POOL:-10.10.0.0/24}"
ADGUARD_DNS="${ADGUARD_DNS:-10.42.42.44}"
GUEST_DNS="${VPN_GUEST_DNS:-10.42.42.45}"
WAN_IF="${WAN_IF:-ens6}"
DNS_NET="${DNS_NET:-10.42.42.0/24}"
PORTAL_VIP="${PORTAL_VIP:-10.11.0.1}"
VPS_IP="${VPS_IP:-$(ip -4 -o addr show dev "$WAN_IF" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)}"
VPS_IP="${VPS_IP:-74.208.76.213}"

echo "ikev2 forward: pool=${IKEV2_POOL} wan=${WAN_IF} guest_dns=${GUEST_DNS} adguard=${ADGUARD_DNS} vip=${PORTAL_VIP} vps=${VPS_IP}"

# Internal VIP for split-DNS portal/admin (shared by IKEv2 + OpenVPN)
if ! ip -4 addr show dev lo 2>/dev/null | grep -q "inet ${PORTAL_VIP}/"; then
  ip addr add "${PORTAL_VIP}/32" dev lo
  echo "  added ${PORTAL_VIP}/32 on lo"
fi
# Prefer main/local for VIP (avoid table 220 surprises)
ip rule del to "${PORTAL_VIP}/32" lookup main priority 110 2>/dev/null || true
ip rule add to "${PORTAL_VIP}/32" lookup main priority 110 2>/dev/null || true

# Do NOT MASQUERADE VPN→VPS-public-IP (hairpin).
iptables -t nat -C POSTROUTING -s "$IKEV2_POOL" -d "${VPS_IP}/32" -m comment --comment SM-IKEV2-NO-HAIRPIN-MASQ -j RETURN 2>/dev/null \
  || iptables -t nat -I POSTROUTING 1 -s "$IKEV2_POOL" -d "${VPS_IP}/32" -m comment --comment SM-IKEV2-NO-HAIRPIN-MASQ -j RETURN

# Internet egress
iptables -t nat -C POSTROUTING -s "$IKEV2_POOL" -o "$WAN_IF" -m comment --comment SM-IKEV2-MASQ -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s "$IKEV2_POOL" -o "$WAN_IF" -m comment --comment SM-IKEV2-MASQ -j MASQUERADE

iptables -C FORWARD -s "$IKEV2_POOL" -m comment --comment SM-IKEV2-FWD -j ACCEPT 2>/dev/null \
  || iptables -I FORWARD 1 -s "$IKEV2_POOL" -m comment --comment SM-IKEV2-FWD -j ACCEPT
iptables -C FORWARD -d "$IKEV2_POOL" -m comment --comment SM-IKEV2-FWD -j ACCEPT 2>/dev/null \
  || iptables -I FORWARD 1 -d "$IKEV2_POOL" -m comment --comment SM-IKEV2-FWD -j ACCEPT

# Drop every prior SM-IKEV2-DNS DNAT (avoids stale 1.1.1.1 + guest dual rules).
while iptables -t nat -C PREROUTING -s "$IKEV2_POOL" -p udp --dport 53 -m comment --comment SM-IKEV2-DNS -j DNAT --to-destination 1.1.1.1:53 2>/dev/null; do
  iptables -t nat -D PREROUTING -s "$IKEV2_POOL" -p udp --dport 53 -m comment --comment SM-IKEV2-DNS -j DNAT --to-destination 1.1.1.1:53 || break
done
while iptables -t nat -C PREROUTING -s "$IKEV2_POOL" -p tcp --dport 53 -m comment --comment SM-IKEV2-DNS -j DNAT --to-destination 1.1.1.1:53 2>/dev/null; do
  iptables -t nat -D PREROUTING -s "$IKEV2_POOL" -p tcp --dport 53 -m comment --comment SM-IKEV2-DNS -j DNAT --to-destination 1.1.1.1:53 || break
done
# Also clear any previous guest/adguard pool DNATs so we re-add cleanly.
while iptables -t nat -S PREROUTING 2>/dev/null | grep -q -- "-s ${IKEV2_POOL} .* --dport 53 .* SM-IKEV2-DNS"; do
  line="$(iptables -t nat -S PREROUTING | grep -E -- "-s ${IKEV2_POOL} .* --dport 53 .* SM-IKEV2-DNS" | head -1 || true)"
  [[ -z "$line" ]] && break
  eval "iptables -t nat ${line/-A/-D}" 2>/dev/null || break
done

# Pool-wide default DNS → guest NXDOMAIN resolver
iptables -t nat -I PREROUTING 1 -s "$IKEV2_POOL" -p udp --dport 53 -m comment --comment SM-IKEV2-DNS -j DNAT --to-destination "${GUEST_DNS}:53"
iptables -t nat -I PREROUTING 1 -s "$IKEV2_POOL" -p tcp --dport 53 -m comment --comment SM-IKEV2-DNS -j DNAT --to-destination "${GUEST_DNS}:53"
iptables -t nat -C POSTROUTING -s "$IKEV2_POOL" -d "$DNS_NET" -m comment --comment SM-IKEV2-DNS -j MASQUERADE 2>/dev/null \
  || iptables -t nat -I POSTROUTING 1 -s "$IKEV2_POOL" -d "$DNS_NET" -m comment --comment SM-IKEV2-DNS -j MASQUERADE
iptables -C FORWARD -s "$IKEV2_POOL" -d "$DNS_NET" -m comment --comment SM-IKEV2-DNS -j ACCEPT 2>/dev/null \
  || iptables -I FORWARD 1 -s "$IKEV2_POOL" -d "$DNS_NET" -m comment --comment SM-IKEV2-DNS -j ACCEPT
iptables -C FORWARD -s "$DNS_NET" -d "$IKEV2_POOL" -m comment --comment SM-IKEV2-DNS -j ACCEPT 2>/dev/null \
  || iptables -I FORWARD 1 -s "$DNS_NET" -d "$IKEV2_POOL" -m comment --comment SM-IKEV2-DNS -j ACCEPT
# Allow guest + AdGuard DNS peers past docker raw drop
for dns_ip in "$GUEST_DNS" "$ADGUARD_DNS"; do
  iptables -t raw -C PREROUTING -s "$IKEV2_POOL" -d "${dns_ip}/32" -m comment --comment SM-VPN-DNS-ALLOW -j ACCEPT 2>/dev/null \
    || iptables -t raw -I PREROUTING 1 -s "$IKEV2_POOL" -d "${dns_ip}/32" -m comment --comment SM-VPN-DNS-ALLOW -j ACCEPT
done

# Host INPUT for IKEv2: narrow HTTPS only. Full host access is granted per
# allowlisted VIP by ensure-vpn-client-gate.sh (Security → VPN trust circle).
if command -v ufw >/dev/null 2>&1; then
  ufw delete allow from "$IKEV2_POOL" >/dev/null 2>&1 || true
  ufw allow from "$IKEV2_POOL" to any port 443 proto tcp comment 'IKEv2 base HTTPS' >/dev/null 2>&1 || true
  ufw allow from "$IKEV2_POOL" to any port 80 proto tcp comment 'IKEv2 base HTTPS' >/dev/null 2>&1 || true
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

[Install]
WantedBy=multi-user.target
EOF

# Ensure this unit always loads portal env (VPN_GUEST_DNS etc.)
cat >/etc/systemd/system/sm-ikev2-forward.service <<EOF
[Unit]
Description=ServerManager IKEv2 client internet forward/NAT
After=network-online.target strongswan-starter.service ufw.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
EnvironmentFile=-/opt/wireguard/port-forward-ui.env
ExecStart=/opt/ikev2/ensure-ikev2-forward.sh

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable sm-portal-vip.service sm-ikev2-forward.service >/dev/null 2>&1 || true
systemctl start sm-portal-vip.service >/dev/null 2>&1 || true

echo "ikev2 forward rules OK — reconnect ServerManager IKEv2"
iptables -t nat -S PREROUTING | grep SM-IKEV2-DNS || true
