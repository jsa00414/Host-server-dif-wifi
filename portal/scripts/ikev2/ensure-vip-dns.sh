#!/usr/bin/env bash
# DNS on portal VIP 10.11.0.1 — Windows often keeps DNS=10.11.0.1 after OpenVPN
# disconnect; without a listener, nslookup/portal resolve hang → browser timeout.
set -euo pipefail

VIP="${VPN_INTERNAL_IP:-10.11.0.1}"
VPS="${VPS_PUBLIC_IP:-74.208.76.213}"
CONF_DIR="${VIP_DNS_DIR:-/opt/ikev2/vip-dns}"

ip addr add "${VIP}/32" dev lo 2>/dev/null || true
mkdir -p "$CONF_DIR"
cat >"${CONF_DIR}/dnsmasq.conf" <<CFG
listen-address=${VIP}
bind-interfaces
port=53
no-resolv
no-hosts
address=/portal.vpstruelord.com/${VIP}
address=/router.vpstruelord.com/${VIP}
address=/keys.vpstruelord.com/${VPS}
address=/vpstruelord.com/${VPS}
server=127.0.0.53
CFG

cat >/etc/systemd/system/sm-vip-dns.service <<UNIT
[Unit]
Description=ServerManager VIP DNS (${VIP}) for portal
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/sbin/dnsmasq -C ${CONF_DIR}/dnsmasq.conf -k --log-facility=-
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now sm-vip-dns.service
iptables -C INPUT -d "${VIP}/32" -p udp --dport 53 -j ACCEPT 2>/dev/null || \
  iptables -I INPUT 1 -d "${VIP}/32" -p udp --dport 53 -j ACCEPT
iptables -C INPUT -d "${VIP}/32" -p tcp --dport 53 -j ACCEPT 2>/dev/null || \
  iptables -I INPUT 1 -d "${VIP}/32" -p tcp --dport 53 -j ACCEPT

dig +time=2 +tries=1 +short portal.vpstruelord.com @"$VIP" || true
echo "vip-dns: portal @${VIP} ready"
