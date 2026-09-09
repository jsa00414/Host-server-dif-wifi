#!/bin/bash
set -euo pipefail
export PATH="/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
iptables -t nat -C POSTROUTING -s 10.9.0.0/24 -o ens6 -m comment --comment SM-OVPN-MASQ -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -o ens6 -m comment --comment SM-OVPN-MASQ -j MASQUERADE
iptables -C FORWARD -s 10.9.0.0/24 -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -s 10.9.0.0/24 -j ACCEPT
iptables -C FORWARD -d 10.9.0.0/24 -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -d 10.9.0.0/24 -j ACCEPT
iptables -C FORWARD -d 192.168.8.0/24 -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -d 192.168.8.0/24 -j ACCEPT
iptables -C FORWARD -s 192.168.8.0/24 -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -s 192.168.8.0/24 -j ACCEPT
if command -v ufw >/dev/null 2>&1; then
  ufw allow 8443/tcp comment "OpenVPN TCP school" >/dev/null 2>&1 || true
fi
