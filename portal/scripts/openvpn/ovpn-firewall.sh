#!/bin/bash
set -euo pipefail
export PATH="/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
iptables -t nat -C POSTROUTING -s 10.9.0.0/24 -o ens6 -m comment --comment SM-OVPN-MASQ -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -o ens6 -m comment --comment SM-OVPN-MASQ -j MASQUERADE
iptables -C FORWARD -s 10.9.0.0/24 -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -s 10.9.0.0/24 -j ACCEPT
iptables -C FORWARD -d 10.9.0.0/24 -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -d 10.9.0.0/24 -j ACCEPT
iptables -C FORWARD -d 192.168.8.0/24 -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -d 192.168.8.0/24 -j ACCEPT
iptables -C FORWARD -s 192.168.8.0/24 -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -s 192.168.8.0/24 -j ACCEPT

# OpenVPN DNS → AdGuard (10.42.42.44) → Pi-hole
# DNAT any DNS from tun0 to AdGuard (direct container access from tun0 is unreliable)
ADGUARD_DNS="${ADGUARD_DNS:-10.42.42.44}"
iptables -t nat -C PREROUTING -i tun0 -p udp --dport 53 -m comment --comment SM-OVPN-DNS -j DNAT --to-destination "${ADGUARD_DNS}:53" 2>/dev/null \
  || iptables -t nat -I PREROUTING 1 -i tun0 -p udp --dport 53 -m comment --comment SM-OVPN-DNS -j DNAT --to-destination "${ADGUARD_DNS}:53"
iptables -t nat -C PREROUTING -i tun0 -p tcp --dport 53 -m comment --comment SM-OVPN-DNS -j DNAT --to-destination "${ADGUARD_DNS}:53" 2>/dev/null \
  || iptables -t nat -I PREROUTING 1 -i tun0 -p tcp --dport 53 -m comment --comment SM-OVPN-DNS -j DNAT --to-destination "${ADGUARD_DNS}:53"
iptables -C FORWARD -s 10.9.0.0/24 -d 10.42.42.0/24 -m comment --comment SM-OVPN-DNS -j ACCEPT 2>/dev/null \
  || iptables -I FORWARD 1 -s 10.9.0.0/24 -d 10.42.42.0/24 -m comment --comment SM-OVPN-DNS -j ACCEPT
iptables -C FORWARD -s 10.42.42.0/24 -d 10.9.0.0/24 -m comment --comment SM-OVPN-DNS -j ACCEPT 2>/dev/null \
  || iptables -I FORWARD 1 -s 10.42.42.0/24 -d 10.9.0.0/24 -m comment --comment SM-OVPN-DNS -j ACCEPT
iptables -t nat -C POSTROUTING -s 10.9.0.0/24 -d 10.42.42.0/24 -m comment --comment SM-OVPN-DNS -j MASQUERADE 2>/dev/null \
  || iptables -t nat -I POSTROUTING 1 -s 10.9.0.0/24 -d 10.42.42.0/24 -m comment --comment SM-OVPN-DNS -j MASQUERADE

if command -v ufw >/dev/null 2>&1; then
  ufw allow 8443/tcp comment "OpenVPN TCP school" >/dev/null 2>&1 || true
fi
