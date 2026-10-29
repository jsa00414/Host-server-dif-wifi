#!/bin/bash
# OpenVPN (tun0) forwarding + DNS access to circle (AdGuard) and guest DNS.
set -euo pipefail
export PATH="/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

ADGUARD_DNS="${ADGUARD_DNS:-${OVPN_DNS_ADGUARD:-10.42.42.44}}"
GUEST_DNS="${GUEST_DNS:-${VPN_GUEST_DNS:-10.42.42.45}}"

iptables -t nat -C POSTROUTING -s 10.9.0.0/24 -o ens6 -m comment --comment SM-OVPN-MASQ -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -o ens6 -m comment --comment SM-OVPN-MASQ -j MASQUERADE
# Flint LAN sources preserved across OVPN (circle→Xray / guest→sing-box). MASQ
# residual UDP/ICMP that is not TCP-REDIRECT'd into the proxies.
iptables -t nat -C POSTROUTING -s 192.168.8.0/24 -o ens6 -m comment --comment SM-LAN-MASQ -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s 192.168.8.0/24 -o ens6 -m comment --comment SM-LAN-MASQ -j MASQUERADE
iptables -C FORWARD -s 10.9.0.0/24 -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -s 10.9.0.0/24 -j ACCEPT
iptables -C FORWARD -d 10.9.0.0/24 -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -d 10.9.0.0/24 -j ACCEPT
iptables -C FORWARD -d 192.168.8.0/24 -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -d 192.168.8.0/24 -j ACCEPT
iptables -C FORWARD -s 192.168.8.0/24 -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -s 192.168.8.0/24 -j ACCEPT

# Docker raw PREROUTING drops traffic to container IPs unless it arrives on the
# docker bridge. That black-holes OpenVPN/IKEv2 clients trying to use AdGuard
# (circle) at .44 or guest-dns at .45. Allow VPN sources (and tun0) first.
for dns in "$ADGUARD_DNS" "$GUEST_DNS"; do
  [ -n "$dns" ] || continue
  tag="SM-VPN-DNS-ALLOW-TUN"
  [ "$dns" = "$GUEST_DNS" ] && tag="SM-VPN-DNS-ALLOW-TUN-GUEST"
  iptables -t raw -C PREROUTING -i tun0 -d "${dns}/32" -m comment --comment "$tag" -j ACCEPT 2>/dev/null \
    || iptables -t raw -I PREROUTING 1 -i tun0 -d "${dns}/32" -m comment --comment "$tag" -j ACCEPT
  for src in 10.9.0.0/24 10.10.0.0/24 10.8.0.0/24 192.168.8.0/24; do
    cmt="SM-VPN-DNS-ALLOW"
    [ "$dns" = "$GUEST_DNS" ] && cmt="SM-VPN-DNS-ALLOW-GUEST"
    iptables -t raw -C PREROUTING -s "$src" -d "${dns}/32" -m comment --comment "$cmt" -j ACCEPT 2>/dev/null \
      || iptables -t raw -I PREROUTING 1 -s "$src" -d "${dns}/32" -m comment --comment "$cmt" -j ACCEPT
  done
done

iptables -C FORWARD -s 10.9.0.0/24 -d 10.42.42.0/24 -m comment --comment SM-OVPN-DNS -j ACCEPT 2>/dev/null \
  || iptables -I FORWARD 1 -s 10.9.0.0/24 -d 10.42.42.0/24 -m comment --comment SM-OVPN-DNS -j ACCEPT
iptables -C FORWARD -s 10.42.42.0/24 -d 10.9.0.0/24 -m comment --comment SM-OVPN-DNS -j ACCEPT 2>/dev/null \
  || iptables -I FORWARD 1 -s 10.42.42.0/24 -d 10.9.0.0/24 -m comment --comment SM-OVPN-DNS -j ACCEPT

# Force OVPN client DNS to circle AdGuard, but do NOT rewrite queries already
# aimed at guest DNS (Flint SM-LAN-GUEST-DNS / out-of-circle clients).
while iptables -t nat -C PREROUTING -i tun0 -p udp --dport 53 -m comment --comment SM-OVPN-DNS -j DNAT --to-destination "${ADGUARD_DNS}:53" 2>/dev/null; do
  iptables -t nat -D PREROUTING -i tun0 -p udp --dport 53 -m comment --comment SM-OVPN-DNS -j DNAT --to-destination "${ADGUARD_DNS}:53" || break
done
while iptables -t nat -C PREROUTING -i tun0 -p tcp --dport 53 -m comment --comment SM-OVPN-DNS -j DNAT --to-destination "${ADGUARD_DNS}:53" 2>/dev/null; do
  iptables -t nat -D PREROUTING -i tun0 -p tcp --dport 53 -m comment --comment SM-OVPN-DNS -j DNAT --to-destination "${ADGUARD_DNS}:53" || break
done
iptables -t nat -C PREROUTING -i tun0 -p udp --dport 53 ! -d "${GUEST_DNS}/32" -m comment --comment SM-OVPN-DNS -j DNAT --to-destination "${ADGUARD_DNS}:53" 2>/dev/null \
  || iptables -t nat -I PREROUTING 1 -i tun0 -p udp --dport 53 ! -d "${GUEST_DNS}/32" -m comment --comment SM-OVPN-DNS -j DNAT --to-destination "${ADGUARD_DNS}:53"
iptables -t nat -C PREROUTING -i tun0 -p tcp --dport 53 ! -d "${GUEST_DNS}/32" -m comment --comment SM-OVPN-DNS -j DNAT --to-destination "${ADGUARD_DNS}:53" 2>/dev/null \
  || iptables -t nat -I PREROUTING 1 -i tun0 -p tcp --dport 53 ! -d "${GUEST_DNS}/32" -m comment --comment SM-OVPN-DNS -j DNAT --to-destination "${ADGUARD_DNS}:53"

iptables -t nat -C POSTROUTING -s 10.9.0.0/24 -d 10.42.42.0/24 -m comment --comment SM-OVPN-DNS -j MASQUERADE 2>/dev/null \
  || iptables -t nat -I POSTROUTING 1 -s 10.9.0.0/24 -d 10.42.42.0/24 -m comment --comment SM-OVPN-DNS -j MASQUERADE

if command -v ufw >/dev/null 2>&1; then
  ufw allow 8443/tcp comment "OpenVPN TCP school" >/dev/null 2>&1 || true
fi
