#!/usr/bin/env bash
# Ensure IKEv2 clients (10.10.0.0/24) can reach the internet + AdGuard DNS.
# strongSwan assigns the pool, but FORWARD/MASQUERADE must be re-applied after
# reboot (iptables policy DROP on FORWARD). Safe to re-run.
set -euo pipefail

IKEV2_POOL="${IKEV2_POOL:-10.10.0.0/24}"
ADGUARD_DNS="${ADGUARD_DNS:-10.42.42.44}"
WAN_IF="${WAN_IF:-ens6}"
DNS_NET="${DNS_NET:-10.42.42.0/24}"

echo "ikev2 forward: pool=${IKEV2_POOL} wan=${WAN_IF} dns=${ADGUARD_DNS}"

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

# Persist best-effort (if netfilter-persistent / iptables-save present)
if command -v netfilter-persistent >/dev/null 2>&1; then
  netfilter-persistent save >/dev/null 2>&1 || true
elif command -v iptables-save >/dev/null 2>&1 && [[ -d /etc/iptables ]]; then
  iptables-save >/etc/iptables/rules.v4 2>/dev/null || true
fi

echo "--- NAT ---"
iptables -t nat -L POSTROUTING -n -v --line-numbers | grep -E 'SM-IKEV2|10\.10\.0' || true
iptables -t nat -L PREROUTING -n -v --line-numbers | grep -E 'SM-IKEV2|10\.10\.0' || true
echo "--- FORWARD ---"
iptables -L FORWARD -n -v --line-numbers | grep -E 'SM-IKEV2|10\.10\.0' || true
echo "ikev2 forward rules OK — reconnect ServerManager IKEv2 on the phone"
