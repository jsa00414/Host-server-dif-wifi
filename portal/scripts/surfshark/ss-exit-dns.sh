#!/bin/bash
# Force Surfshark / WireGuard-exit DNS through AdGuard -> Pi-hole (127.0.0.1:53)
set -euo pipefail
COMMENT="SM-SS-EXIT-DNS"
ACTION="${1:-status}"
IFACE="${2:-}"

del_rules() {
  local line
  while line=$(iptables -t nat -S PREROUTING 2>/dev/null | grep -- "$COMMENT" | head -1); do
    [ -n "$line" ] || break
    line="${line/-A /-D }"
    # shellcheck disable=SC2086
    eval iptables -t nat $line || break
  done
  while line=$(iptables -t nat -S OUTPUT 2>/dev/null | grep -- "$COMMENT" | head -1); do
    [ -n "$line" ] || break
    line="${line/-A /-D }"
    # shellcheck disable=SC2086
    eval iptables -t nat $line || break
  done
}

add_rules() {
  if ! ss -lunp 2>/dev/null | grep -q '127.0.0.1:53'; then
    echo "AdGuard DNS not listening on 127.0.0.1:53" >&2
    return 1
  fi
  del_rules
  local iface="$IFACE"
  if [ -z "$iface" ] && [ -f /opt/surfshark/ss-vpn-exit.state ]; then
    iface=$(grep '^IFACE=' /opt/surfshark/ss-vpn-exit.state 2>/dev/null | cut -d= -f2- || true)
  fi
  # Leaked/public DNS from WG + Flint subnets -> local AdGuard (2nd pass after CoreDNS path)
  for src in 10.8.0.0/24 192.168.8.0/24 10.0.0.0/24 10.42.42.42/32; do
    for proto in udp tcp; do
      iptables -t nat -A PREROUTING -s "$src" -p "$proto" --dport 53 \
        -m comment --comment "$COMMENT" -j REDIRECT --to-ports 53
    done
  done
  # DNS leaving via Surfshark tunnel -> back through AdGuard -> Pi-hole
  if [ -n "$iface" ] && ip link show "$iface" >/dev/null 2>&1; then
    for proto in udp tcp; do
      iptables -t nat -A OUTPUT -o "$iface" -p "$proto" --dport 53 \
        -m comment --comment "$COMMENT" -j REDIRECT --to-ports 53
      iptables -t nat -A PREROUTING -i "$iface" -p "$proto" --dport 53 \
        -m comment --comment "$COMMENT" -j REDIRECT --to-ports 53
    done
  fi
  echo "enabled${iface:+ on ${iface}}"
}

status_rules() {
  if iptables -t nat -S 2>/dev/null | grep -q -- "$COMMENT"; then
    echo "enabled"
    iptables -t nat -S PREROUTING 2>/dev/null | grep -- "$COMMENT" || true
    iptables -t nat -S OUTPUT 2>/dev/null | grep -- "$COMMENT" || true
    return 0
  fi
  echo "disabled"
  return 1
}

case "$ACTION" in
  enable) add_rules ;;
  disable) del_rules; echo "disabled" ;;
  status) status_rules ;;
  *) echo "usage: $0 enable|disable|status [iface]" >&2; exit 2 ;;
esac
