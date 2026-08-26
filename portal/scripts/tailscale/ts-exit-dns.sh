#!/bin/bash
# Force Tailscale / WireGuard-exit DNS through AdGuard -> Pi-hole.
#
# Same as ss-exit-dns.sh: REDIRECT to :53 breaks clients because AdGuard only
# binds 127.0.0.1:53. DNAT to AdGuard on the wg-easy docker bridge instead.
set -euo pipefail
COMMENT="SM-TS-EXIT-DNS"
ACTION="${1:-status}"
IFACE="${2:-tailscale0}"
ADGUARD_CONTAINER="${ADGUARD_CONTAINER:-sm-adguard}"

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

adguard_bridge_ip() {
  local ip
  ip="$(
    docker inspect "$ADGUARD_CONTAINER" \
      --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' 2>/dev/null \
      | tr ' ' '\n' \
      | awk '/^10\.42\.42\./ { print; exit }'
  )"
  if [ -z "$ip" ]; then
    ip="$(
      docker inspect "$ADGUARD_CONTAINER" \
        --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' 2>/dev/null \
        | awk '{ print $1 }'
    )"
  fi
  printf '%s' "$ip"
}

add_rules() {
  if ! ss -lunp 2>/dev/null | grep -q '127.0.0.1:53'; then
    echo "AdGuard DNS not listening on 127.0.0.1:53" >&2
    return 1
  fi
  local ag_ip
  ag_ip="$(adguard_bridge_ip)"
  if [ -z "$ag_ip" ]; then
    echo "AdGuard container ${ADGUARD_CONTAINER} has no docker IP" >&2
    return 1
  fi
  del_rules
  local iface="$IFACE"
  if [ -z "$iface" ] && [ -f /opt/dns/ts-vpn-exit.state ]; then
    iface=$(grep '^IFACE=' /opt/dns/ts-vpn-exit.state 2>/dev/null | cut -d= -f2- || true)
  fi
  iface="${iface:-tailscale0}"
  local wg_ip
  wg_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' wg-easy 2>/dev/null | awk 'NF{print; exit}')"
  wg_ip="${wg_ip:-10.42.42.42}"
  for src in 10.8.0.0/24 192.168.8.0/24 10.0.0.0/24 "${wg_ip}/32"; do
    for proto in udp tcp; do
      iptables -t nat -A PREROUTING -s "$src" -p "$proto" --dport 53 \
        -m comment --comment "$COMMENT" -j DNAT --to-destination "${ag_ip}:53"
    done
  done
  if [ -n "$iface" ] && ip link show "$iface" >/dev/null 2>&1; then
    for proto in udp tcp; do
      iptables -t nat -A OUTPUT -o "$iface" -p "$proto" --dport 53 \
        -m comment --comment "$COMMENT" -j REDIRECT --to-ports 53
    done
  fi
  echo "enabled${iface:+ on ${iface}} via ${ag_ip}"
}

status_rules() {
  # Avoid `grep -q` under pipefail: early match SIGPIPEs iptables → false "disabled".
  local rules
  rules="$(iptables -t nat -S 2>/dev/null || true)"
  if printf '%s\n' "$rules" | grep -- "$COMMENT" >/dev/null; then
    echo "enabled"
    printf '%s\n' "$rules" | grep -- "$COMMENT" || true
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
