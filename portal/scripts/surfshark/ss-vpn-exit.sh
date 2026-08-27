#!/bin/bash
# VPS keeps public IP. WireGuard clients exit via Surfshark WG tunnel.
set -uo pipefail

STATE_FILE="/opt/surfshark/ss-vpn-exit.state"
MANAGE="/opt/surfshark/ss-manage.sh"
TS_DISABLE="/opt/dns/ts-vpn-exit.sh"
SS_EXIT_DNS="/opt/surfshark/ss-exit-dns.sh"
MANGLE_COMMENT="SM-SS-VPN-EXIT"
MARK="0x184"
RT_TABLE="53"
ACTION="${1:-status}"
SERVER="${2:-}"

PUBLIC_IP="$(ip -4 -o addr show dev ens6 2>/dev/null | awk '{print $4}' | head -1 | cut -d/ -f1)"
PUBLIC_IP="${PUBLIC_IP:-74.208.54.132}"

wg_easy_ip() {
  docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' wg-easy 2>/dev/null \
    | awk 'NF{print; exit}'
}

wg_docker_bridge() {
  local ip="${1:-$(wg_easy_ip)}"
  local bridge subnet net
  [ -n "$ip" ] || return 1
  subnet="$(echo "$ip" | awk -F. '{print $1"."$2"."$3".0/24"}')"
  bridge="$(ip -4 route show table main | awk -v s="$subnet" '$1==s && $0 !~ /via / { for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }')"
  if [ -n "$bridge" ] && [[ "$bridge" == br-* ]]; then
    printf '%s\n' "$bridge"
    return 0
  fi
  net="$(docker inspect wg-easy --format '{{range $k,$v := .NetworkSettings.Networks}}{{println $k}}{{end}}' 2>/dev/null | head -1)"
  if [ -n "$net" ]; then
    bridge="$(docker network inspect "$net" --format '{{if .Options}}{{index .Options "com.docker.network.bridge.name"}}{{end}}' 2>/dev/null)"
    if [ -n "$bridge" ]; then
      printf '%s\n' "$bridge"
      return 0
    fi
  fi
  return 1
}

WG_EASY_IP="$(wg_easy_ip)"
WG_DOCKER_BRIDGE="$(wg_docker_bridge "$WG_EASY_IP")"

del_ip_rules() {
  local prio
  for prio in 100 101 102 103 104 105 106 107 108 140 150 160 200; do
    local i=0
    while [ "$i" -lt 12 ]; do
      ip rule del priority "$prio" 2>/dev/null || break
      i=$((i+1))
    done
  done
}

del_mangle() {
  local line
  while line=$(iptables -t mangle -S PREROUTING 2>/dev/null | grep -E "SM-SS-VPN-EXIT|$MANGLE_COMMENT" | head -1); do
    [ -n "$line" ] || break
    line="${line/-A /-D }"
    # shellcheck disable=SC2086
    eval iptables -t mangle $line 2>/dev/null || break
  done
  iptables -t mangle -F SM-SS-VPN-EXIT 2>/dev/null || true
  iptables -t mangle -X SM-SS-VPN-EXIT 2>/dev/null || true
}

add_mangle() {
  del_mangle
  iptables -t mangle -N SM-SS-VPN-EXIT 2>/dev/null || iptables -t mangle -F SM-SS-VPN-EXIT
  iptables -t mangle -A SM-SS-VPN-EXIT -d 10.0.0.0/8 -j RETURN
  iptables -t mangle -A SM-SS-VPN-EXIT -d 172.16.0.0/12 -j RETURN
  iptables -t mangle -A SM-SS-VPN-EXIT -d 192.168.0.0/16 -j RETURN
  iptables -t mangle -A SM-SS-VPN-EXIT -d ${PUBLIC_IP}/32 -j RETURN
  iptables -t mangle -A SM-SS-VPN-EXIT -d 100.64.0.0/10 -j RETURN
  iptables -t mangle -A SM-SS-VPN-EXIT -m comment --comment "$MANGLE_COMMENT" -j MARK --set-mark "$MARK"
  iptables -t mangle -A PREROUTING -s 10.8.0.0/24 -j SM-SS-VPN-EXIT
  if [ -n "$WG_DOCKER_BRIDGE" ]; then
    iptables -t mangle -A PREROUTING -s 192.168.8.0/24 -i "$WG_DOCKER_BRIDGE" -j SM-SS-VPN-EXIT
    iptables -t mangle -A PREROUTING -s 10.0.0.0/24 -i "$WG_DOCKER_BRIDGE" -j SM-SS-VPN-EXIT
  fi
}

setup_table() {
  local iface="$1"
  ip route flush table "$RT_TABLE" 2>/dev/null || true
  ip route add default dev "$iface" table "$RT_TABLE" 2>/dev/null || true
}

add_ip_rules() {
  del_ip_rules
  ip rule add priority 100 from "${PUBLIC_IP}/32" lookup main 2>/dev/null || true
  ip rule add priority 101 to "${PUBLIC_IP}/32" lookup main 2>/dev/null || true
  ip rule add priority 102 to 10.8.0.0/24 lookup main 2>/dev/null || true
  ip rule add priority 103 to 192.168.8.0/24 lookup main 2>/dev/null || true
  ip rule add priority 104 to 10.42.42.0/24 lookup main 2>/dev/null || true
  ip rule add priority 105 to 10.0.0.0/24 lookup main 2>/dev/null || true
  ip rule add priority 106 to 172.16.0.0/12 lookup main 2>/dev/null || true
  ip rule add priority 107 to 127.0.0.0/8 lookup main 2>/dev/null || true
  ip rule add priority 108 to 100.64.0.0/10 lookup main 2>/dev/null || true
  ip rule add priority 140 fwmark "$MARK" lookup "$RT_TABLE" 2>/dev/null || true
  ip rule add priority 200 from all lookup main 2>/dev/null || true
}

wg_easy_peer_masq_on() {
  # Keep SNAT for VPS→Flint management traffic over the wg-easy tunnel.
  docker exec wg-easy sh -c '
    for iface in $(wg show interfaces 2>/dev/null); do
      iptables -t nat -C POSTROUTING -o "$iface" -j MASQUERADE 2>/dev/null \
        || iptables -t nat -A POSTROUTING -o "$iface" -j MASQUERADE 2>/dev/null \
        || true
    done
  ' 2>/dev/null || true
}

wg_easy_masq_off() {
  docker exec wg-easy iptables -t nat -C POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE 2>/dev/null \
    && docker exec wg-easy iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE 2>/dev/null \
    || true
  wg_easy_peer_masq_on
  local iface="$1"
  # Only SNAT WireGuard client egress via Surfshark — never via ens6 (VPS public IP).
  iptables -t nat -C POSTROUTING -s 10.8.0.0/24 -o "$iface" -m comment --comment "$MANGLE_COMMENT" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -I POSTROUTING 1 -s 10.8.0.0/24 -o "$iface" -m comment --comment "$MANGLE_COMMENT" -j MASQUERADE
  iptables -t nat -C POSTROUTING -s 192.168.8.0/24 -o "$iface" -m comment --comment "$MANGLE_COMMENT" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -I POSTROUTING 1 -s 192.168.8.0/24 -o "$iface" -m comment --comment "$MANGLE_COMMENT" -j MASQUERADE
  iptables -t nat -C POSTROUTING -s 10.0.0.0/24 -o "$iface" -m comment --comment "$MANGLE_COMMENT" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -I POSTROUTING 1 -s 10.0.0.0/24 -o "$iface" -m comment --comment "$MANGLE_COMMENT" -j MASQUERADE
}

wg_easy_masq_on() {
  docker exec wg-easy iptables -t nat -C POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE 2>/dev/null \
    || docker exec wg-easy iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE 2>/dev/null \
    || true
  local line
  while line=$(iptables -t nat -S POSTROUTING 2>/dev/null | grep -- "$MANGLE_COMMENT" | head -1); do
    [ -n "$line" ] || break
    line="${line/-A /-D }"
    # shellcheck disable=SC2086
    eval iptables -t nat $line 2>/dev/null || break
  done
}

save_state() {
  printf 'ENABLED=%s\nSERVER=%s\nIFACE=%s\nPUBLIC_IP=%s\n' "$1" "$2" "$3" "$PUBLIC_IP" > "$STATE_FILE"
}

enable_vpn_exit() {
  local server="$1"
  if [ -z "$server" ]; then
    echo "server name required" >&2
    return 2
  fi
  if [ -x "$TS_DISABLE" ]; then
    "$TS_DISABLE" disable 2>&1 || true
  fi
  local out rc ifname
  ifname="ss-${server}"
  out=$("$MANAGE" connect "$server" 2>&1)
  rc=$?
  echo "$out"
  if [ "$rc" -ne 0 ]; then
    save_state 0 "" ""
    return "$rc"
  fi
  if ! ip link show "$ifname" >/dev/null 2>&1; then
    echo "interface $ifname not up" >&2
    save_state 0 "" ""
    return 1
  fi
  wg_easy_masq_off "$ifname"
  setup_table "$ifname"
  add_mangle
  add_ip_rules
  save_state 1 "$server" "$ifname"
  if [ -x "$SS_EXIT_DNS" ]; then
    "$SS_EXIT_DNS" enable "$ifname" 2>&1 || true
  fi
  echo "surfshark vpn-exit enabled via ${server} (${ifname}); VPS→${PUBLIC_IP}"
}

disable_vpn_exit() {
  if [ -x "$SS_EXIT_DNS" ]; then
    "$SS_EXIT_DNS" disable 2>&1 || true
  fi
  "$MANAGE" disconnect 2>&1 || true
  del_mangle
  ip route flush table "$RT_TABLE" 2>/dev/null || true
  del_ip_rules
  wg_easy_masq_on
  save_state 0 "" ""
  echo "surfshark vpn-exit disabled"
}

status_vpn_exit() {
  if [ -f "$STATE_FILE" ]; then cat "$STATE_FILE"; else echo "ENABLED=0"; fi
  echo "--- servers ---"
  "$MANAGE" list 2>/dev/null || true
  echo "--- wg ---"
  wg show 2>/dev/null || true
  echo "--- ip rules ---"
  ip rule show | sed -n '1,40p'
}

case "$ACTION" in
  enable) enable_vpn_exit "$SERVER" ;;
  disable) disable_vpn_exit ;;
  protect-only)
    if [ -f "$STATE_FILE" ]; then
      ifname=$(grep '^IFACE=' "$STATE_FILE" | cut -d= -f2-)
      [ -n "$ifname" ] && ip link show "$ifname" >/dev/null 2>&1 && wg_easy_masq_off "$ifname" && setup_table "$ifname" && add_mangle && add_ip_rules
    fi
    echo "protect-only"
    ;;
  status) status_vpn_exit ;;
  *) echo "usage: $0 enable <server>|disable|protect-only|status" >&2; exit 2 ;;
esac
