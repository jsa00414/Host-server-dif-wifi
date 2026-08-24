#!/bin/bash
# VPS keeps public IP. WireGuard clients exit via Surfshark WG tunnel.
set -uo pipefail

STATE_FILE="/opt/surfshark/ss-vpn-exit.state"
MANAGE="/opt/surfshark/ss-manage.sh"
TS_DISABLE="/opt/dns/ts-vpn-exit.sh"
MANGLE_COMMENT="SM-SS-VPN-EXIT"
MARK="0x184"
RT_TABLE="53"
WG_EASY_IP="10.42.42.42"
ACTION="${1:-status}"
SERVER="${2:-}"

PUBLIC_IP="$(ip -4 -o addr show dev ens6 2>/dev/null | awk '{print $4}' | head -1 | cut -d/ -f1)"
PUBLIC_IP="${PUBLIC_IP:-74.208.54.132}"

del_ip_rules() {
  local prio
  for prio in 100 101 102 103 104 105 106 107 108 150 160 200; do
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
  iptables -t mangle -A PREROUTING -s 192.168.8.0/24 -i br-1c0f4d1d4b87 -j SM-SS-VPN-EXIT
  iptables -t mangle -A PREROUTING -s 10.0.0.0/24 -i br-1c0f4d1d4b87 -j SM-SS-VPN-EXIT
  iptables -t mangle -A PREROUTING -s "$WG_EASY_IP"/32 -i br-1c0f4d1d4b87 -j SM-SS-VPN-EXIT
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
  ip rule add priority 108 to 74.208.54.0/24 lookup main 2>/dev/null || true
  ip rule add priority 150 fwmark "$MARK" lookup "$RT_TABLE" 2>/dev/null || true
  ip rule add priority 200 from all lookup main 2>/dev/null || true
}

wg_easy_masq_off() {
  docker exec wg-easy iptables -t nat -C POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE 2>/dev/null \
    && docker exec wg-easy iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE 2>/dev/null \
    || true
  local iface="$1"
  iptables -t nat -C POSTROUTING -s 10.8.0.0/24 -o ens6 -m comment --comment "$MANGLE_COMMENT" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -I POSTROUTING 1 -s 10.8.0.0/24 -o ens6 -m comment --comment "$MANGLE_COMMENT" -j MASQUERADE
  iptables -t nat -C POSTROUTING -s 192.168.8.0/24 -o ens6 -m comment --comment "$MANGLE_COMMENT" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -I POSTROUTING 1 -s 192.168.8.0/24 -o ens6 -m comment --comment "$MANGLE_COMMENT" -j MASQUERADE
  iptables -t nat -C POSTROUTING -s 10.0.0.0/24 -o ens6 -m comment --comment "$MANGLE_COMMENT" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -I POSTROUTING 1 -s 10.0.0.0/24 -o ens6 -m comment --comment "$MANGLE_COMMENT" -j MASQUERADE
  iptables -t nat -C POSTROUTING -s 10.8.0.0/24 -o "$iface" -m comment --comment "$MANGLE_COMMENT" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -I POSTROUTING 1 -s 10.8.0.0/24 -o "$iface" -m comment --comment "$MANGLE_COMMENT" -j MASQUERADE
  iptables -t nat -C POSTROUTING -s 192.168.8.0/24 -o "$iface" -m comment --comment "$MANGLE_COMMENT" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -I POSTROUTING 1 -s 192.168.8.0/24 -o "$iface" -m comment --comment "$MANGLE_COMMENT" -j MASQUERADE
  iptables -t nat -C POSTROUTING -s 10.0.0.0/24 -o "$iface" -m comment --comment "$MANGLE_COMMENT" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -I POSTROUTING 1 -s 10.0.0.0/24 -o "$iface" -m comment --comment "$MANGLE_COMMENT" -j MASQUERADE
  iptables -t nat -C POSTROUTING -s "$WG_EASY_IP"/32 -o "$iface" -m comment --comment "$MANGLE_COMMENT" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -I POSTROUTING 1 -s "$WG_EASY_IP"/32 -o "$iface" -m comment --comment "$MANGLE_COMMENT" -j MASQUERADE
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
  echo "surfshark vpn-exit enabled via ${server} (${ifname}); VPS→${PUBLIC_IP}"
}

disable_vpn_exit() {
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
