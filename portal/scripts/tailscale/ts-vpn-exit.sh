#!/bin/bash
# VPS keeps public IP. WireGuard + OpenVPN clients exit via Tailscale exit node.
set -uo pipefail

STATE_FILE="/opt/dns/ts-vpn-exit.state"
SS_DISABLE="/opt/surfshark/ss-vpn-exit.sh"
TS_EXIT_DNS="/opt/dns/ts-exit-dns.sh"
TS_HOST_PROTECT="/opt/dns/ts-host-protect.sh"
MANGLE_COMMENT="SM-TS-VPN-EXIT"
MARK="0x174"
RT_TABLE="52"
TS_IFACE="tailscale0"
WG_SUBNET="${WG_SUBNET:-10.8.0.0/24}"
OVPN_SUBNET="${OVPN_SUBNET:-10.9.0.0/24}"
OVPN_IFACE="${OVPN_IFACE:-tun0}"
LAN_SUBNET="${LAN_SUBNET:-192.168.8.0/24}"
GL_SUBNET="${GL_SUBNET:-10.0.0.0/24}"
ACTION="${1:-status}"
EXIT_IP="${2:-}"

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

del_stale_wg_routes() {
  local ip="${1:-$(wg_easy_ip)}"
  [ -n "$ip" ] || return 0
  ip route del "$WG_SUBNET" via "$ip" dev tailscale0 2>/dev/null || true
  ip route del 192.168.8.0/24 via "$ip" dev tailscale0 2>/dev/null || true
  ip route del 10.0.0.0/24 via "$ip" dev tailscale0 2>/dev/null || true
  ip route del "${ip}/32" dev tailscale0 2>/dev/null || true
}

WG_EASY_IP="$(wg_easy_ip)"
WG_DOCKER_BRIDGE="$(wg_docker_bridge "$WG_EASY_IP")"

del_ip_rules() {
  local prio
  for prio in 150 160 200; do
    local i=0
    while [ "$i" -lt 12 ]; do
      ip rule del priority "$prio" 2>/dev/null || break
      i=$((i + 1))
    done
  done
}

add_ip_rules() {
  if [ -x "$TS_HOST_PROTECT" ]; then
    "$TS_HOST_PROTECT" enable 2>/dev/null || "$TS_HOST_PROTECT" protect-only 2>/dev/null || true
  fi
  del_ip_rules
  ip rule add priority 150 fwmark "$MARK" lookup "$RT_TABLE" 2>/dev/null || true
  ip rule add priority 200 from all lookup main 2>/dev/null || true
}

del_mangle() {
  local line
  while line=$(iptables -t mangle -S PREROUTING 2>/dev/null | grep -E "SM-TS-VPN-EXIT|$MANGLE_COMMENT" | head -1); do
    [ -n "$line" ] || break
    line="${line/-A /-D }"
    # shellcheck disable=SC2086
    eval iptables -t mangle $line 2>/dev/null || break
  done
  iptables -t mangle -F SM-TS-VPN-EXIT 2>/dev/null || true
  iptables -t mangle -X SM-TS-VPN-EXIT 2>/dev/null || true
}

add_mangle() {
  del_mangle
  WG_EASY_IP="$(wg_easy_ip)"
  WG_DOCKER_BRIDGE="$(wg_docker_bridge "$WG_EASY_IP")"
  del_stale_wg_routes "$WG_EASY_IP"
  iptables -t mangle -N SM-TS-VPN-EXIT 2>/dev/null || iptables -t mangle -F SM-TS-VPN-EXIT
  iptables -t mangle -A SM-TS-VPN-EXIT -d 10.0.0.0/8 -j RETURN
  iptables -t mangle -A SM-TS-VPN-EXIT -d 172.16.0.0/12 -j RETURN
  iptables -t mangle -A SM-TS-VPN-EXIT -d 192.168.0.0/16 -j RETURN
  iptables -t mangle -A SM-TS-VPN-EXIT -d ${PUBLIC_IP}/32 -j RETURN
  iptables -t mangle -A SM-TS-VPN-EXIT -d 100.64.0.0/10 -j RETURN
  iptables -t mangle -A SM-TS-VPN-EXIT -m comment --comment "$MANGLE_COMMENT" -j MARK --set-mark "$MARK"
  iptables -t mangle -A PREROUTING -s "$WG_SUBNET" -j SM-TS-VPN-EXIT
  iptables -t mangle -A PREROUTING -s "$OVPN_SUBNET" -j SM-TS-VPN-EXIT
  if ip link show "$OVPN_IFACE" >/dev/null 2>&1; then
    iptables -t mangle -A PREROUTING -s "$LAN_SUBNET" -i "$OVPN_IFACE" -j SM-TS-VPN-EXIT
    iptables -t mangle -A PREROUTING -s "$GL_SUBNET" -i "$OVPN_IFACE" -j SM-TS-VPN-EXIT
  fi
  if [ -n "$WG_DOCKER_BRIDGE" ]; then
    iptables -t mangle -A PREROUTING -s "$LAN_SUBNET" -i "$WG_DOCKER_BRIDGE" -j SM-TS-VPN-EXIT
    iptables -t mangle -A PREROUTING -s "$GL_SUBNET" -i "$WG_DOCKER_BRIDGE" -j SM-TS-VPN-EXIT
  fi
}

add_forward_rules() {
  local iface="$1"
  iptables -C FORWARD -i "$OVPN_IFACE" -o "$iface" -m comment --comment "$MANGLE_COMMENT" -j ACCEPT 2>/dev/null \
    || iptables -I FORWARD 1 -i "$OVPN_IFACE" -o "$iface" -m comment --comment "$MANGLE_COMMENT" -j ACCEPT
  iptables -C FORWARD -i "$iface" -o "$OVPN_IFACE" -m state --state RELATED,ESTABLISHED -m comment --comment "$MANGLE_COMMENT" -j ACCEPT 2>/dev/null \
    || iptables -I FORWARD 1 -i "$iface" -o "$OVPN_IFACE" -m state --state RELATED,ESTABLISHED -m comment --comment "$MANGLE_COMMENT" -j ACCEPT
  for subnet in "$LAN_SUBNET" "$GL_SUBNET"; do
    iptables -C FORWARD -s "$subnet" -o "$iface" -m comment --comment "$MANGLE_COMMENT" -j ACCEPT 2>/dev/null \
      || iptables -I FORWARD 1 -s "$subnet" -o "$iface" -m comment --comment "$MANGLE_COMMENT" -j ACCEPT
  done
}

del_forward_rules() {
  local line
  while line=$(iptables -S FORWARD 2>/dev/null | grep -- "$MANGLE_COMMENT" | head -1); do
    [ -n "$line" ] || break
    line="${line/-A /-D }"
    # shellcheck disable=SC2086
    eval iptables $line 2>/dev/null || break
  done
}

setup_table() {
  local iface="$1"
  ip route flush table "$RT_TABLE" 2>/dev/null || true
  ip route add default dev "$iface" table "$RT_TABLE" 2>/dev/null || true
}

add_client_masq() {
  local iface="$1"
  local subnet
  for subnet in "$WG_SUBNET" "$OVPN_SUBNET" "$LAN_SUBNET" "$GL_SUBNET"; do
    iptables -t nat -C POSTROUTING -s "$subnet" -o ens6 -m comment --comment "$MANGLE_COMMENT" -j MASQUERADE 2>/dev/null \
      || iptables -t nat -I POSTROUTING 1 -s "$subnet" -o ens6 -m comment --comment "$MANGLE_COMMENT" -j MASQUERADE
    iptables -t nat -C POSTROUTING -s "$subnet" -o "$iface" -m comment --comment "$MANGLE_COMMENT" -j MASQUERADE 2>/dev/null \
      || iptables -t nat -I POSTROUTING 1 -s "$subnet" -o "$iface" -m comment --comment "$MANGLE_COMMENT" -j MASQUERADE
  done
}

wg_easy_peer_masq_on() {
  docker exec wg-easy sh -c '
    for iface in $(wg show interfaces 2>/dev/null); do
      iptables -t nat -C POSTROUTING -o "$iface" -j MASQUERADE 2>/dev/null \
        || iptables -t nat -A POSTROUTING -o "$iface" -j MASQUERADE 2>/dev/null \
        || true
    done
  ' 2>/dev/null || true
}

wg_easy_masq_off() {
  docker exec wg-easy iptables -t nat -C POSTROUTING -s "$WG_SUBNET" -o eth0 -j MASQUERADE 2>/dev/null \
    && docker exec wg-easy iptables -t nat -D POSTROUTING -s "$WG_SUBNET" -o eth0 -j MASQUERADE 2>/dev/null \
    || true
  wg_easy_peer_masq_on
  add_client_masq "$1"
  if [ -n "$WG_EASY_IP" ]; then
    iptables -t nat -C POSTROUTING -s "$WG_EASY_IP"/32 -o "$1" -m comment --comment "$MANGLE_COMMENT" -j MASQUERADE 2>/dev/null \
      || iptables -t nat -I POSTROUTING 1 -s "$WG_EASY_IP"/32 -o "$1" -m comment --comment "$MANGLE_COMMENT" -j MASQUERADE
  fi
}

ovpn_masq_on() {
  iptables -t nat -C POSTROUTING -s "$OVPN_SUBNET" -o ens6 -m comment --comment SM-OVPN-MASQ -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -s "$OVPN_SUBNET" -o ens6 -m comment --comment SM-OVPN-MASQ -j MASQUERADE 2>/dev/null \
    || true
}

wg_easy_masq_on() {
  docker exec wg-easy iptables -t nat -C POSTROUTING -s "$WG_SUBNET" -o eth0 -j MASQUERADE 2>/dev/null \
    || docker exec wg-easy iptables -t nat -A POSTROUTING -s "$WG_SUBNET" -o eth0 -j MASQUERADE 2>/dev/null \
    || true
  local line
  while line=$(iptables -t nat -S POSTROUTING 2>/dev/null | grep -- "$MANGLE_COMMENT" | head -1); do
    [ -n "$line" ] || break
    line="${line/-A /-D }"
    # shellcheck disable=SC2086
    eval iptables -t nat $line 2>/dev/null || break
  done
  ovpn_masq_on
}

save_state() {
  printf 'ENABLED=%s\nEXIT_IP=%s\nIFACE=%s\nPUBLIC_IP=%s\n' "$1" "$2" "$3" "$PUBLIC_IP" > "$STATE_FILE"
}

enable_vpn_exit() {
  local exit_ip="$1"
  if [ -z "$exit_ip" ]; then
    echo "exit node IP required" >&2
    return 2
  fi
  if [ -x "$SS_DISABLE" ]; then
    "$SS_DISABLE" disable 2>&1 || true
  fi
  if ! ip link show "$TS_IFACE" >/dev/null 2>&1; then
    echo "tailscale interface $TS_IFACE not up" >&2
    save_state 0 "" ""
    return 1
  fi
  local ts_out ts_rc
  ts_out=$(tailscale set --exit-node="$exit_ip" --exit-node-allow-lan-access=true 2>&1)
  ts_rc=$?
  echo "$ts_out"
  if [ "$ts_rc" -ne 0 ]; then
    save_state 0 "" ""
    return "$ts_rc"
  fi
  wg_easy_masq_off "$TS_IFACE"
  setup_table "$TS_IFACE"
  add_mangle
  add_forward_rules "$TS_IFACE"
  add_ip_rules
  save_state 1 "$exit_ip" "$TS_IFACE"
  if [ -x "$TS_EXIT_DNS" ] && [ -f /opt/dns/ts-exit-dns.enabled ]; then
    "$TS_EXIT_DNS" enable "$TS_IFACE" 2>&1 || true
  fi
  echo "tailscale vpn-exit enabled via ${exit_ip}; VPS→${PUBLIC_IP} (WG ${WG_SUBNET}, OVPN ${OVPN_SUBNET}, LAN ${LAN_SUBNET}, GL ${GL_SUBNET})"
}

disable_vpn_exit() {
  tailscale set --exit-node= 2>&1 || true
  del_mangle
  del_forward_rules
  ip route flush table "$RT_TABLE" 2>/dev/null || true
  del_ip_rules
  del_stale_wg_routes "$(wg_easy_ip)"
  wg_easy_masq_on
  if [ -x "$TS_HOST_PROTECT" ]; then
    "$TS_HOST_PROTECT" protect-only 2>/dev/null || true
  fi
  save_state 0 "" ""
  echo "tailscale vpn-exit disabled"
}

status_vpn_exit() {
  if [ -f "$STATE_FILE" ]; then cat "$STATE_FILE"; else echo "ENABLED=0"; fi
  echo "--- tailscale ---"
  tailscale status 2>/dev/null || true
  echo "--- mangle ---"
  iptables -t mangle -S PREROUTING 2>/dev/null | grep SM-TS || true
  echo "--- ip rules ---"
  ip rule show | sed -n '1,40p'
}

case "$ACTION" in
  enable) enable_vpn_exit "$EXIT_IP" ;;
  disable) disable_vpn_exit ;;
  protect-only)
    if [ -f "$STATE_FILE" ]; then
      exit_ip=$(grep '^EXIT_IP=' "$STATE_FILE" | cut -d= -f2-)
      if grep -q '^ENABLED=1' "$STATE_FILE" 2>/dev/null \
        && ip link show "$TS_IFACE" >/dev/null 2>&1 \
        && [ -n "$exit_ip" ]; then
        tailscale set --exit-node="$exit_ip" --exit-node-allow-lan-access=true 2>/dev/null || true
        wg_easy_masq_off "$TS_IFACE"
        setup_table "$TS_IFACE"
        add_mangle
        add_forward_rules "$TS_IFACE"
        add_ip_rules
      fi
    fi
    echo "protect-only"
    ;;
  status) status_vpn_exit ;;
  *) echo "usage: $0 enable <exit-ip>|disable|protect-only|status" >&2; exit 2 ;;
esac
