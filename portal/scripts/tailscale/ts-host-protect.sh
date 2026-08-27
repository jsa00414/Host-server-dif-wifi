#!/bin/bash
# Keep VPS→Flint / wg-easy paths working while Tailscale is running.
set -uo pipefail

STATE_FILE="/opt/dns/ts-host-protect.state"
PUBLIC_IP="$(ip -4 -o addr show dev ens6 2>/dev/null | awk '{print $4}' | head -1 | cut -d/ -f1)"
PUBLIC_IP="${PUBLIC_IP:-74.208.54.132}"
ACTION="${1:-status}"

wg_easy_ip() {
  docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' wg-easy 2>/dev/null \
    | awk 'NF{print; exit}'
}

wg_docker_bridge() {
  local ip="${1:-$(wg_easy_ip)}"
  [ -n "$ip" ] || return 1
  ip -4 route get "$ip" 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit }}'
}

WG_EASY_IP="$(wg_easy_ip)"
WG_DOCKER_BRIDGE="$(wg_docker_bridge "$WG_EASY_IP")"

tailscale_running() {
  ip link show tailscale0 >/dev/null 2>&1
}

del_ip_rules() {
  local prio
  for prio in 100 101 102 103 104 105 106 107 108; do
    local i=0
    while [ "$i" -lt 12 ]; do
      ip rule del priority "$prio" 2>/dev/null || break
      i=$((i + 1))
    done
  done
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
}

del_router_routes() {
  local ip bridge
  ip="$(wg_easy_ip)"
  bridge="$(wg_docker_bridge "$ip")"
  [ -n "$ip" ] || return 0
  [ -n "$bridge" ] || return 0
  ip route del 10.8.0.0/24 via "$ip" dev "$bridge" 2>/dev/null || true
  ip route del 192.168.8.0/24 via "$ip" dev "$bridge" 2>/dev/null || true
  ip route del "${ip}/32" dev "$bridge" 2>/dev/null || true
}

add_router_routes() {
  del_router_routes
  [ -n "$WG_EASY_IP" ] || return 0
  [ -n "$WG_DOCKER_BRIDGE" ] || return 0
  ip route replace 10.8.0.0/24 via "$WG_EASY_IP" dev "$WG_DOCKER_BRIDGE" metric 10 2>/dev/null || true
  ip route replace 192.168.8.0/24 via "$WG_EASY_IP" dev "$WG_DOCKER_BRIDGE" metric 10 2>/dev/null || true
  ip route replace "${WG_EASY_IP}/32" dev "$WG_DOCKER_BRIDGE" metric 5 2>/dev/null || true
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

enable_protect() {
  if ! tailscale_running; then
    echo "tailscale not running" >&2
    return 1
  fi
  WG_EASY_IP="$(wg_easy_ip)"
  WG_DOCKER_BRIDGE="$(wg_docker_bridge "$WG_EASY_IP")"
  add_ip_rules
  add_router_routes
  wg_easy_peer_masq_on
  printf 'ENABLED=1\nPUBLIC_IP=%s\nWG_EASY_IP=%s\n' "$PUBLIC_IP" "${WG_EASY_IP:-}" > "$STATE_FILE"
  echo "ts-host-protect enabled (VPS→Flint via wg-easy)"
}

disable_protect() {
  del_ip_rules
  del_router_routes
  rm -f "$STATE_FILE"
  echo "ts-host-protect disabled"
}

status_protect() {
  if [ -f "$STATE_FILE" ]; then cat "$STATE_FILE"; else echo "ENABLED=0"; fi
  echo "--- routes ---"
  ip -4 route show table main 2>/dev/null | grep -E '10\.8\.0\.|192\.168\.8\.|10\.42\.42\.' || true
  echo "--- ip rules ---"
  ip rule show | sed -n '1,20p'
}

case "$ACTION" in
  enable) enable_protect ;;
  disable) disable_protect ;;
  protect-only)
    if tailscale_running; then
      enable_protect || true
    fi
    echo "protect-only"
    ;;
  status) status_protect ;;
  *) echo "usage: $0 enable|disable|protect-only|status" >&2; exit 2 ;;
esac
