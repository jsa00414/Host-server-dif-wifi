#!/bin/bash
# Prefer UDP OpenVPN (tun1 / 10.9.1.2) for home LAN when Flint dials UDP.
set -u
WG_GW="${WG_LAN_GW:-10.42.42.42}"
OVPN_GW="${OVPN_FLINT_UDP_IP:-10.9.1.2}"
OVPN_DEV="${OVPN_UDP_DEV:-tun1}"

prefer_ovpn_lan_routes() {
  local cidr
  for cidr in 192.168.8.0/24 10.0.0.0/24 10.8.0.0/24; do
    local i=0
    while [ "$i" -lt 8 ]; do
      ip route del "$cidr" via "$WG_GW" 2>/dev/null || break
      i=$((i + 1))
    done
  done
  ip route replace 192.168.8.0/24 via "$OVPN_GW" dev "$OVPN_DEV" metric 4
  ip route replace 10.0.0.0/24 via "$OVPN_GW" dev "$OVPN_DEV" metric 4
  ip route replace 192.168.8.0/24 via "$WG_GW" metric 100 2>/dev/null || true
  ip route replace 10.0.0.0/24 via "$WG_GW" metric 100 2>/dev/null || true
  ip route replace 10.8.0.0/24 via "$WG_GW" metric 100 2>/dev/null || true
  ip link set dev "$OVPN_DEV" txqueuelen 10000 2>/dev/null || true
}

if [ "${common_name:-}" = "flint" ]; then
  prefer_ovpn_lan_routes
fi
exit 0
