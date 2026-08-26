#!/bin/bash
# When Flint leaves OpenVPN, restore WireGuard as the home-LAN path.
set -u

WG_GW="${WG_LAN_GW:-10.42.42.42}"
OVPN_GW="${OVPN_FLINT_IP:-10.9.0.2}"

if [ "${common_name:-}" = "flint" ]; then
  ip route del 192.168.8.0/24 via "$OVPN_GW" dev tun0 metric 5 2>/dev/null || true
  ip route del 10.0.0.0/24 via "$OVPN_GW" dev tun0 metric 5 2>/dev/null || true
  ip route del 192.168.8.0/24 via "$OVPN_GW" dev tun0 metric 50 2>/dev/null || true
  ip route del 10.0.0.0/24 via "$OVPN_GW" dev tun0 metric 50 2>/dev/null || true
  # Remove leftover unmetered WG routes, then restore a single metric-10 path.
  for cidr in 192.168.8.0/24 10.0.0.0/24 10.8.0.0/24; do
    i=0
    while [ "$i" -lt 8 ]; do
      ip route del "$cidr" via "$WG_GW" 2>/dev/null || break
      i=$((i + 1))
    done
    ip route replace "$cidr" via "$WG_GW" metric 10 2>/dev/null || true
  done
fi
exit 0
