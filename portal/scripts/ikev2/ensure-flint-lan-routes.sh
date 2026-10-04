#!/usr/bin/env bash
# Prefer OpenVPN path to Flint LAN while flint client is connected.
set -euo pipefail
STATUS="${OPENVPN_STATUS_LOG:-/var/log/openvpn-status.log}"
OVPN_GW="${OVPN_FLINT_VPN_IP:-10.9.0.2}"
TUN_IF="${OVPN_TUN_IF:-tun0}"
if grep -q '^flint,' "$STATUS" 2>/dev/null; then
  ip route replace 192.168.8.0/24 via "$OVPN_GW" dev "$TUN_IF" metric 5
  ip route replace 10.0.0.0/24 via "$OVPN_GW" dev "$TUN_IF" metric 5
fi
