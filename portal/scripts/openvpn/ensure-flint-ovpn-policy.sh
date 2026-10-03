#!/bin/bash
# Keep Flint OpenVPN as site-to-site: policy mode + local LAN access.
# Global mode (route_policy.global.mode=0) blackholes br-lan and home Wi‑Fi
# stops loading anything while the tunnel is up.
set -euo pipefail
ENV_FILE="${PORTAL_ENV_FILE:-/opt/wireguard/port-forward-ui.env}"
OVPN_GW="${OVPN_FLINT_IP:-10.9.0.2}"
# shellcheck disable=SC1090
set -a
[ -f "$ENV_FILE" ] && . "$ENV_FILE"
set +a
PASS="${ROUTER_PASS:-}"
if [ -z "$PASS" ] && [ -n "${ROUTER_PASS_B64:-}" ]; then
  PASS="$(
    ROUTER_PASS_B64="$ROUTER_PASS_B64" python3 -c \
      'import os,base64; print(base64.b64decode(os.environ["ROUTER_PASS_B64"]).decode())' \
      2>/dev/null || true
  )"
fi
[ -n "$PASS" ] || exit 0
command -v sshpass >/dev/null 2>&1 || exit 0
export SSHPASS="$PASS"
sshpass -e ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password \
  -o PubkeyAuthentication=no -o ConnectTimeout=8 "root@${OVPN_GW}" sh -s <<'REMOTE'
uci set route_policy.global.mode='1'
for s in $(uci show ovpnclient 2>/dev/null | sed -n "s/^\(ovpnclient\.[^=]*\)\.local_access=.*/\1/p"); do
  uci set "${s}.local_access=1"
done
uci commit route_policy
uci commit ovpnclient
/etc/init.d/vpn-client reload 2>/dev/null || true
ip rule del from all iif br-lan blackhole 2>/dev/null || true
echo "flint ovpn policy mode=$(uci get route_policy.global.mode) local_access=1"
REMOTE
