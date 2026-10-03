#!/bin/bash
# Keep Flint OpenVPN DNS healthy while leaving VPN mode as configured.
# Firmware 4.11+ gl-dns-v2: never force dnsmasq upstream to 10.9.0.1 (no DNS
# on the OVPN VIP). Prefer Automatic DNS and do not override VPN DNS.
# Do NOT change route_policy.global.mode — user may want global (0) or policy (1).
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
# Keep local LAN able to reach the router admin while the tunnel is up
for s in $(uci show ovpnclient 2>/dev/null | sed -n "s/^\(ovpnclient\.[^=]*\)\.local_access=.*/\1/p"); do
  uci set "${s}.local_access=1"
done
uci commit ovpnclient
# DNS fix only — do not change route_policy.global.mode
uci set gl-dns-v2.@dns[0].mode='auto' 2>/dev/null || true
uci set gl-dns-v2.@dns[0].override_vpn='0' 2>/dev/null || true
uci set gl-dns-v2.@dns[0].manual_enable='0' 2>/dev/null || true
uci commit gl-dns-v2 2>/dev/null || true
while uci -q delete dhcp.@dnsmasq[0].server; do :; done
uci set dhcp.@dnsmasq[0].noresolv='0' 2>/dev/null || true
uci commit dhcp 2>/dev/null || true
/etc/init.d/dnsmasq reload 2>/dev/null || /etc/init.d/dnsmasq restart 2>/dev/null || true
ip route replace 10.42.42.0/24 dev ovpnclient1 table 1011 2>/dev/null || true
echo "flint vpn mode=$(uci get route_policy.global.mode) local_access=1 dns=$(uci get gl-dns-v2.@dns[0].mode 2>/dev/null) override_vpn=$(uci get gl-dns-v2.@dns[0].override_vpn 2>/dev/null)"
REMOTE
