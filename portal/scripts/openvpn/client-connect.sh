#!/bin/bash
# Prefer OpenVPN for home LAN while Flint is connected; keep WG as fallback.
# Also push Flint firewall rules so VPS can reach Buffalo admin/files.
set -u

WG_GW="${WG_LAN_GW:-10.42.42.42}"
OVPN_GW="${OVPN_FLINT_IP:-10.9.0.2}"
ENV_FILE="${PORTAL_ENV_FILE:-/opt/wireguard/port-forward-ui.env}"
ALLOW_SCRIPT="${OVPN_ALLOW_SCRIPT:-/opt/openvpn/scripts/flint-allow-vpn-ssh.sh}"

demote_wg_lan_routes() {
  # Unmetered WG routes beat OVPN metric 5 — delete every via-$WG_GW copy first.
  local cidr
  for cidr in 192.168.8.0/24 10.0.0.0/24 10.8.0.0/24; do
    local i=0
    while [ "$i" -lt 8 ]; do
      ip route del "$cidr" via "$WG_GW" 2>/dev/null || break
      i=$((i + 1))
    done
  done
}

prefer_ovpn_lan_routes() {
  demote_wg_lan_routes
  ip route replace 192.168.8.0/24 via "$OVPN_GW" dev tun0 metric 5
  ip route replace 10.0.0.0/24 via "$OVPN_GW" dev tun0 metric 5
  ip route replace 192.168.8.0/24 via "$WG_GW" metric 100 2>/dev/null || true
  ip route replace 10.0.0.0/24 via "$WG_GW" metric 100 2>/dev/null || true
  ip route replace 10.8.0.0/24 via "$WG_GW" metric 100 2>/dev/null || true
}

push_flint_lan_allow() {
  # Non-blocking: OpenVPN must not wait on SSH.
  (
    sleep 2
    [ -f "$ALLOW_SCRIPT" ] || exit 0
    # shellcheck disable=SC1090
    set -a
    [ -f "$ENV_FILE" ] && . "$ENV_FILE"
    set +a
    PASS="${ROUTER_PASS:-}"
    if [ -z "$PASS" ] && [ -n "${ROUTER_PASS_B64:-}" ]; then
      PASS="$(ROUTER_PASS_B64="$ROUTER_PASS_B64" python3 -c 'import os,base64; print(base64.b64decode(os.environ["ROUTER_PASS_B64"]).decode())' 2>/dev/null || true)"
    fi
    [ -n "$PASS" ] || exit 0
    export SSHPASS="$PASS"
    command -v sshpass >/dev/null 2>&1 || exit 0
    # Flint dropbear often has no sftp-server — pipe the script over SSH.
    sshpass -e ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password \
      -o PubkeyAuthentication=no -o ConnectTimeout=8 \
      "root@${OVPN_GW}" "cat > /tmp/flint-allow-vpn-ssh.sh && chmod +x /tmp/flint-allow-vpn-ssh.sh && sh /tmp/flint-allow-vpn-ssh.sh" \
      < "$ALLOW_SCRIPT" 2>/dev/null || true
  ) >/tmp/sm-ovpn-flint-lan.log 2>&1 &
}

if [ "${common_name:-}" = "flint" ]; then
  prefer_ovpn_lan_routes
  push_flint_lan_allow
fi
exit 0
