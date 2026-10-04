#!/usr/bin/env bash
# Deny shared campus/ISP egress (Neumann University NAT) from reaching
# portal/router HTTP(S) at the *Caddy* layer (@denied_wan). Do NOT UFW-deny
# TCP 443 for that IP: OpenVPN is multiplexed on :443 via sslh, and a blanket
# deny blocks Flint/Windows OpenVPN from campus (sticky WAN 192.81.235.246).
#
# This script only ensures campus can still reach VPN ports, and reminds that
# HTTPS deny belongs in Caddy — not UFW on the shared 443 listener.
set -euo pipefail

DENIED_IP="${VPN_CIRCLE_DENIED_IPS:-192.81.235.246}"
DENIED_IP="${DENIED_IP%%[[:space:],;]*}"
COMMENT="deny-campus-neumann"

if [[ -z "$DENIED_IP" ]]; then
  echo "no denied IP configured"
  exit 0
fi

if ! command -v ufw >/dev/null 2>&1; then
  echo "ufw not installed"
  exit 0
fi

# Remove legacy UFW denials that black-hole OpenVPN on :443.
while ufw status numbered 2>/dev/null | grep -qE "${DENIED_IP}.*${COMMENT}|${COMMENT}.*${DENIED_IP}|deny.*${DENIED_IP}.*443"; do
  num=$(ufw status numbered 2>/dev/null | grep -E "${DENIED_IP}" | grep -iE 'DENY|REJECT' | head -1 | sed -n 's/^\[\s*\([0-9]*\)\].*/\1/p')
  [[ -n "$num" ]] || break
  ufw --force delete "$num" >/dev/null 2>&1 || break
  echo "removed legacy ufw deny #$num for $DENIED_IP (was blocking OVPN :443)"
done

# Explicit allows so campus sticky can use VPN even if a later blanket deny appears.
ufw allow from "$DENIED_IP" to any port 443 proto tcp comment 'campus-sticky-ovpn-443' >/dev/null 2>&1 || true
ufw allow from "$DENIED_IP" to any port 8443 proto tcp comment 'campus-sticky-ovpn-8443' >/dev/null 2>&1 || true
ufw allow from "$DENIED_IP" to any port 500 proto udp comment 'campus-sticky-ike' >/dev/null 2>&1 || true
ufw allow from "$DENIED_IP" to any port 4500 proto udp comment 'campus-sticky-ike' >/dev/null 2>&1 || true

echo "campus $DENIED_IP: VPN ports allowed; HTTPS forbid stays in Caddy @denied_wan (not UFW)"
