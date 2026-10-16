#!/usr/bin/env bash
# Permanently deny shared campus/ISP egress (Neumann University NAT) from
# reaching portal/router HTTP(S) on the VPS. Complements Caddy @denied_wan.
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

if ufw status numbered 2>/dev/null | grep -q "$DENIED_IP"; then
  echo "ufw already denies $DENIED_IP"
else
  # Insert before the public Anywhere 80/443 allows when possible.
  if ufw status numbered 2>/dev/null | grep -qE '\[ *[0-9]+\] 80/tcp[[:space:]]+ALLOW IN[[:space:]]+Anywhere'; then
    ufw insert 3 deny from "$DENIED_IP" to any port 80,443 proto tcp comment "$COMMENT" || \
      ufw deny from "$DENIED_IP" to any port 80,443 proto tcp comment "$COMMENT"
  else
    ufw deny from "$DENIED_IP" to any port 80,443 proto tcp comment "$COMMENT"
  fi
  echo "ufw deny added for $DENIED_IP on 80/443"
fi
