#!/usr/bin/env bash
# Restart Unbound (and bounce Pi-hole if needed) / AdGuard when recursive DNS dies.
set -euo pipefail
LOG_TAG=sm-dns-health
dig_ok() {
  local ip="$1"
  dig +time=2 +tries=1 @"$ip" google.com A +short 2>/dev/null | grep -Eq '^[0-9]+\.'
}
log() { logger -t "$LOG_TAG" "$*"; echo "$*"; }

UNBOUND_IP="${UNBOUND_IP:-172.30.0.2}"
ADGUARD_IP="${ADGUARD_IP:-10.42.42.44}"

if ! dig_ok "$UNBOUND_IP"; then
  log "unbound@$UNBOUND_IP dead — restarting sm-unbound"
  docker restart sm-unbound >/dev/null
  sleep 4
  dig_ok "$UNBOUND_IP" && log "unbound recovered" || log "unbound still bad"
  docker restart sm-pihole >/dev/null || true
fi

if ! dig_ok "$ADGUARD_IP"; then
  log "adguard@$ADGUARD_IP dead — restarting sm-adguard"
  docker restart sm-adguard >/dev/null
  sleep 3
  dig_ok "$ADGUARD_IP" && log "adguard recovered" || { log "adguard still bad"; exit 1; }
fi
exit 0
