#!/usr/bin/env bash
# Restart Unbound / AdGuard (circle) / guest-dns when recursive DNS dies.
set -euo pipefail
LOG_TAG=sm-dns-health
dig_ok() {
  local ip="$1"
  dig +time=2 +tries=1 @"$ip" google.com A +short 2>/dev/null | grep -Eq '^[0-9]+\.'
}
log() { logger -t "$LOG_TAG" "$*"; echo "$*"; }

UNBOUND_IP="${UNBOUND_IP:-172.30.0.2}"
ADGUARD_IP="${ADGUARD_IP:-10.42.42.44}"
GUEST_DNS_IP="${GUEST_DNS_IP:-${VPN_GUEST_DNS:-10.42.42.45}}"
fail=0

if ! dig_ok "$UNBOUND_IP"; then
  log "unbound@$UNBOUND_IP dead — restarting sm-unbound"
  docker restart sm-unbound >/dev/null
  sleep 4
  dig_ok "$UNBOUND_IP" && log "unbound recovered" || log "unbound still bad"
  docker restart sm-pihole >/dev/null || true
fi

if ! dig_ok "$ADGUARD_IP"; then
  log "adguard@$ADGUARD_IP (circle) dead — restarting sm-adguard"
  docker restart sm-adguard >/dev/null
  sleep 3
  dig_ok "$ADGUARD_IP" && log "adguard recovered" || { log "adguard still bad"; fail=1; }
fi

if ! dig_ok "$GUEST_DNS_IP"; then
  log "guest-dns@$GUEST_DNS_IP dead — restarting sm-guest-dns"
  docker restart sm-guest-dns >/dev/null
  sleep 2
  dig_ok "$GUEST_DNS_IP" && log "guest-dns recovered" || { log "guest-dns still bad"; fail=1; }
fi

# Keep OVPN raw allow + guest DNAT exclusion in place (docker recreate drops raw).
if [[ -x /opt/wireguard/port-forward-ui/scripts/openvpn/ovpn-firewall.sh ]]; then
  /opt/wireguard/port-forward-ui/scripts/openvpn/ovpn-firewall.sh >/dev/null 2>&1 || true
elif [[ -x /usr/local/sbin/ovpn-firewall.sh ]]; then
  /usr/local/sbin/ovpn-firewall.sh >/dev/null 2>&1 || true
fi

exit "$fail"
