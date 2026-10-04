#!/bin/bash
# Install/refresh sm-guest-dns (CoreDNS NXDOMAIN for admin hosts) and point
# VPN_GUEST_DNS at 10.42.42.45 so guest/pending clients get a real DNS miss.
set -euo pipefail

DNS_ROOT="${DNS_ROOT:-/opt/dns}"
GUEST_DIR="${DNS_ROOT}/guest-nxdomain"
GUEST_IP="${VPN_GUEST_DNS_VIP:-10.42.42.45}"
ENV_FILE="${PORTAL_ENV_FILE:-/opt/wireguard/port-forward-ui.env}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

mkdir -p "$GUEST_DIR"
if [[ "$SCRIPT_DIR/Corefile" -ef "$GUEST_DIR/Corefile" ]]; then
  :
elif [[ -f "$SCRIPT_DIR/Corefile" ]]; then
  install -m 644 "$SCRIPT_DIR/Corefile" "$GUEST_DIR/Corefile"
fi

COMPOSE="${DNS_ROOT}/docker-compose.yml"
if [[ ! -f "$COMPOSE" ]]; then
  echo "missing $COMPOSE" >&2
  exit 1
fi

if ! grep -q 'container_name: sm-guest-dns' "$COMPOSE"; then
  python3 - "$COMPOSE" "$GUEST_IP" <<'PY'
import pathlib, sys
path = pathlib.Path(sys.argv[1])
vip = sys.argv[2]
text = path.read_text()
block = f"""
  guest-dns:
    image: coredns/coredns:1.11.3
    container_name: sm-guest-dns
    restart: unless-stopped
    command: ["-conf", "/Corefile"]
    volumes:
      - ./guest-nxdomain/Corefile:/Corefile:ro
    networks:
      sm_dns: {{}}
      wireguard_wg:
        ipv4_address: {vip}
"""
needle = "  inject:"
if needle not in text:
    raise SystemExit("could not find inject: service to insert guest-dns before")
if "sm-guest-dns" in text:
    raise SystemExit(0)
path.write_text(text.replace(needle, block + needle, 1))
print(f"inserted guest-dns service at {vip}")
PY
fi

cd "$DNS_ROOT"
docker compose up -d guest-dns

# Point portal env at guest VIP (used by IKEv2 + Flint guest DNAT scripts).
if [[ -f "$ENV_FILE" ]]; then
  if grep -q '^VPN_GUEST_DNS=' "$ENV_FILE"; then
    sed -i "s|^VPN_GUEST_DNS=.*|VPN_GUEST_DNS=${GUEST_IP}|" "$ENV_FILE"
  else
    printf '\nVPN_GUEST_DNS=%s\n' "$GUEST_IP" >>"$ENV_FILE"
  fi
  echo "VPN_GUEST_DNS=${GUEST_IP} in $ENV_FILE"
fi

# Smoke: portal must NXDOMAIN; google must resolve.
sleep 1
if command -v dig >/dev/null; then
  dig +time=2 +tries=1 @"$GUEST_IP" portal.vpstruelord.com A +noall +comments 2>/dev/null | grep -E 'status:|NXDOMAIN' || true
  dig +short +time=2 +tries=1 @"$GUEST_IP" example.com A | head -2 || true
fi

echo "guest-nxdomain dns ready at ${GUEST_IP}"
