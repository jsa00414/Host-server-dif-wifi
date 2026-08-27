#!/usr/bin/env bash
# Refresh strongSwan server cert from Caddy Let's Encrypt files.
set -euo pipefail

IKEV2_DIR="${IKEV2_DIR:-/opt/ikev2}"
IKEV2_HOST="${IKEV2_HOST:-portal.vpstruelord.com}"
CADDY_CERT_DIR="${CADDY_CERT_DIR:-/var/lib/docker/volumes/truemail_caddy_data/_data/caddy/certificates/acme-v02.api.letsencrypt.org-directory/${IKEV2_HOST}}"

CRT="${CADDY_CERT_DIR}/${IKEV2_HOST}.crt"
KEY="${CADDY_CERT_DIR}/${IKEV2_HOST}.key"

[[ -f "$CRT" && -f "$KEY" ]] || exit 0

mkdir -p "$IKEV2_DIR/certs" "$IKEV2_DIR/private" /etc/ipsec.d/certs /etc/ipsec.d/private
cp -f "$CRT" "$IKEV2_DIR/certs/server.crt"
cp -f "$KEY" "$IKEV2_DIR/private/server.key"
chmod 644 "$IKEV2_DIR/certs/server.crt"
chmod 600 "$IKEV2_DIR/private/server.key"
cp -f "$IKEV2_DIR/certs/server.crt" /etc/ipsec.d/certs/server.crt
cp -f "$IKEV2_DIR/private/server.key" /etc/ipsec.d/private/server.key
chmod 600 /etc/ipsec.d/private/server.key

if systemctl is-active --quiet strongswan-starter 2>/dev/null; then
  ipsec rereadall >/dev/null 2>&1 || true
  ipsec reload >/dev/null 2>&1 || true
fi
