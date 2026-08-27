#!/usr/bin/env bash
# Refresh strongSwan server cert from Caddy Let's Encrypt files.
set -euo pipefail

IKEV2_DIR="${IKEV2_DIR:-/opt/ikev2}"
IKEV2_HOST="${IKEV2_HOST:-portal.vpstruelord.com}"
CADDY_CERT_DIR="${CADDY_CERT_DIR:-/var/lib/docker/volumes/truemail_caddy_data/_data/caddy/certificates/acme-v02.api.letsencrypt.org-directory/${IKEV2_HOST}}"

CRT="${CADDY_CERT_DIR}/${IKEV2_HOST}.crt"
KEY="${CADDY_CERT_DIR}/${IKEV2_HOST}.key"

[[ -f "$CRT" && -f "$KEY" ]] || exit 0

mkdir -p "$IKEV2_DIR/certs" "$IKEV2_DIR/private" /etc/ipsec.d/certs /etc/ipsec.d/private /etc/ipsec.d/cacerts

# Leaf only for leftcert; chain → cacerts
awk 'BEGIN{n=0} /BEGIN CERT/{n++} n==1{print} n>1{exit}' "$CRT" > "$IKEV2_DIR/certs/server.crt"
awk 'BEGIN{n=0} /BEGIN CERT/{n++} n>1{print}' "$CRT" > "$IKEV2_DIR/certs/chain.pem"
cp -f "$KEY" "$IKEV2_DIR/private/server.key"
chmod 644 "$IKEV2_DIR/certs/server.crt"
chmod 600 "$IKEV2_DIR/private/server.key"

cp -f "$IKEV2_DIR/certs/server.crt" /etc/ipsec.d/certs/server.crt
cp -f "$IKEV2_DIR/private/server.key" /etc/ipsec.d/private/server.key
chmod 600 /etc/ipsec.d/private/server.key
if grep -q "BEGIN CERTIFICATE" "$IKEV2_DIR/certs/chain.pem"; then
  cp -f "$IKEV2_DIR/certs/chain.pem" /etc/ipsec.d/cacerts/le-intermediate.pem
fi

# Keep secrets algorithm in sync (LE renewals stay ECDSA; self-signed may be RSA)
if [[ -f /etc/ipsec.secrets ]]; then
  KEY_ALG="ECDSA"
  if openssl pkey -in /etc/ipsec.d/private/server.key -noout -text 2>/dev/null | grep -qi "RSA Private"; then
    KEY_ALG="RSA"
  fi
  sed -i -E "s/^: (RSA|ECDSA) /: ${KEY_ALG} /" /etc/ipsec.secrets || true
fi

if systemctl is-active --quiet strongswan-starter 2>/dev/null; then
  ipsec rereadall >/dev/null 2>&1 || true
  ipsec rereadsecrets >/dev/null 2>&1 || true
  ipsec reload >/dev/null 2>&1 || true
fi
