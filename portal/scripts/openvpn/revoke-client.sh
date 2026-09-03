#!/bin/bash
# Revoke an OpenVPN client and remove its .ovpn (does not stop active sessions instantly).
set -euo pipefail
export PATH="/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
NAME="${1:?client name}"
ROOT=/opt/openvpn
EASY=$ROOT/easy-rsa
PKI=$EASY/pki

if [ "$NAME" = "server" ] || [ "$NAME" = "ca" ] || [ "$NAME" = "flint" ]; then
  echo "refusing to revoke protected client: $NAME" >&2
  exit 2
fi
if ! [[ "$NAME" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$ ]]; then
  echo "invalid client name" >&2
  exit 2
fi

cd "$EASY"
if [ -f "$PKI/issued/${NAME}.crt" ]; then
  EASYRSA_BATCH=1 ./easyrsa revoke "$NAME" || true
  EASYRSA_BATCH=1 ./easyrsa gen-crl || true
  # Install CRL if server supports it
  if [ -f "$PKI/crl.pem" ]; then
    cp -a "$PKI/crl.pem" "$ROOT/crl.pem"
    chmod 644 "$ROOT/crl.pem"
  fi
fi
rm -f "$ROOT/clients/${NAME}.ovpn"
echo "revoked $NAME"
