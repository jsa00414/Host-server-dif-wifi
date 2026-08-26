#!/bin/bash
set -euo pipefail
export PATH="/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
NAME="${1:?client name}"
HOST="${OVPN_HOST:-74.208.76.213}"
PORT="${OVPN_PORT:-8443}"
PROTO="${OVPN_PROTO:-tcp}"
ROOT=/opt/openvpn
PKI=$ROOT/easy-rsa/pki
OUT="$ROOT/clients/${NAME}.ovpn"
[ -f "$PKI/issued/${NAME}.crt" ] || { echo "missing cert $NAME" >&2; exit 1; }
{
  echo "client"
  echo "dev tun"
  echo "proto ${PROTO}-client"
  echo "remote ${HOST} ${PORT}"
  echo "resolv-retry infinite"
  echo "nobind"
  echo "persist-key"
  echo "persist-tun"
  echo "remote-cert-tls server"
  echo "cipher AES-256-GCM"
  echo "auth SHA256"
  echo "verb 3"
  echo "mute 20"
  if [ "$NAME" != "flint" ]; then
    echo "redirect-gateway def1 bypass-dhcp"
  fi
  echo "<ca>"
  cat "$PKI/ca.crt"
  echo "</ca>"
  echo "<cert>"
  openssl x509 -in "$PKI/issued/${NAME}.crt"
  echo "</cert>"
  echo "<key>"
  cat "$PKI/private/${NAME}.key"
  echo "</key>"
  echo "<tls-crypt>"
  cat "$PKI/tc.key"
  echo "</tls-crypt>"
} > "$OUT"
chmod 600 "$OUT"
echo "$OUT"
