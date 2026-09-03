#!/bin/bash
# Issue a new OpenVPN client cert and write its .ovpn profile.
set -euo pipefail
export PATH="/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
NAME="${1:?client name}"
REDIRECT="${2:-}"
ROOT=/opt/openvpn
EASY=$ROOT/easy-rsa
PKI=$EASY/pki

if ! [[ "$NAME" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$ ]]; then
  echo "invalid client name" >&2
  exit 2
fi
if [ "$NAME" = "server" ] || [ "$NAME" = "ca" ]; then
  echo "reserved name" >&2
  exit 2
fi

cd "$EASY"
if [ ! -f "$PKI/issued/${NAME}.crt" ]; then
  EASYRSA_BATCH=1 ./easyrsa build-client-full "$NAME" nopass
fi

export OVPN_REDIRECT_GATEWAY="${REDIRECT}"
/opt/openvpn/scripts/build-client.sh "$NAME"
