#!/bin/bash
# Build / refresh an OpenVPN client .ovpn (expects cert already issued).
# Profiles are OpenVPN Connect–compatible (no Community-only directives).
set -euo pipefail
export PATH="/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
NAME="${1:?client name}"
HOST="${OVPN_HOST:-74.208.76.213}"
PORT="${OVPN_PORT:-443}"
PROTO="${OVPN_PROTO:-tcp}"
ROOT=/opt/openvpn
PKI=$ROOT/easy-rsa/pki
OUT="$ROOT/clients/${NAME}.ovpn"
REDIRECT="${OVPN_REDIRECT_GATEWAY:-}"
# connect = OpenVPN Connect (Windows/iOS/Android); community = classic GUI extras
STYLE="${OVPN_PROFILE_STYLE:-connect}"

[ -f "$PKI/issued/${NAME}.crt" ] || { echo "missing cert $NAME" >&2; exit 1; }
[ -f "$PKI/private/${NAME}.key" ] || { echo "missing key $NAME" >&2; exit 1; }
[ -f "$PKI/ta.key" ] || { echo "missing tls-auth ta.key" >&2; exit 1; }
[ -f "$PKI/ca.crt" ] || { echo "missing ca.crt" >&2; exit 1; }

# Default: phone/laptop clients get full tunnel; site routers (flint) do not.
if [ -z "$REDIRECT" ]; then
  if [ "$NAME" = "flint" ]; then
    REDIRECT=0
  else
    REDIRECT=1
  fi
fi

{
  echo "client"
  echo "dev tun"
  echo "proto ${PROTO}"
  echo "remote ${HOST} ${PORT}"
  echo "nobind"
  echo "remote-cert-tls server"
  echo "cipher AES-256-CBC"
  echo "auth SHA256"
  echo "key-direction 1"
  echo "verb 3"
  # Community-only options break OpenVPN Connect ("unsupported options"):
  # resolv-retry, persist-key, persist-tun, mute, connect-retry, block-outside-dns
  if [ "$STYLE" = "community" ]; then
    echo "resolv-retry infinite"
    echo "persist-key"
    echo "persist-tun"
    echo "mute 20"
    echo "connect-retry 2"
  fi
  if [ "$REDIRECT" = "1" ] || [ "$REDIRECT" = "true" ] || [ "$REDIRECT" = "yes" ]; then
    echo "redirect-gateway def1"
    # AdGuard via tun DNS DNAT (10.9.0.1:53 → 10.42.42.44). Rewrites
    # portal/admin → 10.9.0.1 so Caddy sees a VPN client_ip.
    echo "dhcp-option DNS 10.9.0.1"
    if [ "$STYLE" = "community" ]; then
      echo "block-outside-dns"
    fi
  fi
  echo "route 192.168.8.0 255.255.255.0 vpn_gateway"
  echo "route 10.8.0.0 255.255.255.0 vpn_gateway"
  echo "<ca>"
  cat "$PKI/ca.crt"
  echo "</ca>"
  echo "<cert>"
  openssl x509 -in "$PKI/issued/${NAME}.crt"
  echo "</cert>"
  echo "<key>"
  cat "$PKI/private/${NAME}.key"
  echo "</key>"
  echo "<tls-auth>"
  cat "$PKI/ta.key"
  echo "</tls-auth>"
} > "$OUT"
chmod 600 "$OUT"
# Friendly alias for Flint router imports
if [ "$NAME" = "flint" ]; then
  cp -a "$OUT" "$ROOT/clients/GL-MT6000.ovpn"
  chmod 600 "$ROOT/clients/GL-MT6000.ovpn"
fi
echo "$OUT"
