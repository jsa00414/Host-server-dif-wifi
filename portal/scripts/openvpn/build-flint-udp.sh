#!/bin/bash
# Build Flint UDP client profile aimed at :1194 for ~100Mbps site tunnel.
set -euo pipefail
export PATH="/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
export OVPN_PROTO=udp
export OVPN_PORT=1194
export OVPN_REDIRECT_GATEWAY=0
ROOT=/opt/openvpn
bash "$ROOT/scripts/build-client.sh" flint
# Keep TCP profile as flint-tcp.ovpn backup; write UDP as flint.ovpn + GL-MT6000.ovpn
if [ -f "$ROOT/clients/flint.ovpn" ]; then
  # build-client already wrote flint.ovpn as UDP when OVPN_PROTO=udp
  cp -a "$ROOT/clients/flint.ovpn" "$ROOT/clients/flint-udp.ovpn"
  cp -a "$ROOT/clients/flint.ovpn" "$ROOT/clients/GL-MT6000.ovpn"
fi
# Also ensure a TCP fallback profile exists for campus-only days
if [ -f "$ROOT/clients/flint-tcp.ovpn" ]; then
  :
elif [ -f "$ROOT/server.conf" ]; then
  OVPN_PROTO=tcp OVPN_PORT=443 OVPN_REDIRECT_GATEWAY=0 bash "$ROOT/scripts/build-client.sh" flint
  cp -a "$ROOT/clients/flint.ovpn" "$ROOT/clients/flint-tcp.ovpn"
  # restore UDP as primary download name
  cp -a "$ROOT/clients/flint-udp.ovpn" "$ROOT/clients/flint.ovpn"
  cp -a "$ROOT/clients/flint-udp.ovpn" "$ROOT/clients/GL-MT6000.ovpn"
fi
echo "UDP profile: $ROOT/clients/flint-udp.ovpn"
