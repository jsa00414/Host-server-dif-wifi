#!/usr/bin/env bash
# Flint: keep circle (AdGuard .44) + guest (.45) DNS reachable and pin LAN
# dnsmasq upstream to AdGuard so WiFi keeps working when campus DNS dies.
set -euo pipefail

ENV_FILE="${PORTAL_ENV_FILE:-/opt/wireguard/port-forward-ui.env}"
FLINT_HOST="${FLINT_OVPN_IP:-10.9.0.2}"
OVPN_GW="${OVPN_VPS_VPN_IP:-10.9.0.1}"
ADGUARD_DNS="${OVPN_DNS_ADGUARD:-10.42.42.44}"
GUEST_DNS="${VPN_GUEST_DNS:-10.42.42.45}"

# shellcheck disable=SC1090
set -a
[ -f "$ENV_FILE" ] && . "$ENV_FILE"
set +a

ADGUARD_DNS="${OVPN_DNS_ADGUARD:-$ADGUARD_DNS}"
GUEST_DNS="${VPN_GUEST_DNS:-$GUEST_DNS}"
ADGUARD_DNS="${ADGUARD_DNS:-10.42.42.44}"
GUEST_DNS="${GUEST_DNS:-10.42.42.45}"

PASS="${ROUTER_PASS:-}"
if [ -z "$PASS" ] && [ -n "${ROUTER_PASS_B64:-}" ]; then
  PASS="$(
    ROUTER_PASS_B64="$ROUTER_PASS_B64" python3 -c \
      'import os,base64; print(base64.b64decode(os.environ["ROUTER_PASS_B64"]).decode())' \
      2>/dev/null || true
  )"
fi
[ -n "$PASS" ] || {
  echo "flint-dns: no ROUTER_PASS — skip"
  exit 0
}
command -v sshpass >/dev/null 2>&1 || {
  echo "flint-dns: sshpass missing — skip"
  exit 0
}

export SSHPASS="$PASS"
timeout 40 sshpass -e ssh -o StrictHostKeyChecking=no \
  -o PreferredAuthentications=password -o PubkeyAuthentication=no \
  -o ConnectTimeout=12 \
  "root@${FLINT_HOST}" \
  ADGUARD_DNS="$ADGUARD_DNS" GUEST_DNS="$GUEST_DNS" OVPN_GW="$OVPN_GW" \
  sh -s <<'FLINT'
set -euo pipefail
ADGUARD_DNS="${ADGUARD_DNS:-10.42.42.44}"
GUEST_DNS="${GUEST_DNS:-10.42.42.45}"
OVPN_GW="${OVPN_GW:-10.9.0.1}"

# Host routes via OVPN peer (on-link /24 alone is flaky for some VIP containers).
if ip link show ovpnclient1 >/dev/null 2>&1; then
  ip route replace "$ADGUARD_DNS" via "$OVPN_GW" dev ovpnclient1 metric 5 2>/dev/null || true
  ip route replace "$GUEST_DNS" via "$OVPN_GW" dev ovpnclient1 metric 5 2>/dev/null || true
fi

mkdir -p /tmp/dnsmasq.d /etc/dnsmasq.d
# Circle WiFi (LAN DHCP → 192.168.8.1): prefer AdGuard, Cloudflare fallback.
# Out-of-circle clients are DNATed to guest DNS before dnsmasq (SM-LAN-GUEST-DNS).
cat >/tmp/dnsmasq.d/sm-circle-upstream.conf <<EOF
# Managed by ensure-flint-circle-guest-dns.sh
# Prefer VPS circle DNS so LAN WiFi stays up when campus DNS flakes.
server=${ADGUARD_DNS}
server=1.1.1.1
server=8.8.8.8
EOF
cp -f /tmp/dnsmasq.d/sm-circle-upstream.conf /etc/dnsmasq.d/sm-circle-upstream.conf 2>/dev/null || true

# Persist routes across reboot via firewall.user snippet.
mkdir -p /etc/firewall.user.d
cat >/etc/firewall.user.d/sm-circle-guest-dns-routes.sh <<EOF
#!/bin/sh
# Managed by ensure-flint-circle-guest-dns.sh
ip route replace ${ADGUARD_DNS} via ${OVPN_GW} dev ovpnclient1 metric 5 2>/dev/null || true
ip route replace ${GUEST_DNS} via ${OVPN_GW} dev ovpnclient1 metric 5 2>/dev/null || true
EOF
chmod +x /etc/firewall.user.d/sm-circle-guest-dns-routes.sh
if [ -f /etc/firewall.user ]; then
  grep -q sm-circle-guest-dns-routes /etc/firewall.user 2>/dev/null || \
    echo '[ -f /etc/firewall.user.d/sm-circle-guest-dns-routes.sh ] && . /etc/firewall.user.d/sm-circle-guest-dns-routes.sh' >> /etc/firewall.user
fi

killall -HUP dnsmasq 2>/dev/null || true

_dns_ok() {
  local ip="$1"
  if command -v dig >/dev/null 2>&1; then
    dig +time=2 +tries=1 @"$ip" google.com A +short 2>/dev/null | grep -Eq '^[0-9]+\.'
  else
    nslookup google.com "$ip" 2>/dev/null | grep -Eq 'Address( [0-9]+)?: [0-9]+\.[0-9]+'
  fi
}
echo -n "circle_dns="; _dns_ok "$ADGUARD_DNS" && echo OK || echo FAIL
echo -n "guest_dns="; _dns_ok "$GUEST_DNS" && echo OK || echo FAIL
echo -n "lan_dnsmasq="; _dns_ok 192.168.8.1 && echo OK || echo FAIL
FLINT

echo "flint-circle-guest-dns: applied"
