#!/usr/bin/env bash
# Bind IKEv2 to the OpenVPN tunnel VIP and lock UDP 500/4500 to VPN clients.
#
# Flow: Connect OpenVPN first → AdGuard rewrites portal.vpstruelord.com → 10.9.0.1
# → Windows/phone IKEv2 to that name hits strongSwan on tun0 (not the public WAN).
set -euo pipefail

IKEV2_VIA_OVPN_IF="${IKEV2_VIA_OVPN_IF:-tun0}"
IKEV2_VIA_OVPN_ADDR="${IKEV2_VIA_OVPN_ADDR:-10.9.0.1}"
CHARON_CONF="${CHARON_CONF:-/etc/strongswan.d/charon/sm-ikev2-via-openvpn.conf}"

echo "==> IKEv2 via OpenVPN (iface=${IKEV2_VIA_OVPN_IF} addr=${IKEV2_VIA_OVPN_ADDR})"

if ! ip -4 addr show dev "$IKEV2_VIA_OVPN_IF" 2>/dev/null | grep -q "inet ${IKEV2_VIA_OVPN_ADDR}/"; then
  echo "WARN: ${IKEV2_VIA_OVPN_IF} does not have ${IKEV2_VIA_OVPN_ADDR} — is OpenVPN server up?"
fi

# strongSwan: only bind the OpenVPN interface (not public ens6)
cat > "$CHARON_CONF" << EOF
# Managed by ensure-ikev2-via-openvpn.sh — IKEv2 only on OpenVPN tun
charon {
    # Prefer tun0 so IKE is not offered on the public WAN NIC.
    interfaces_use = ${IKEV2_VIA_OVPN_IF}
    # Still answer when clients hit the VIP explicitly.
    port = 500
    port_nat_t = 4500
}
EOF
chmod 644 "$CHARON_CONF"
echo "wrote ${CHARON_CONF}"

# UFW: drop public IKEv2, allow from OpenVPN (+ WG / LAN) only
if command -v ufw >/dev/null 2>&1; then
  # Remove wide-open rules (ignore missing)
  while ufw status numbered 2>/dev/null | grep -E '^\[[0-9]+\] 500/udp.*Anywhere' >/dev/null; do
    num=$(ufw status numbered | sed -n 's/^\[\([0-9]\+\)\] 500\/udp.*Anywhere.*/\1/p' | head -1)
    [[ -n "$num" ]] || break
    ufw --force delete "$num" >/dev/null || break
  done
  while ufw status numbered 2>/dev/null | grep -E '^\[[0-9]+\] 4500/udp.*Anywhere' >/dev/null; do
    num=$(ufw status numbered | sed -n 's/^\[\([0-9]\+\)\] 4500\/udp.*Anywhere.*/\1/p' | head -1)
    [[ -n "$num" ]] || break
    ufw --force delete "$num" >/dev/null || break
  done

  for src in 10.9.0.0/24 10.8.0.0/24 10.42.42.0/24 192.168.8.0/24; do
    ufw allow from "$src" to any port 500 proto udp comment 'IKEv2 via VPN' >/dev/null 2>&1 || true
    ufw allow from "$src" to any port 4500 proto udp comment 'IKEv2 NAT-T via VPN' >/dev/null 2>&1 || true
  done
  echo "ufw: 500/4500 limited to VPN/LAN sources"
fi

# Reload strongSwan so interfaces_use takes effect
if systemctl is-active --quiet strongswan-starter 2>/dev/null; then
  systemctl reload strongswan-starter 2>/dev/null || ipsec reload 2>/dev/null || systemctl restart strongswan-starter
elif command -v ipsec >/dev/null 2>&1; then
  ipsec reload 2>/dev/null || ipsec restart 2>/dev/null || true
fi

sleep 1
echo "--- listen ---"
ss -ulnp | grep -E ':500|:4500' || true
echo "--- ufw ---"
ufw status | grep -E '500/udp|4500/udp' || true
echo "OK: Connect OpenVPN first, then IKEv2 to portal.vpstruelord.com (DNS → ${IKEV2_VIA_OVPN_ADDR})"
