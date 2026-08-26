#!/bin/sh
# Run ON the Flint (GL.iNet Terminal or local SSH while on Flint Wi‑Fi).
# Allows portal SSH over the school OpenVPN tunnel (tun+ / 10.9.0.0/24).
set -e

echo "Allowing SSH from OpenVPN (tun+ / 10.9.0.0/24)…"

# Dropbear on all interfaces (not LAN-only)
if uci -q get dropbear.@dropbear[0] >/dev/null 2>&1; then
  uci -q delete dropbear.@dropbear[0].Interface || true
  uci -q set dropbear.@dropbear[0].enable='1'
  uci commit dropbear
  /etc/init.d/dropbear reload 2>/dev/null || /etc/init.d/dropbear restart || true
fi

# Live firewall accept (iptables and/or nft)
iptables -C INPUT -i tun+ -p tcp --dport 22 -j ACCEPT 2>/dev/null \
  || iptables -I INPUT -i tun+ -p tcp --dport 22 -j ACCEPT 2>/dev/null || true
iptables -C INPUT -s 10.9.0.0/24 -p tcp --dport 22 -j ACCEPT 2>/dev/null \
  || iptables -I INPUT -s 10.9.0.0/24 -p tcp --dport 22 -j ACCEPT 2>/dev/null || true

if command -v nft >/dev/null 2>&1; then
  nft list chain inet fw4 input 2>/dev/null | grep -q 'iifname "tun\*" tcp dport 22 accept' \
    || nft insert rule inet fw4 input iifname "tun*" tcp dport 22 accept 2>/dev/null || true
  nft list chain inet fw4 input 2>/dev/null | grep -q 'ip saddr 10.9.0.0/24 tcp dport 22 accept' \
    || nft insert rule inet fw4 input ip saddr 10.9.0.0/24 tcp dport 22 accept 2>/dev/null || true
fi

# Persist across reboot via firewall.user when present
USER_FW=/etc/firewall.user
MARK="# servermanager-ovpn-ssh"
if [ -e "$USER_FW" ] || touch "$USER_FW" 2>/dev/null; then
  if ! grep -q "$MARK" "$USER_FW" 2>/dev/null; then
    cat >> "$USER_FW" << EOF

$MARK
iptables -C INPUT -i tun+ -p tcp --dport 22 -j ACCEPT 2>/dev/null || iptables -I INPUT -i tun+ -p tcp --dport 22 -j ACCEPT
iptables -C INPUT -s 10.9.0.0/24 -p tcp --dport 22 -j ACCEPT 2>/dev/null || iptables -I INPUT -s 10.9.0.0/24 -p tcp --dport 22 -j ACCEPT
EOF
  fi
fi

echo "Done. From the VPS, SSH should work to 10.9.0.2 and 192.168.8.1 over OpenVPN."
echo "Keep OpenVPN connected; WireGuard can stay disabled at school."
