#!/bin/sh
# Run ON the Flint (GL.iNet Terminal / local SSH), or pushed from the VPS
# when OpenVPN connects.
#
# 1) Allow portal SSH over the school OpenVPN tunnel (tun+ / ovpnclient* / 10.9.0.0/24)
# 2) Allow VPS → home LAN (Buffalo admin :80 + WebAccess :9000, etc.)
#    GL.iNet VPN-client zones only forward LAN→VPN by default, so reverse
#    access needs an explicit forward + MASQUERADE (LAN blackhole otherwise).
set -e

echo "Allowing SSH + LAN access from OpenVPN (10.9.0.0/24)…"

# Dropbear on all interfaces (not LAN-only)
if uci -q get dropbear.@dropbear[0] >/dev/null 2>&1; then
  uci -q delete dropbear.@dropbear[0].Interface || true
  uci -q set dropbear.@dropbear[0].enable='1'
  uci commit dropbear
  /etc/init.d/dropbear reload 2>/dev/null || /etc/init.d/dropbear restart || true
fi

# --- INPUT: SSH from tunnel ---
iptables -C INPUT -i tun+ -p tcp --dport 22 -j ACCEPT 2>/dev/null \
  || iptables -I INPUT -i tun+ -p tcp --dport 22 -j ACCEPT 2>/dev/null || true
iptables -C INPUT -i ovpnclient+ -p tcp --dport 22 -j ACCEPT 2>/dev/null \
  || iptables -I INPUT -i ovpnclient+ -p tcp --dport 22 -j ACCEPT 2>/dev/null || true
iptables -C INPUT -s 10.9.0.0/24 -p tcp --dport 22 -j ACCEPT 2>/dev/null \
  || iptables -I INPUT -s 10.9.0.0/24 -p tcp --dport 22 -j ACCEPT 2>/dev/null || true

# --- FORWARD: VPS (OVPN) ↔ home LAN (Buffalo / NAS) ---
# Prefer fw3 custom chain so we run before zone reject.
iptables -C forwarding_rule -s 10.9.0.0/24 -d 192.168.8.0/24 -j ACCEPT 2>/dev/null \
  || iptables -I forwarding_rule 1 -s 10.9.0.0/24 -d 192.168.8.0/24 -j ACCEPT 2>/dev/null || true
iptables -C forwarding_rule -s 192.168.8.0/24 -d 10.9.0.0/24 -j ACCEPT 2>/dev/null \
  || iptables -I forwarding_rule 1 -s 192.168.8.0/24 -d 10.9.0.0/24 -j ACCEPT 2>/dev/null || true
iptables -C forwarding_rule -i ovpnclient+ -o br-lan -j ACCEPT 2>/dev/null \
  || iptables -I forwarding_rule 1 -i ovpnclient+ -o br-lan -j ACCEPT 2>/dev/null || true
iptables -C forwarding_rule -i tun+ -o br-lan -j ACCEPT 2>/dev/null \
  || iptables -I forwarding_rule 1 -i tun+ -o br-lan -j ACCEPT 2>/dev/null || true
iptables -C forwarding_rule -i br-lan -o ovpnclient+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null \
  || iptables -I forwarding_rule 1 -i br-lan -o ovpnclient+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
iptables -C forwarding_rule -i br-lan -o tun+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null \
  || iptables -I forwarding_rule 1 -i br-lan -o tun+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

# MASQUERADE so LAN hosts reply to Flint (avoids GL policy blackhole on br-lan→VPN).
iptables -t nat -C POSTROUTING -s 10.9.0.0/24 -o br-lan -m comment --comment SM-OVPN-LAN -j MASQUERADE 2>/dev/null \
  || iptables -t nat -I POSTROUTING 1 -s 10.9.0.0/24 -o br-lan -m comment --comment SM-OVPN-LAN -j MASQUERADE 2>/dev/null || true

if command -v nft >/dev/null 2>&1; then
  nft list chain inet fw4 input 2>/dev/null | grep -q 'iifname "tun\*" tcp dport 22 accept' \
    || nft insert rule inet fw4 input iifname "tun*" tcp dport 22 accept 2>/dev/null || true
  nft list chain inet fw4 input 2>/dev/null | grep -q 'ip saddr 10.9.0.0/24 tcp dport 22 accept' \
    || nft insert rule inet fw4 input ip saddr 10.9.0.0/24 tcp dport 22 accept 2>/dev/null || true
fi

# Persist UCI forward ovpnclient → lan when that zone exists (survives some reloads).
if uci -q get firewall.ovpnclient1 >/dev/null 2>&1; then
  if ! uci -q get firewall.ovpnclient12lan >/dev/null 2>&1; then
    uci set firewall.ovpnclient12lan=forwarding
    uci set firewall.ovpnclient12lan.src='ovpnclient1'
    uci set firewall.ovpnclient12lan.dest='lan'
    uci set firewall.ovpnclient12lan.name='sm-ovpn-to-lan'
    uci commit firewall
  fi
fi

# Persist across reboot / firewall restart via firewall.user
USER_FW=/etc/firewall.user
MARK="# servermanager-ovpn-lan"
if [ -e "$USER_FW" ] || touch "$USER_FW" 2>/dev/null; then
  if ! grep -q "$MARK" "$USER_FW" 2>/dev/null; then
    cat >> "$USER_FW" << 'EOF'

# servermanager-ovpn-lan
iptables -C INPUT -i tun+ -p tcp --dport 22 -j ACCEPT 2>/dev/null || iptables -I INPUT -i tun+ -p tcp --dport 22 -j ACCEPT
iptables -C INPUT -i ovpnclient+ -p tcp --dport 22 -j ACCEPT 2>/dev/null || iptables -I INPUT -i ovpnclient+ -p tcp --dport 22 -j ACCEPT
iptables -C INPUT -s 10.9.0.0/24 -p tcp --dport 22 -j ACCEPT 2>/dev/null || iptables -I INPUT -s 10.9.0.0/24 -p tcp --dport 22 -j ACCEPT
iptables -C forwarding_rule -s 10.9.0.0/24 -d 192.168.8.0/24 -j ACCEPT 2>/dev/null || iptables -I forwarding_rule 1 -s 10.9.0.0/24 -d 192.168.8.0/24 -j ACCEPT
iptables -C forwarding_rule -s 192.168.8.0/24 -d 10.9.0.0/24 -j ACCEPT 2>/dev/null || iptables -I forwarding_rule 1 -s 192.168.8.0/24 -d 10.9.0.0/24 -j ACCEPT
iptables -C forwarding_rule -i ovpnclient+ -o br-lan -j ACCEPT 2>/dev/null || iptables -I forwarding_rule 1 -i ovpnclient+ -o br-lan -j ACCEPT
iptables -C forwarding_rule -i tun+ -o br-lan -j ACCEPT 2>/dev/null || iptables -I forwarding_rule 1 -i tun+ -o br-lan -j ACCEPT
iptables -t nat -C POSTROUTING -s 10.9.0.0/24 -o br-lan -m comment --comment SM-OVPN-LAN -j MASQUERADE 2>/dev/null || iptables -t nat -I POSTROUTING 1 -s 10.9.0.0/24 -o br-lan -m comment --comment SM-OVPN-LAN -j MASQUERADE
EOF
  fi
fi

# --- DNS: AdGuard (→ Pi-hole) via OpenVPN gateway ---
# Use 10.9.0.1 (VPS OVPN gateway). VPS DNATs :53 → AdGuard. Direct 10.42.42.44
# from the tunnel is unreliable across the docker bridge.
OVPN_DNS="${OVPN_DNS:-10.9.0.1}"
echo "Adding OpenVPN DNS ${OVPN_DNS} (AdGuard → Pi-hole) as Flint LAN upstream…"

iptables -C forwarding_rule -s 192.168.8.0/24 -d 10.9.0.0/24 -j ACCEPT 2>/dev/null \
  || iptables -I forwarding_rule 1 -s 192.168.8.0/24 -d 10.9.0.0/24 -j ACCEPT 2>/dev/null || true
iptables -C forwarding_rule -i br-lan -d 10.9.0.1 -p udp --dport 53 -j ACCEPT 2>/dev/null \
  || iptables -I forwarding_rule 1 -i br-lan -d 10.9.0.1 -p udp --dport 53 -j ACCEPT 2>/dev/null || true

EXISTING="$(uci -q get dhcp.@dnsmasq[0].server 2>/dev/null || true)"
case " $EXISTING " in
  *" ${OVPN_DNS} "*|*" ${OVPN_DNS}#"*) ;;
  *)
    while uci -q delete dhcp.@dnsmasq[0].server >/dev/null 2>&1; do :; done
    uci add_list dhcp.@dnsmasq[0].server="${OVPN_DNS}"
    for srv in $EXISTING; do
      [ "$srv" = "${OVPN_DNS}" ] && continue
      # Drop direct AdGuard IP if present — gateway DNAT path is preferred
      [ "$srv" = "10.42.42.44" ] && continue
      uci add_list dhcp.@dnsmasq[0].server="$srv"
    done
    ;;
esac
uci set dhcp.@dnsmasq[0].noresolv='0'
uci commit dhcp
/etc/init.d/dnsmasq restart >/dev/null 2>&1 || /etc/init.d/dnsmasq reload >/dev/null 2>&1 || true

echo "Done. VPS can SSH to 10.9.0.2 and reach Buffalo at 192.168.8.159 over OpenVPN."
echo "LAN DNS prefers ${OVPN_DNS} → AdGuard → Pi-hole (WAN DNS kept as fallback)."
