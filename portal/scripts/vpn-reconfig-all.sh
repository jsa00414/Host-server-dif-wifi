#!/usr/bin/env bash
# ServerManager — full VPN stack reconfig (OpenVPN + IKEv2 + DNS + sslh).
# Preserves OpenVPN PKI and IKEv2 LE certs / windows.pass.
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export DEBIAN_FRONTEND=noninteractive

IKEV2_DIR="${IKEV2_DIR:-/opt/ikev2}"
OVPN_DIR="${OVPN_DIR:-/opt/openvpn}"
GUEST_DNS="${VPN_GUEST_DNS:-1.1.1.1}"
ADGUARD_DNS="${ADGUARD_DNS:-10.42.42.44}"
IKEV2_DNS="${IKEV2_DNS:-$GUEST_DNS}"

echo "==> VPN reconfig-all $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "    guest_dns=${GUEST_DNS} adguard=${ADGUARD_DNS} ike_push=${IKEV2_DNS}"

############################################
# 1) OpenVPN — conf / scripts / firewall
############################################
echo "==> OpenVPN"
if [[ -f "$OVPN_DIR/scripts/server.conf" ]]; then
  install -m 0644 "$OVPN_DIR/scripts/server.conf" "$OVPN_DIR/server.conf"
fi
[[ -f "$OVPN_DIR/scripts/ccd-flint" ]] && install -m 0644 "$OVPN_DIR/scripts/ccd-flint" "$OVPN_DIR/ccd/flint"
[[ -f "$OVPN_DIR/scripts/ccd-windows" ]] && install -m 0644 "$OVPN_DIR/scripts/ccd-windows" "$OVPN_DIR/ccd/windows"
if [[ -f "$OVPN_DIR/scripts/openvpn-server-sm.service" ]]; then
  install -m 0644 "$OVPN_DIR/scripts/openvpn-server-sm.service" /etc/systemd/system/openvpn-server-sm.service
  systemctl daemon-reload
fi
bash "$OVPN_DIR/scripts/ovpn-firewall.sh"
# Rebuild client profiles (same PKI)
if [[ -x "$OVPN_DIR/scripts/build-client.sh" ]]; then
  for name in flint windows james-iphone test-phone; do
    if [[ -f "$OVPN_DIR/easy-rsa/pki/issued/${name}.crt" ]]; then
      if [[ "$name" = "flint" ]]; then
        bash "$OVPN_DIR/scripts/build-client.sh" flint || true
      else
        OVPN_REDIRECT_GATEWAY=1 bash "$OVPN_DIR/scripts/build-client.sh" "$name" || true
      fi
    fi
  done
fi
systemctl enable openvpn-server-sm >/dev/null 2>&1 || true
systemctl restart openvpn-server-sm
systemctl restart sslh-sm 2>/dev/null || systemctl restart sslh 2>/dev/null || true

############################################
# 2) IKEv2 — VIP pool / guest DNS push / dhcp off
############################################
echo "==> IKEv2 conf"
# Force dhcp plugin off (Assigning IPv4 hang)
DHCP_CONF="/etc/strongswan.d/charon/dhcp.conf"
if [[ -f "$DHCP_CONF" ]]; then
  python3 - <<'PY'
from pathlib import Path
import re
p = Path("/etc/strongswan.d/charon/dhcp.conf")
p.write_text(re.sub(r"(?m)^(\s*)load\s*=\s*\S+", r"\1load = no", p.read_text()))
print("dhcp load = no")
PY
fi

# Align ipsec.conf: VIP+DNS on ikev2-eap only, guest rightdns, fragmentation
IKEV2_HOST="${IKEV2_HOST:-portal.vpstruelord.com}"
IKEV2_POOL="${IKEV2_POOL:-10.10.0.0/24}"
WAN_IF_DETECT="$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
WAN_IF_DETECT="${WAN_IF_DETECT:-ens6}"
VPS_PUBLIC_IP="${VPS_PUBLIC_IP:-$(ip -4 -o addr show dev "$WAN_IF_DETECT" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)}"
VPS_PUBLIC_IP="${VPS_PUBLIC_IP:-74.208.76.213}"
export IKEV2_HOST IKEV2_POOL IKEV2_DNS VPS_PUBLIC_IP
if [[ -f /etc/ipsec.conf ]] || [[ -d /etc/ipsec.d ]]; then
  python3 - <<'PY'
from pathlib import Path
import os
host = os.environ.get("IKEV2_HOST", "portal.vpstruelord.com")
pool = os.environ.get("IKEV2_POOL", "10.10.0.0/24")
dns = os.environ.get("IKEV2_DNS", "1.1.1.1")
vps = os.environ.get("VPS_PUBLIC_IP", "74.208.76.213")
text = f"""# ServerManager IKEv2 — Windows built-in VPN (LE RSA + EAP-MSCHAPv2)
# Managed by vpn-reconfig-all.sh
config setup
    uniqueids=never
    charondebug="ike 1, knl 1, cfg 0"

conn %default
    keyexchange=ikev2
    ike=aes256-sha256-modp2048,aes256-sha1-modp1024,aes128-sha1-modp1024!
    esp=aes256-sha256,aes256-sha1,aes128-sha1!
    dpdaction=clear
    dpddelay=300s
    rekey=no
    mobike=no
    fragmentation=yes
    left=%any
    leftid=@{host}
    leftcert=server.crt
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    right=%any

conn ikev2-eap
    also=%default
    mobike=no
    leftauth=pubkey
    rightauth=eap-mschapv2
    rightsendcert=never
    eap_identity=%identity
    rightsourceip={pool}
    rightdns={dns}
    auto=add

conn passthrough-vps
    type=passthrough
    left=%any
    leftsubnet={vps}/32
    right=%any
    rightsubnet=0.0.0.0/0
    authby=never
    auto=route
"""
Path("/etc/ipsec.conf").write_text(text)
print(f"ipsec.conf: pool={pool} rightdns={dns} passthrough={vps}")
PY
fi

# WAN-only interfaces_use
WAN_IF="$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
WAN_IF="${WAN_IF:-ens6}"
CHARON_MAIN="/etc/strongswan.d/charon.conf"
if [[ -f "$CHARON_MAIN" ]]; then
  WAN_IF="$WAN_IF" python3 - <<'PY'
from pathlib import Path
import os, re
p = Path("/etc/strongswan.d/charon.conf")
t = p.read_text()
wan = os.environ["WAN_IF"]
if re.search(r"(?m)^\s*interfaces_use\s*=", t):
    t = re.sub(r"(?m)^\s*#?\s*interfaces_use\s*=.*$", f"    interfaces_use = {wan}", t, count=1)
else:
    t = t.replace("charon {\n", f"charon {{\n    interfaces_use = {wan}\n", 1)
p.write_text(t)
print(f"interfaces_use = {wan}")
PY
fi

############################################
# 3) Ensure scripts — DNS / forward / public / ACL
############################################
echo "==> ensure scripts"
VPN_GUEST_DNS="$GUEST_DNS" ADGUARD_DNS="$ADGUARD_DNS" \
  bash "$IKEV2_DIR/ensure-ikev2-forward.sh"
bash "$IKEV2_DIR/ensure-ikev2-public.sh" || true
bash "$IKEV2_DIR/ensure-ikev2-no-nest.sh" || true
bash "$IKEV2_DIR/ensure-vpn-split-dns.sh" || true
bash "$IKEV2_DIR/ensure-vpn-client-gate.sh" || true
bash "$IKEV2_DIR/ensure-ikev2-peer-acl.sh" || true
bash "$IKEV2_DIR/ensure-caddy-no-h3.sh" || true

systemctl enable strongswan-starter >/dev/null 2>&1 || true
# Clean restart under systemd
ipsec stop >/dev/null 2>&1 || true
sleep 1
pkill -9 -x charon >/dev/null 2>&1 || true
pkill -9 -x starter >/dev/null 2>&1 || true
sleep 1
systemctl reset-failed strongswan-starter >/dev/null 2>&1 || true
systemctl restart strongswan-starter

# Host name (sudo noise)
if ! grep -q 'vps2.vpstruelord.com' /etc/hosts 2>/dev/null; then
  echo '127.0.1.1 vps2.vpstruelord.com vps2' >> /etc/hosts
fi

systemctl restart port-forward-ui >/dev/null 2>&1 || true

############################################
# 4) Verify
############################################
echo "==> verify"
echo "openvpn=$(systemctl is-active openvpn-server-sm 2>/dev/null || echo n/a)"
echo "sslh=$(systemctl is-active sslh-sm 2>/dev/null || systemctl is-active sslh 2>/dev/null || echo n/a)"
echo "ikev2=$(systemctl is-active strongswan-starter 2>/dev/null || echo n/a)"
echo "portal=$(systemctl is-active port-forward-ui 2>/dev/null || echo n/a)"
ss -tlnp | grep -E ':443|:8443' || true
ss -ulnp | grep -E ':500 |:4500' || true
echo "--- ipsec ---"
grep -nE 'rightdns|rightsourceip|conn ' /etc/ipsec.conf | head -20
ipsec statusall 2>&1 | sed -n '1,35p' || true
echo "--- dhcp ---"
grep -E '^\s*load' /etc/strongswan.d/charon/dhcp.conf || true
echo "--- DNS DNAT ---"
iptables -t nat -L PREROUTING -n -v --line-numbers | head -12
echo "--- OVPN status ---"
head -15 /var/log/openvpn-status.log 2>/dev/null || true
echo "OK vpn-reconfig-all finished"
