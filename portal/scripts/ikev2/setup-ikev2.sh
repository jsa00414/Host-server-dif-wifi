#!/bin/bash
# ServerManager — IKEv2 (Windows built-in VPN) via strongSwan
# Uses Let's Encrypt RSA cert (Windows trusts ISRG Root X1). ECDSA LE is rejected by Windows IKEv2.
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

IKEV2_DIR="${IKEV2_DIR:-/opt/ikev2}"
IKEV2_HOST="${IKEV2_HOST:-portal.vpstruelord.com}"
IKEV2_POOL="${IKEV2_POOL:-10.10.0.0/24}"
IKEV2_DNS="${IKEV2_DNS:-10.42.42.44}"
IKEV2_USER="${IKEV2_USER:-windows}"
ADGUARD_DNS="${ADGUARD_DNS:-10.42.42.44}"
ENV_FILE="${PORTAL_ENV_FILE:-/opt/wireguard/port-forward-ui.env}"
LE_LIVE="${IKEV2_LE_LIVE:-/etc/letsencrypt/live/ikev2-portal-rsa}"
ACME_WEBROOT="${ACME_WEBROOT:-/var/www/acme}"

mkdir -p "$IKEV2_DIR/certs" "$IKEV2_DIR/private" /etc/ipsec.d/certs /etc/ipsec.d/private /etc/ipsec.d/cacerts
mkdir -p "$ACME_WEBROOT/.well-known/acme-challenge"

# Ensure RSA Let's Encrypt cert exists (Windows-compatible)
if [[ ! -f "$LE_LIVE/fullchain.pem" || ! -f "$LE_LIVE/privkey.pem" ]]; then
  if ! command -v certbot >/dev/null 2>&1; then
    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y certbot
  fi
  certbot certonly --webroot -w "$ACME_WEBROOT" \
    -d "$IKEV2_HOST" \
    --key-type rsa --rsa-key-size 2048 \
    --cert-name ikev2-portal-rsa \
    --agree-tos --register-unsafely-without-email \
    --non-interactive --preferred-challenges http
fi

# Leaf in certs/, chain in cacerts/ (AppArmor: /etc/ipsec.d only)
awk 'BEGIN{n=0} /BEGIN CERT/{n++} n==1{print} n>1{exit}' "$LE_LIVE/fullchain.pem" > "$IKEV2_DIR/certs/server.crt"
cp -f "$LE_LIVE/chain.pem" "$IKEV2_DIR/certs/chain.pem"
cp -f "$LE_LIVE/privkey.pem" "$IKEV2_DIR/private/server.key"
chmod 644 "$IKEV2_DIR/certs/server.crt"
chmod 600 "$IKEV2_DIR/private/server.key"
# Drop private CA leftovers (not used with LE)
rm -f "$IKEV2_DIR/certs/ca.crt" /etc/ipsec.d/cacerts/ikev2-ca.pem

cp -f "$IKEV2_DIR/certs/server.crt" /etc/ipsec.d/certs/server.crt
cp -f "$IKEV2_DIR/private/server.key" /etc/ipsec.d/private/server.key
chmod 600 /etc/ipsec.d/private/server.key
rm -f /etc/ipsec.d/cacerts/le-int-*.pem /etc/ipsec.d/cacerts/le-rsa-chain.pem /etc/ipsec.d/cacerts/ikev2-ca.pem
python3 - <<'PY'
from pathlib import Path
text = Path("/opt/ikev2/certs/chain.pem").read_text()
parts, cur = [], []
for line in text.splitlines():
    if "BEGIN CERTIFICATE" in line and cur:
        parts.append("\n".join(cur) + "\n")
        cur = [line]
    else:
        cur.append(line)
if cur:
    parts.append("\n".join(cur) + "\n")
out = Path("/etc/ipsec.d/cacerts")
for idx, pem in enumerate(parts):
    if "BEGIN CERTIFICATE" in pem:
        (out / f"le-int-{idx}.pem").write_text(pem)
PY

PASS_FILE="$IKEV2_DIR/windows.pass"
if [[ -f "$PASS_FILE" ]]; then
  IKEV2_PASS="$(tr -d '\n' < "$PASS_FILE")"
else
  IKEV2_PASS="$(openssl rand -base64 18 | tr -d '/+=' | head -c 20)"
  printf '%s\n' "$IKEV2_PASS" > "$PASS_FILE"
  chmod 600 "$PASS_FILE"
fi
printf '%s\n' "$IKEV2_USER" > "$IKEV2_DIR/users.txt"
chmod 600 "$IKEV2_DIR/users.txt" "$PASS_FILE"

cat > /etc/ipsec.conf << EOF
# ServerManager IKEv2 — Windows built-in VPN (LE RSA + EAP-MSCHAPv2)
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
    left=%any
    leftid=@${IKEV2_HOST}
    leftcert=server.crt
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    rightsourceip=${IKEV2_POOL}
    rightdns=${IKEV2_DNS}
    right=%any

conn ikev2-eap
    also=%default
    mobike=no
    leftauth=pubkey
    rightauth=eap-mschapv2
    rightsendcert=never
    eap_identity=%identity
    auto=add
EOF

# Bind charon to WAN only. Advertising docker/tun private ADD_4_ADDR makes
# Windows MOBIKE flip the SA onto Flint OpenVPN (10.9.0.2) and die.
WAN_IF="${IKEV2_WAN_IF:-$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')}"
WAN_IF="${WAN_IF:-ens6}"
CHARON_MAIN="${CHARON_MAIN:-/etc/strongswan.d/charon.conf}"
if [[ -f "$CHARON_MAIN" ]]; then
  WAN_IF="$WAN_IF" CHARON_MAIN="$CHARON_MAIN" python3 - <<'PY'
from pathlib import Path
import os, re
p = Path(os.environ["CHARON_MAIN"])
t = p.read_text()
wan = os.environ["WAN_IF"]
if re.search(r"(?m)^\s*interfaces_use\s*=", t):
    t = re.sub(r"(?m)^\s*#?\s*interfaces_use\s*=.*$", f"    interfaces_use = {wan}", t, count=1)
else:
    t = t.replace("charon {\n", f"charon {{\n    interfaces_use = {wan}\n", 1)
p.write_text(t)
print(f"set interfaces_use = {wan} in {p}")
PY
fi
KN="/etc/strongswan.d/charon/kernel-netlink.conf"
if [[ -f "$KN" ]]; then
  python3 - <<'PY'
from pathlib import Path
import re
p = Path("/etc/strongswan.d/charon/kernel-netlink.conf")
t = p.read_text()
for key, val in (("roam_events", "no"), ("process_route", "no")):
    if re.search(rf"(?m)^\s*#?\s*{key}\s*=", t):
        t = re.sub(rf"(?m)^\s*#?\s*{key}\s*=\s*.*$", f"    {key} = {val}", t, count=1)
    else:
        t = t.replace("kernel-netlink {\n", f"kernel-netlink {{\n    {key} = {val}\n", 1)
p.write_text(t)
PY
fi

cat > /etc/ipsec.secrets << EOF
# ServerManager IKEv2 secrets
: RSA server.key
${IKEV2_USER} : EAP "${IKEV2_PASS}"
EOF
chmod 600 /etc/ipsec.secrets

for plug in eap-mschapv2 eap-identity openssl pem pkcs1 pubkey x509 revocation attr kernel-netlink socket-default; do
  conf="/etc/strongswan.d/charon/${plug}.conf"
  if [[ -f "$conf" ]]; then
    sed -i "s/load = no/load = yes/g" "$conf" || true
  fi
done

# Public IKEv2 on WAN (UDP 500/4500). Optional nested mode:
#   IKEV2_VIA_OPENVPN=1 bash setup → ensure-ikev2-via-openvpn.sh
if [[ "${IKEV2_VIA_OPENVPN:-0}" = "1" ]]; then
  VIA_OVPN_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/ensure-ikev2-via-openvpn.sh"
  if [[ -f "$VIA_OVPN_SRC" ]]; then
    cp -f "$VIA_OVPN_SRC" "$IKEV2_DIR/ensure-ikev2-via-openvpn.sh"
    chmod 0755 "$IKEV2_DIR/ensure-ikev2-via-openvpn.sh"
    bash "$IKEV2_DIR/ensure-ikev2-via-openvpn.sh" || true
  fi
else
  PUBLIC_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/ensure-ikev2-public.sh"
  if [[ -f "$PUBLIC_SRC" ]]; then
    cp -f "$PUBLIC_SRC" "$IKEV2_DIR/ensure-ikev2-public.sh"
    chmod 0755 "$IKEV2_DIR/ensure-ikev2-public.sh"
    bash "$IKEV2_DIR/ensure-ikev2-public.sh" || true
  else
    ufw allow 500/udp comment "IKEv2 IKE" >/dev/null 2>&1 || true
    ufw allow 4500/udp comment "IKEv2 NAT-T" >/dev/null 2>&1 || true
  fi
  NO_NEST_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/ensure-ikev2-no-nest.sh"
  if [[ -f "$NO_NEST_SRC" ]]; then
    cp -f "$NO_NEST_SRC" "$IKEV2_DIR/ensure-ikev2-no-nest.sh"
    chmod 0755 "$IKEV2_DIR/ensure-ikev2-no-nest.sh"
    bash "$IKEV2_DIR/ensure-ikev2-no-nest.sh" || true
  fi
fi
# Host INPUT for portal VIP / sslh (split-DNS points portal at 10.11.0.1)
ufw allow from 10.10.0.0/24 comment "IKEv2 clients to host" >/dev/null 2>&1 || true
iptables -t nat -C POSTROUTING -s 10.10.0.0/24 -o ens6 -m comment --comment SM-IKEV2-MASQ -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s 10.10.0.0/24 -o ens6 -m comment --comment SM-IKEV2-MASQ -j MASQUERADE
iptables -C FORWARD -s 10.10.0.0/24 -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -s 10.10.0.0/24 -j ACCEPT
iptables -C FORWARD -d 10.10.0.0/24 -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -d 10.10.0.0/24 -j ACCEPT
iptables -t nat -C PREROUTING -s 10.10.0.0/24 -p udp --dport 53 -m comment --comment SM-IKEV2-DNS -j DNAT --to-destination "${ADGUARD_DNS}:53" 2>/dev/null \
  || iptables -t nat -I PREROUTING 1 -s 10.10.0.0/24 -p udp --dport 53 -m comment --comment SM-IKEV2-DNS -j DNAT --to-destination "${ADGUARD_DNS}:53"
iptables -t nat -C PREROUTING -s 10.10.0.0/24 -p tcp --dport 53 -m comment --comment SM-IKEV2-DNS -j DNAT --to-destination "${ADGUARD_DNS}:53" 2>/dev/null \
  || iptables -t nat -I PREROUTING 1 -s 10.10.0.0/24 -p tcp --dport 53 -m comment --comment SM-IKEV2-DNS -j DNAT --to-destination "${ADGUARD_DNS}:53"
iptables -t nat -C POSTROUTING -s 10.10.0.0/24 -d 10.42.42.0/24 -m comment --comment SM-IKEV2-DNS -j MASQUERADE 2>/dev/null \
  || iptables -t nat -I POSTROUTING 1 -s 10.10.0.0/24 -d 10.42.42.0/24 -m comment --comment SM-IKEV2-DNS -j MASQUERADE
iptables -C FORWARD -s 10.10.0.0/24 -d 10.42.42.0/24 -m comment --comment SM-IKEV2-DNS -j ACCEPT 2>/dev/null \
  || iptables -I FORWARD 1 -s 10.10.0.0/24 -d 10.42.42.0/24 -m comment --comment SM-IKEV2-DNS -j ACCEPT

if [[ -f "$ENV_FILE" ]]; then
  grep -q '^IKEV2_HOST=' "$ENV_FILE" 2>/dev/null || echo "IKEV2_HOST=${IKEV2_HOST}" >> "$ENV_FILE"
  grep -q '^IKEV2_USER=' "$ENV_FILE" 2>/dev/null || echo "IKEV2_USER=${IKEV2_USER}" >> "$ENV_FILE"
  grep -q '^IKEV2_DIR=' "$ENV_FILE" 2>/dev/null || echo "IKEV2_DIR=${IKEV2_DIR}" >> "$ENV_FILE"
fi

SCRIPT_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/Setup-ServerManagerVpn.ps1"
if [[ -f "$SCRIPT_SRC" && "$SCRIPT_SRC" != "$IKEV2_DIR/Setup-ServerManagerVpn.ps1" ]]; then
  cp -f "$SCRIPT_SRC" "$IKEV2_DIR/Setup-ServerManagerVpn.ps1"
fi

# VPN-only admin hostnames → 10.11.0.1 lo VIP (avoid public-IP exclusion → 403)
SPLIT_DNS_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/ensure-vpn-split-dns.sh"
if [[ -f "$SPLIT_DNS_SRC" ]]; then
  cp -f "$SPLIT_DNS_SRC" "$IKEV2_DIR/ensure-vpn-split-dns.sh"
  chmod 0755 "$IKEV2_DIR/ensure-vpn-split-dns.sh"
  bash "$IKEV2_DIR/ensure-vpn-split-dns.sh" || true
fi

# Allow active IKEv2 peer WAN IPs in Caddy (Windows DoH / gateway exclusion)
PEER_ACL_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/ensure-ikev2-peer-acl.sh"
PEER_SVC_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/sm-ikev2-peer-acl.service"
PEER_TMR_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/sm-ikev2-peer-acl.timer"
if [[ -f "$PEER_ACL_SRC" ]]; then
  cp -f "$PEER_ACL_SRC" "$IKEV2_DIR/ensure-ikev2-peer-acl.sh"
  chmod 0755 "$IKEV2_DIR/ensure-ikev2-peer-acl.sh"
  [[ -f "$PEER_SVC_SRC" ]] && cp -f "$PEER_SVC_SRC" /etc/systemd/system/sm-ikev2-peer-acl.service
  [[ -f "$PEER_TMR_SRC" ]] && cp -f "$PEER_TMR_SRC" /etc/systemd/system/sm-ikev2-peer-acl.timer
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable --now sm-ikev2-peer-acl.timer >/dev/null 2>&1 || true
  bash "$IKEV2_DIR/ensure-ikev2-peer-acl.sh" || true
fi

NOH3_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/ensure-caddy-no-h3.sh"
if [[ -f "$NOH3_SRC" ]]; then
  cp -f "$NOH3_SRC" "$IKEV2_DIR/ensure-caddy-no-h3.sh"
  chmod 0755 "$IKEV2_DIR/ensure-caddy-no-h3.sh"
  bash "$IKEV2_DIR/ensure-caddy-no-h3.sh" || true
fi

systemctl enable strongswan-starter >/dev/null 2>&1 || true
systemctl restart strongswan-starter
sleep 1
ipsec statusall 2>/dev/null | head -40 || true

echo
echo "IKEv2 ready (Let's Encrypt RSA — Windows trusts ISRG Root X1)"
echo "  Server:   ${IKEV2_HOST}"
echo "  User:     ${IKEV2_USER}"
echo "  Password: ${IKEV2_PASS}"
echo "  Pool:     ${IKEV2_POOL}"
echo "  DNS:      ${IKEV2_DNS} → AdGuard ${ADGUARD_DNS}"
echo "  Cert:     ${LE_LIVE}"
echo "  SplitDNS: portal/admin → ${IKEV2_DNS} (AdGuard rewrite)"
echo "  PeerACL:  active IKEv2 WAN IPs synced into Caddy @vpn_clients"
if [[ "${IKEV2_VIA_OPENVPN:-0}" = "1" ]]; then
  echo "  Mode:     IKEv2 via OpenVPN only (tun0)"
else
  echo "  Mode:     public IKEv2 (UDP 500/4500)"
fi
