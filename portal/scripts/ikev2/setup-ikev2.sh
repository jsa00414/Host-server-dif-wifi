#!/bin/bash
# ServerManager — IKEv2 (Windows built-in VPN) via strongSwan
# Uses Let's Encrypt RSA cert (Windows trusts ISRG Root X1). ECDSA LE is rejected by Windows IKEv2.
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

IKEV2_DIR="${IKEV2_DIR:-/opt/ikev2}"
IKEV2_HOST="${IKEV2_HOST:-portal.vpstruelord.com}"
IKEV2_POOL="${IKEV2_POOL:-10.10.0.0/24}"
IKEV2_DNS="${IKEV2_DNS:-10.9.0.1}"
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
    leftauth=pubkey
    rightauth=eap-mschapv2
    rightsendcert=never
    eap_identity=%identity
    auto=add
EOF

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

ufw allow 500/udp comment "IKEv2 IKE" >/dev/null 2>&1 || true
ufw allow 4500/udp comment "IKEv2 NAT-T" >/dev/null 2>&1 || true
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
