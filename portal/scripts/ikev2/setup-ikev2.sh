#!/bin/bash
# ServerManager — IKEv2 (Windows built-in VPN) via strongSwan
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

IKEV2_DIR="${IKEV2_DIR:-/opt/ikev2}"
IKEV2_HOST="${IKEV2_HOST:-portal.vpstruelord.com}"
IKEV2_POOL="${IKEV2_POOL:-10.10.0.0/24}"
IKEV2_DNS="${IKEV2_DNS:-10.9.0.1}"
IKEV2_USER="${IKEV2_USER:-windows}"
ADGUARD_DNS="${ADGUARD_DNS:-10.42.42.44}"
CADDY_CERT_DIR="${CADDY_CERT_DIR:-/var/lib/docker/volumes/truemail_caddy_data/_data/caddy/certificates/acme-v02.api.letsencrypt.org-directory/${IKEV2_HOST}}"
ENV_FILE="${PORTAL_ENV_FILE:-/opt/wireguard/port-forward-ui.env}"

mkdir -p "$IKEV2_DIR/certs" "$IKEV2_DIR/private"

# Prefer live Let's Encrypt cert from Caddy (trusted by Windows).
if [[ -f "$CADDY_CERT_DIR/${IKEV2_HOST}.crt" && -f "$CADDY_CERT_DIR/${IKEV2_HOST}.key" ]]; then
  # Leaf only in server.crt; intermediates go to cacerts (AppArmor-readable).
  awk 'BEGIN{n=0} /BEGIN CERT/{n++} n==1{print} n>1{exit}' \
    "$CADDY_CERT_DIR/${IKEV2_HOST}.crt" > "$IKEV2_DIR/certs/server.crt"
  awk 'BEGIN{n=0} /BEGIN CERT/{n++} n>1{print}' \
    "$CADDY_CERT_DIR/${IKEV2_HOST}.crt" > "$IKEV2_DIR/certs/chain.pem"
  cp -f "$CADDY_CERT_DIR/${IKEV2_HOST}.key" "$IKEV2_DIR/private/server.key"
  chmod 644 "$IKEV2_DIR/certs/server.crt"
  chmod 600 "$IKEV2_DIR/private/server.key"
  echo "Using Let's Encrypt cert for ${IKEV2_HOST}"
else
  echo "Caddy LE cert not found at $CADDY_CERT_DIR — generating self-signed (Windows must trust CA)" >&2
  if [[ ! -f "$IKEV2_DIR/private/ca.key" ]]; then
    ipsec pki --gen --type rsa --size 4096 --outform pem > "$IKEV2_DIR/private/ca.key"
    ipsec pki --self --ca --lifetime 3650 --in "$IKEV2_DIR/private/ca.key" \
      --dn "CN=ServerManager IKEv2 CA" --outform pem > "$IKEV2_DIR/certs/ca.crt"
  fi
  ipsec pki --gen --type rsa --size 2048 --outform pem > "$IKEV2_DIR/private/server.key"
  ipsec pki --pub --in "$IKEV2_DIR/private/server.key" | ipsec pki --issue --lifetime 825 \
    --cacert "$IKEV2_DIR/certs/ca.crt" --cakey "$IKEV2_DIR/private/ca.key" \
    --dn "CN=${IKEV2_HOST}" --san "${IKEV2_HOST}" --san "74.208.76.213" \
    --flag serverAuth --flag ikeIntermediate --outform pem > "$IKEV2_DIR/certs/server.crt"
  chmod 600 "$IKEV2_DIR/private/"*.key
fi

# Password (persist)
PASS_FILE="$IKEV2_DIR/windows.pass"
if [[ -f "$PASS_FILE" ]]; then
  IKEV2_PASS="$(tr -d '\n' < "$PASS_FILE")"
else
  IKEV2_PASS="$(openssl rand -base64 18 | tr -d '/+=' | head -c 20)"
  printf '%s\n' "$IKEV2_PASS" > "$PASS_FILE"
  chmod 600 "$PASS_FILE"
fi

# Users file for portal
printf '%s\n' "$IKEV2_USER" > "$IKEV2_DIR/users.txt"
chmod 600 "$IKEV2_DIR/users.txt" "$PASS_FILE"

# strongSwan classic config (Ubuntu strongswan-starter)
cat > /etc/ipsec.conf << EOF
# ServerManager IKEv2 — Windows built-in VPN
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
    # Windows expects remote identity to match the VPN server FQDN.
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

# Install cert where strongSwan looks by default (AppArmor: /etc/ipsec.d only)
mkdir -p /etc/ipsec.d/certs /etc/ipsec.d/private /etc/ipsec.d/cacerts
cp -f "$IKEV2_DIR/certs/server.crt" /etc/ipsec.d/certs/server.crt
cp -f "$IKEV2_DIR/private/server.key" /etc/ipsec.d/private/server.key
chmod 644 /etc/ipsec.d/certs/server.crt
chmod 600 /etc/ipsec.d/private/server.key
if [[ -f "$IKEV2_DIR/certs/chain.pem" ]] && grep -q "BEGIN CERTIFICATE" "$IKEV2_DIR/certs/chain.pem"; then
  cp -f "$IKEV2_DIR/certs/chain.pem" /etc/ipsec.d/cacerts/le-intermediate.pem
fi
if [[ -f "$IKEV2_DIR/certs/ca.crt" ]]; then
  cp -f "$IKEV2_DIR/certs/ca.crt" /etc/ipsec.d/cacerts/ikev2-ca.pem
fi

# Caddy/Let's Encrypt keys are typically ECDSA (P-256). AppArmor only allows
# charon to read under /etc/ipsec.d/, so keep key/cert there and declare ECDSA.
KEY_ALG="ECDSA"
if openssl pkey -in /etc/ipsec.d/private/server.key -noout -text 2>/dev/null | grep -qi "RSA Private"; then
  KEY_ALG="RSA"
fi
cat > /etc/ipsec.secrets << EOF
# ServerManager IKEv2 secrets
: ${KEY_ALG} server.key
${IKEV2_USER} : EAP "${IKEV2_PASS}"
EOF
chmod 600 /etc/ipsec.secrets

# Enable required plugins
for plug in eap-mschapv2 eap-identity openssl pem pkcs1 pubkey x509 revocation attr kernel-netlink socket-default; do
  conf="/etc/strongswan.d/charon/${plug}.conf"
  if [[ -f "$conf" ]]; then
    sed -i "s/load = no/load = yes/g" "$conf" || true
  fi
done

# Firewall + NAT for IKEv2 pool
ufw allow 500/udp comment "IKEv2 IKE" >/dev/null 2>&1 || true
ufw allow 4500/udp comment "IKEv2 NAT-T" >/dev/null 2>&1 || true
iptables -t nat -C POSTROUTING -s 10.10.0.0/24 -o ens6 -m comment --comment SM-IKEV2-MASQ -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s 10.10.0.0/24 -o ens6 -m comment --comment SM-IKEV2-MASQ -j MASQUERADE
iptables -C FORWARD -s 10.10.0.0/24 -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -s 10.10.0.0/24 -j ACCEPT
iptables -C FORWARD -d 10.10.0.0/24 -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -d 10.10.0.0/24 -j ACCEPT
# DNS: IKEv2 clients use 10.9.0.1 → DNAT to AdGuard (shared with OpenVPN)
iptables -t nat -C PREROUTING -s 10.10.0.0/24 -p udp --dport 53 -m comment --comment SM-IKEV2-DNS -j DNAT --to-destination "${ADGUARD_DNS}:53" 2>/dev/null \
  || iptables -t nat -I PREROUTING 1 -s 10.10.0.0/24 -p udp --dport 53 -m comment --comment SM-IKEV2-DNS -j DNAT --to-destination "${ADGUARD_DNS}:53"
iptables -t nat -C PREROUTING -s 10.10.0.0/24 -p tcp --dport 53 -m comment --comment SM-IKEV2-DNS -j DNAT --to-destination "${ADGUARD_DNS}:53" 2>/dev/null \
  || iptables -t nat -I PREROUTING 1 -s 10.10.0.0/24 -p tcp --dport 53 -m comment --comment SM-IKEV2-DNS -j DNAT --to-destination "${ADGUARD_DNS}:53"
iptables -t nat -C POSTROUTING -s 10.10.0.0/24 -d 10.42.42.0/24 -m comment --comment SM-IKEV2-DNS -j MASQUERADE 2>/dev/null \
  || iptables -t nat -I POSTROUTING 1 -s 10.10.0.0/24 -d 10.42.42.0/24 -m comment --comment SM-IKEV2-DNS -j MASQUERADE
iptables -C FORWARD -s 10.10.0.0/24 -d 10.42.42.0/24 -m comment --comment SM-IKEV2-DNS -j ACCEPT 2>/dev/null \
  || iptables -I FORWARD 1 -s 10.10.0.0/24 -d 10.42.42.0/24 -m comment --comment SM-IKEV2-DNS -j ACCEPT

# Persist env hints for portal
if [[ -f "$ENV_FILE" ]]; then
  grep -q '^IKEV2_HOST=' "$ENV_FILE" 2>/dev/null || echo "IKEV2_HOST=${IKEV2_HOST}" >> "$ENV_FILE"
  grep -q '^IKEV2_USER=' "$ENV_FILE" 2>/dev/null || echo "IKEV2_USER=${IKEV2_USER}" >> "$ENV_FILE"
  grep -q '^IKEV2_DIR=' "$ENV_FILE" 2>/dev/null || echo "IKEV2_DIR=${IKEV2_DIR}" >> "$ENV_FILE"
fi

systemctl enable strongswan-starter >/dev/null 2>&1 || true
systemctl restart strongswan-starter
sleep 1
ipsec statusall 2>/dev/null | head -40 || true

echo
echo "IKEv2 ready"
echo "  Server:   ${IKEV2_HOST}"
echo "  User:     ${IKEV2_USER}"
echo "  Password: ${IKEV2_PASS}"
echo "  Pool:     ${IKEV2_POOL}"
echo "  DNS:      ${IKEV2_DNS} → AdGuard ${ADGUARD_DNS}"
