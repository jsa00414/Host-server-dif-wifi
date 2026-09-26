#!/usr/bin/env bash
# Refresh strongSwan IKEv2 material from Let's Encrypt RSA cert (certbot renew).
set -euo pipefail

IKEV2_DIR="${IKEV2_DIR:-/opt/ikev2}"
LE_LIVE="${IKEV2_LE_LIVE:-/etc/letsencrypt/live/ikev2-portal-rsa}"

[[ -f "$LE_LIVE/fullchain.pem" && -f "$LE_LIVE/privkey.pem" ]] || exit 0

mkdir -p "$IKEV2_DIR/certs" "$IKEV2_DIR/private" /etc/ipsec.d/certs /etc/ipsec.d/private /etc/ipsec.d/cacerts
awk 'BEGIN{n=0} /BEGIN CERT/{n++} n==1{print} n>1{exit}' "$LE_LIVE/fullchain.pem" > "$IKEV2_DIR/certs/server.crt"
cp -f "$LE_LIVE/chain.pem" "$IKEV2_DIR/certs/chain.pem"
cp -f "$LE_LIVE/privkey.pem" "$IKEV2_DIR/private/server.key"
chmod 644 "$IKEV2_DIR/certs/server.crt"
chmod 600 "$IKEV2_DIR/private/server.key"

cp -f "$IKEV2_DIR/certs/server.crt" /etc/ipsec.d/certs/server.crt
cp -f "$IKEV2_DIR/private/server.key" /etc/ipsec.d/private/server.key
chmod 600 /etc/ipsec.d/private/server.key

# Split intermediates into individual files for strongSwan
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
rm -f "$IKEV2_DIR/certs/ca.crt"

if [[ -f /etc/ipsec.secrets ]]; then
  sed -i -E "s/^: (RSA|ECDSA) /: RSA /" /etc/ipsec.secrets || true
fi

if systemctl is-active --quiet strongswan-starter 2>/dev/null; then
  ipsec rereadall >/dev/null 2>&1 || true
  ipsec rereadsecrets >/dev/null 2>&1 || true
  ipsec reload >/dev/null 2>&1 || true
fi
