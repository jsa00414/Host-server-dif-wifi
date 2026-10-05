#!/usr/bin/env bash
# Terminate portal TLS on Flint (LAN MTU) and reverse-proxy to VIP over OVPN.
# Fixes Windows ERR_CONNECTION_TIMED_OUT when DNAT/socat over OpenVPN stalls TLS.
set -euo pipefail

FLINT_HOST="${FLINT_LAN_IP:-192.168.8.1}"
PORTAL_VIP="${VPN_INTERNAL_IP:-10.11.0.1}"
ENV_FILE="${PORTAL_ENV_FILE:-/opt/wireguard/port-forward-ui.env}"
CERT_SRC="${PORTAL_CERT_DIR:-/var/lib/docker/volumes/truemail_caddy_data/_data/caddy/certificates/acme-v02.api.letsencrypt.org-directory/portal.vpstruelord.com}"

PASS=""
if [[ -f "$ENV_FILE" ]]; then
  PASS="$(
    python3 - <<'PY'
import base64
from pathlib import Path
for line in Path("/opt/wireguard/port-forward-ui.env").read_text().splitlines():
    if line.startswith("ROUTER_PASS_B64="):
        print(base64.b64decode(line.split("=", 1)[1].strip().strip('"').strip("'")).decode())
        break
PY
  )"
fi
[[ -n "$PASS" ]] || { echo "flint-portal-nginx: no ROUTER_PASS_B64"; exit 0; }
[[ -f "$CERT_SRC/portal.vpstruelord.com.crt" && -f "$CERT_SRC/portal.vpstruelord.com.key" ]] || {
  echo "flint-portal-nginx: missing LE certs under $CERT_SRC"
  exit 0
}

export SSHPASS="$PASS"
sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=20 "root@${FLINT_HOST}" \
  'mkdir -p /etc/sm-portal-proxy /etc/nginx/conf.d'
sshpass -e ssh -o StrictHostKeyChecking=no "root@${FLINT_HOST}" \
  "cat > /etc/sm-portal-proxy/portal.crt" <"$CERT_SRC/portal.vpstruelord.com.crt"
sshpass -e ssh -o StrictHostKeyChecking=no "root@${FLINT_HOST}" \
  "cat > /etc/sm-portal-proxy/portal.key" <"$CERT_SRC/portal.vpstruelord.com.key"

sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=40 "root@${FLINT_HOST}" sh -s <<REMOTE
set +e
chmod 600 /etc/sm-portal-proxy/portal.key
chmod 644 /etc/sm-portal-proxy/portal.crt
cat >/etc/nginx/conf.d/sm-portal.conf <<'NGX'
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name portal.vpstruelord.com;
    ssl_certificate     /etc/sm-portal-proxy/portal.crt;
    ssl_certificate_key /etc/sm-portal-proxy/portal.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    location / {
        proxy_http_version 1.1;
        proxy_ssl_server_name on;
        proxy_ssl_name portal.vpstruelord.com;
        proxy_set_header Host portal.vpstruelord.com;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Connection "";
        proxy_buffering off;
        proxy_read_timeout 300s;
        proxy_pass https://${PORTAL_VIP};
    }
}
NGX
if [ -f /etc/nginx/nginx.conf ] && ! grep -q 'server_names_hash_bucket_size' /etc/nginx/nginx.conf; then
  sed -i '/http {/a\\    server_names_hash_bucket_size 64;' /etc/nginx/nginx.conf
fi
if [ -f /etc/nginx/nginx.conf ] && ! grep -q 'conf.d/\\*\\.conf' /etc/nginx/nginx.conf; then
  sed -i '/http {/a\\    include /etc/nginx/conf.d/*.conf;' /etc/nginx/nginx.conf
fi
nginx -t 2>&1 && (nginx -s reload 2>/dev/null || /etc/init.d/nginx reload 2>/dev/null || true)
curl -sk -o /dev/null -w "flint_portal_nginx=%{http_code}\\n" --connect-timeout 8 \
  --resolve portal.vpstruelord.com:443:127.0.0.1 https://portal.vpstruelord.com/ || echo flint_portal_nginx=fail
REMOTE
