#!/usr/bin/env bash
# Deploy https://github.com/jsa00414/troop-3-test-site to troop3.vpstruelord.com
# Run on the VPS as root.
set -euo pipefail

DOMAIN="${TROOP3_DOMAIN:-troop3.vpstruelord.com}"
REPO_URL="${TROOP3_REPO:-https://github.com/jsa00414/Troop-3-Site-V2.git}"
BRANCH="${TROOP3_BRANCH:-main}"
SITE_ROOT="${TROOP3_ROOT:-/opt/sites/troop3}"
PORT="${TROOP3_PORT:-3013}"
SERVICE_NAME="${TROOP3_SERVICE:-troop3-site}"
CADDYFILE="${TROOP3_CADDYFILE:-/opt/truemail/Caddyfile}"
COMPOSE_DIR="${TROOP3_COMPOSE_DIR:-/opt/truemail}"
VPS_IP="${VPS_PUBLIC_IP:-74.208.76.213}"
MARKER_BEGIN="# BEGIN TROOP3-SITE"
MARKER_END="# END TROOP3-SITE"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

need_cmd git
need_cmd curl
need_cmd python3

if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
  echo "Installing Node.js 20..."
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y nodejs
fi

echo "=== clone/update ${REPO_URL} @ ${BRANCH} ==="
mkdir -p "$(dirname "$SITE_ROOT")"
if [[ -d "$SITE_ROOT/.git" ]]; then
  current_url="$(git -C "$SITE_ROOT" remote get-url origin 2>/dev/null || true)"
  if [[ "$current_url" != "$REPO_URL" ]]; then
    echo "origin changed ($current_url -> $REPO_URL); recloning"
    rm -rf "$SITE_ROOT"
    git clone --branch "$BRANCH" --depth 1 "$REPO_URL" "$SITE_ROOT"
  else
    git -C "$SITE_ROOT" fetch --prune origin
    git -C "$SITE_ROOT" checkout "$BRANCH"
    git -C "$SITE_ROOT" reset --hard "origin/$BRANCH"
  fi
else
  rm -rf "$SITE_ROOT"
  git clone --branch "$BRANCH" --depth 1 "$REPO_URL" "$SITE_ROOT"
fi

echo "=== build ==="
cd "$SITE_ROOT"
npm ci
npm run build

NODE_BIN="$(command -v node)"
echo "=== systemd unit ${SERVICE_NAME} ==="
cat >"/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=Troop 3 Ambler site (${DOMAIN})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${SITE_ROOT}
Environment=PORT=${PORT}
Environment=NODE_ENV=production
ExecStart=${NODE_BIN} ${SITE_ROOT}/server.js
Restart=on-failure
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}.service"
systemctl restart "${SERVICE_NAME}.service"
sleep 1
systemctl --no-pager --full status "${SERVICE_NAME}.service" | head -n 20

echo "=== Caddy site block ==="
export DOMAIN PORT CADDYFILE MARKER_BEGIN MARKER_END
python3 <<'PY'
from pathlib import Path
import os, re

caddy = Path(os.environ["CADDYFILE"])
text = caddy.read_text(encoding="utf-8")
begin = os.environ["MARKER_BEGIN"]
end = os.environ["MARKER_END"]
domain = os.environ["DOMAIN"]
port = os.environ["PORT"]
block = f"""{begin}
{domain} {{
\tencode gzip
\treverse_proxy 172.18.0.1:{port} {{
\t\theader_up Host {{host}}
\t\theader_up X-Forwarded-Host {{host}}
\t\theader_up X-Forwarded-Proto {{scheme}}
\t\theader_down -X-Frame-Options
\t\theader_down -Content-Security-Policy
\t}}
\theader {{
\t\tStrict-Transport-Security "max-age=31536000; includeSubDomains; preload"
\t\tX-Content-Type-Options nosniff
\t\tReferrer-Policy strict-origin-when-cross-origin
\t\tContent-Security-Policy "frame-ancestors *"
\t}}
}}
{end}
"""
if begin in text and end in text:
    text = re.sub(
        re.escape(begin) + r".*?" + re.escape(end),
        block.strip(),
        text,
        count=1,
        flags=re.S,
    )
else:
    hook_end = "# END PORT-FORWARD-HOOKUPS"
    if hook_end in text:
        text = text.replace(hook_end, hook_end + "\n\n" + block.strip() + "\n", 1)
    else:
        text = text.rstrip() + "\n\n" + block.strip() + "\n"
caddy.write_text(text, encoding="utf-8")
print(f"updated {caddy}")
PY

echo "=== reload Caddy ==="
(
  cd "$COMPOSE_DIR"
  docker compose exec -T caddy caddy validate --config /etc/caddy/Caddyfile
  docker compose exec -T caddy caddy reload --config /etc/caddy/Caddyfile
)

echo "=== Cloudflare DNS A ${DOMAIN} -> ${VPS_IP} ==="
set +u
# shellcheck disable=SC1091
source /opt/wireguard/port-forward-ui.env 2>/dev/null || true
set -u
export DOMAIN VPS_IP
if [[ -n "${CF_API_TOKEN:-}" ]]; then
  export CF_API_TOKEN
  python3 <<'PY'
import json, os, urllib.request, urllib.error

token = os.environ["CF_API_TOKEN"]
domain = os.environ["DOMAIN"]
ip = os.environ["VPS_IP"]
proxied = True

def cf(method, path, payload=None):
    url = "https://api.cloudflare.com/client/v4" + path
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        raise SystemExit(f"Cloudflare {method} {path} failed: {e.code} {body}")

zones = cf("GET", "/zones?name=vpstruelord.com&per_page=50")["result"]
if not zones:
    zones = [
        z
        for z in cf("GET", "/zones?per_page=50")["result"]
        if domain == z["name"] or domain.endswith("." + z["name"])
    ]
if not zones:
    raise SystemExit("Cloudflare zone for vpstruelord.com not found")
zone = zones[0]
zid = zone["id"]
listed = cf("GET", f"/zones/{zid}/dns_records?type=A&name={domain}")["result"]
payload = {"type": "A", "name": domain, "content": ip, "ttl": 120, "proxied": proxied}
if listed:
    rid = listed[0]["id"]
    cf("PUT", f"/zones/{zid}/dns_records/{rid}", payload)
    print(f"updated A {domain} -> {ip} proxied={proxied}")
else:
    cf("POST", f"/zones/{zid}/dns_records", payload)
    print(f"created A {domain} -> {ip} proxied={proxied}")
PY
else
  echo "CF_API_TOKEN not set — add A record ${DOMAIN} -> ${VPS_IP} manually (proxied OK)" >&2
fi

echo "=== local smoke ==="
curl -fsS -o /dev/null -w "local_http=%{http_code}\n" --connect-timeout 5 "http://127.0.0.1:${PORT}/" || true
# Caddy HTTPS is on 127.0.0.1:4443 via sslh; try that first
curl -fsSk -o /dev/null -w "caddy_https=%{http_code}\n" --connect-timeout 15 \
  --resolve "${DOMAIN}:4443:127.0.0.1" "https://${DOMAIN}:4443/" || \
curl -fsS -o /dev/null -w "caddy_http=%{http_code}\n" --connect-timeout 10 \
  -H "Host: ${DOMAIN}" "http://127.0.0.1/" || true

echo "Done. Site should be at https://${DOMAIN}/"
