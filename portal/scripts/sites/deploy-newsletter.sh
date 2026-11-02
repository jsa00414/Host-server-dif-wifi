#!/usr/bin/env bash
# Deploy newsletter.vpstruelord.com from this tree (or a git clone).
# Usage (on VPS as root):
#   bash /opt/wireguard/port-forward-ui/scripts/sites/deploy-newsletter.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
SRC="${NEWSLETTER_SRC:-$ROOT/newsletter}"
DEST="${NEWSLETTER_DEST:-/opt/sites/newsletter}"
PORT="${NEWSLETTER_PORT:-3017}"
DOMAIN="${NEWSLETTER_DOMAIN:-newsletter.vpstruelord.com}"
CADDYFILE="${CADDYFILE_PATH:-/opt/truemail/Caddyfile}"
UNIT=/etc/systemd/system/newsletter-site.service
VPS_IP="${VPS_PUBLIC_IP:-74.208.76.213}"
ENV_FILE="${PORTAL_ENV_FILE:-/opt/wireguard/port-forward-ui.env}"

if [[ ! -f "$SRC/server.js" ]]; then
  echo "missing $SRC/server.js" >&2
  exit 1
fi

mkdir -p "$DEST/public"
rsync -a --delete \
  --exclude node_modules \
  --exclude .git \
  "$SRC"/ "$DEST"/

cat >"$UNIT" <<UNIT
[Unit]
Description=Newsletter site (${DOMAIN})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${DEST}
Environment=PORT=${PORT}
Environment=NODE_ENV=production
ExecStart=/usr/bin/node ${DEST}/server.js
Restart=on-failure
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now newsletter-site.service
systemctl restart newsletter-site.service
sleep 1
systemctl is-active newsletter-site.service
curl -fsS -o /dev/null -w "local=%{http_code}\n" "http://127.0.0.1:${PORT}/"

# Caddy site block outside managed hookups (survives portal Save).
python3 - "$CADDYFILE" "$DOMAIN" "$PORT" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
domain = sys.argv[2]
port = sys.argv[3]
text = path.read_text(encoding="utf-8") if path.is_file() else ""
begin = "# BEGIN NEWSLETTER-SITE"
end = "# END NEWSLETTER-SITE"
block = f"""{begin}
{domain} {{
\tencode gzip
\treverse_proxy 172.18.0.1:{port} {{
\t\theader_up Host {{host}}
\t\theader_up X-Forwarded-Host {{host}}
\t\theader_up X-Forwarded-Proto {{scheme}}
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
    pre, rest = text.split(begin, 1)
    _, post = rest.split(end, 1)
    text = pre.rstrip() + "\n\n" + block + post.lstrip("\n")
else:
    text = text.rstrip() + "\n\n" + block + "\n"
path.write_text(text, encoding="utf-8")
print(f"wrote {path} newsletter block")
PY

# Reload caddy container if present
DOCKER=(docker)
if ! docker ps >/dev/null 2>&1; then
  DOCKER=(sudo docker)
fi
if "${DOCKER[@]}" ps --format '{{.Names}}' | grep -qx truemail-caddy-1; then
  # Host Caddyfile is bind-mounted into the container.
  "${DOCKER[@]}" exec truemail-caddy-1 caddy validate --config /etc/caddy/Caddyfile
  "${DOCKER[@]}" exec truemail-caddy-1 caddy reload --config /etc/caddy/Caddyfile
  echo "caddy reloaded"
fi

# Cloudflare A record (vpstruelord.com zone)
if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
fi
if [[ -n "${CF_API_TOKEN:-}" && -n "${CF_ZONE_ID:-}" ]]; then
  python3 - "$DOMAIN" "$VPS_IP" <<'PY'
import json, os, urllib.request, sys
domain, ip = sys.argv[1], sys.argv[2]
token = os.environ["CF_API_TOKEN"]
zone = os.environ["CF_ZONE_ID"]
proxied = str(os.environ.get("CF_PROXIED", "false")).lower() in ("1", "true", "yes")

def cf(method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        "https://api.cloudflare.com/client/v4" + path,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode())

listed = cf("GET", f"/zones/{zone}/dns_records?type=A&name={domain}")
recs = listed.get("result") or []
payload = {"type": "A", "name": domain, "content": ip, "ttl": 120, "proxied": proxied}
if recs:
    rid = recs[0]["id"]
    out = cf("PUT", f"/zones/{zone}/dns_records/{rid}", payload)
    print("cf updated", domain, "->", ip, "proxied", proxied, "ok", out.get("success"))
else:
    out = cf("POST", f"/zones/{zone}/dns_records", payload)
    print("cf created", domain, "->", ip, "proxied", proxied, "ok", out.get("success"))
PY
else
  echo "CF_API_TOKEN/CF_ZONE_ID missing — set DNS for ${DOMAIN} manually to ${VPS_IP}"
fi

echo "Done. https://${DOMAIN}/"
