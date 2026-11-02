#!/usr/bin/env bash
# Deploy Sunshine Second Grade (Next.js) to newsletter.vpstruelord.com.
# Usage (on VPS as root):
#   bash /opt/wireguard/port-forward-ui/scripts/sites/deploy-newsletter.sh
#
# Optional:
#   NEWSLETTER_SRC   source tree (default: sibling ./newsletter)
#   NEWSLETTER_BUNDLE  prebuilt standalone tarball (.tar.gz) — preferred on low-RAM VPS
#   NEWSLETTER_DEST  install dir (default: /opt/sites/newsletter)
#   NEWSLETTER_PORT  listen port (default: 3017)
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
BUNDLE="${NEWSLETTER_BUNDLE:-}"
APP_URL="${NEXT_PUBLIC_APP_URL:-https://${DOMAIN}}"

have_next_source() {
  [[ -f "$SRC/package.json" ]] && grep -q '"next"' "$SRC/package.json"
}

stage_from_bundle() {
  local tmp
  tmp="$(mktemp -d)"
  tar -xzf "$BUNDLE" -C "$tmp"
  # Accept either flat standalone or a single top-level dir
  if [[ -f "$tmp/server.js" ]]; then
    echo "$tmp"
  else
    local inner
    inner="$(find "$tmp" -maxdepth 2 -type f -name server.js | head -1)"
    [[ -n "$inner" ]] || { echo "bundle missing server.js" >&2; exit 1; }
    echo "$(dirname "$inner")"
  fi
}

stage_from_source_build() {
  echo "Building Next.js app in $SRC (needs RAM; prefer NEWSLETTER_BUNDLE on small VPS)" >&2
  (
    cd "$SRC"
    if [[ -f package-lock.json ]]; then
      npm ci --omit=dev
      # build needs typescript/tailwind from devDependencies
      npm ci
    else
      npm install
    fi
    export NEXT_PUBLIC_APP_URL="$APP_URL"
    npm run build
  )
  local stage
  stage="$(mktemp -d)"
  cp -a "$SRC/.next/standalone/." "$stage/"
  mkdir -p "$stage/.next"
  cp -a "$SRC/.next/static" "$stage/.next/"
  if [[ -d "$SRC/public" ]]; then
    cp -a "$SRC/public" "$stage/"
  fi
  echo "$stage"
}

STAGE=""
CLEANUP_STAGE=0
if [[ -n "$BUNDLE" && -f "$BUNDLE" ]]; then
  STAGE="$(stage_from_bundle)"
  CLEANUP_STAGE=1
elif [[ -f "$SRC/server.js" && -d "$SRC/.next" && -f "$SRC/package.json" ]] && grep -q '"next"' "$SRC/package.json" 2>/dev/null; then
  # Already a standalone runtime tree
  STAGE="$SRC"
elif have_next_source; then
  STAGE="$(stage_from_source_build)"
  CLEANUP_STAGE=1
elif [[ -f "$SRC/server.js" ]]; then
  echo "Refusing legacy Node placeholder at $SRC — provide Next.js source or NEWSLETTER_BUNDLE" >&2
  exit 1
else
  echo "missing newsletter Next.js source at $SRC (or set NEWSLETTER_BUNDLE)" >&2
  exit 1
fi

mkdir -p "$DEST"
# Preserve existing secrets + data across deploys
KEEP_ENV=""
KEEP_DATA=""
if [[ -f "$DEST/.env" ]]; then
  KEEP_ENV="$(mktemp)"
  cp -a "$DEST/.env" "$KEEP_ENV"
fi
if [[ -d "$DEST/data" ]]; then
  KEEP_DATA="$(mktemp -d)"
  cp -a "$DEST/data/." "$KEEP_DATA/"
fi

# Sync runtime (exclude host data/.env we just preserved)
find "$DEST" -mindepth 1 -maxdepth 1 ! -name data ! -name .env -exec rm -rf {} +
cp -a "$STAGE"/. "$DEST"/
mkdir -p "$DEST/data"

if [[ -n "$KEEP_DATA" ]]; then
  cp -a "$KEEP_DATA"/. "$DEST/data/"
  rm -rf "$KEEP_DATA"
fi

if [[ -n "$KEEP_ENV" ]]; then
  cp -a "$KEEP_ENV" "$DEST/.env"
  rm -f "$KEEP_ENV"
else
  SECRET="$(openssl rand -hex 32)"
  cat >"$DEST/.env" <<EOF
SESSION_SECRET=${SECRET}
NEXT_PUBLIC_APP_URL=${APP_URL}
COOKIE_SECURE=true
HOSTNAME=0.0.0.0
PORT=${PORT}
NODE_ENV=production
EOF
  chmod 600 "$DEST/.env"
fi

# Ensure baked public URL stays correct even if .env was preserved from an older deploy
if ! grep -q "^NEXT_PUBLIC_APP_URL=" "$DEST/.env"; then
  echo "NEXT_PUBLIC_APP_URL=${APP_URL}" >>"$DEST/.env"
fi
if ! grep -q "^COOKIE_SECURE=" "$DEST/.env"; then
  echo "COOKIE_SECURE=true" >>"$DEST/.env"
fi
# Must be 0.0.0.0 so Docker Caddy (172.18.0.1) can reach the Node process.
if grep -q "^HOSTNAME=" "$DEST/.env"; then
  sed -i 's/^HOSTNAME=.*/HOSTNAME=0.0.0.0/' "$DEST/.env"
else
  echo "HOSTNAME=0.0.0.0" >>"$DEST/.env"
fi

[[ "$CLEANUP_STAGE" -eq 1 ]] && rm -rf "$STAGE"

cat >"$UNIT" <<UNIT
[Unit]
Description=Newsletter site (${DOMAIN}) — Sunshine Second Grade
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${DEST}
EnvironmentFile=${DEST}/.env
Environment=PORT=${PORT}
Environment=NODE_ENV=production
Environment=HOSTNAME=0.0.0.0
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
sleep 2
systemctl is-active newsletter-site.service
curl -fsS -o /dev/null -w "local=%{http_code}\n" "http://127.0.0.1:${PORT}/admin/login" || true
curl -fsS -o /dev/null -w "local_gate=%{http_code}\n" "http://127.0.0.1:${PORT}/gate" || true

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
out = []
i = 0
found = False
while True:
    a = text.find(begin, i)
    if a < 0:
        out.append(text[i:])
        break
    out.append(text[i:a])
    b = text.find(end, a)
    if b < 0:
        raise SystemExit("NEWSLETTER Caddy end marker missing")
    i = b + len(end)
    found = True
body = "".join(out)
while "\n\n\n\n" in body:
    body = body.replace("\n\n\n\n", "\n\n\n")
text = body.rstrip() + "\n\n" + block + "\n"
path.write_text(text, encoding="utf-8")
print(f"wrote {path} newsletter block (replaced={found})")
PY

DOCKER=(docker)
if ! docker ps >/dev/null 2>&1; then
  DOCKER=(sudo docker)
fi
if "${DOCKER[@]}" ps --format '{{.Names}}' | grep -qx truemail-caddy-1; then
  "${DOCKER[@]}" exec truemail-caddy-1 caddy validate --config /etc/caddy/Caddyfile
  "${DOCKER[@]}" exec truemail-caddy-1 caddy reload --config /etc/caddy/Caddyfile
  echo "caddy reloaded"
fi

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

echo "Done. https://${DOMAIN}/  (gate /admin/login → create class + 2FA; PDF QR → /s/<token>)"
