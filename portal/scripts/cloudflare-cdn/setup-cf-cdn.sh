#!/usr/bin/env bash
# ServerManager — Cloudflare CDN VPN bypass (VLESS + WS behind orange-cloud).
# Campus/firewall often allow Cloudflare IPs when direct VPS :8444 is blocked.
#
# Flow: client → Cloudflare edge :443 → origin Caddy (TLS) → 127.0.0.1:18444 Xray WS
#
# Requires: CF_API_TOKEN (+ CF_ZONE_ID or zone discoverable), Caddy, Xray setup.
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
XRAY_SETUP="${XRAY_SETUP_SCRIPT:-$ROOT/scripts/xray/setup-xray.sh}"
[[ -f "$XRAY_SETUP" ]] || XRAY_SETUP="/opt/wireguard/port-forward-ui/scripts/xray/setup-xray.sh"

XRAY_CF_HOST="${XRAY_CF_HOST:-cdn.vpstruelord.com}"
XRAY_CF_WS_PORT="${XRAY_CF_WS_PORT:-18444}"
XRAY_CF_WS_PATH="${XRAY_CF_WS_PATH:-/vless-cf}"
CADDYFILE="${CADDYFILE_PATH:-/opt/truemail/Caddyfile}"
ENV_FILE="${PORTAL_ENV_FILE:-/opt/wireguard/port-forward-ui.env}"
VPS_PUBLIC_IP="${VPS_PUBLIC_IP:-74.208.76.213}"
MARKER_BEGIN="# BEGIN SM-CF-CDN"
MARKER_END="# END SM-CF-CDN"

if [[ -f "$ENV_FILE" ]]; then
  # Pull only the keys we need (avoid sourcing arbitrary shell from env file).
  eval "$(
    python3 - <<PY
from pathlib import Path
want = {
    "CF_API_TOKEN", "CF_ZONE_ID", "CF_ZONE_NAME", "VPS_PUBLIC_IP",
    "XRAY_CF_HOST", "XRAY_CF_WS_PORT", "XRAY_CF_WS_PATH", "CADDYFILE_PATH",
}
for line in Path("$ENV_FILE").read_text(encoding="utf-8", errors="replace").splitlines():
    s = line.strip()
    if not s or s.startswith("#") or "=" not in s:
        continue
    k, v = s.split("=", 1)
    k = k.strip()
    if k not in want:
        continue
    v = v.strip().strip('"').strip("'")
    print(f"export {k}={v!r}")
PY
  )"
fi

XRAY_CF_HOST="${XRAY_CF_HOST:-cdn.vpstruelord.com}"
XRAY_CF_WS_PORT="${XRAY_CF_WS_PORT:-18444}"
XRAY_CF_WS_PATH="${XRAY_CF_WS_PATH:-/vless-cf}"
[[ "$XRAY_CF_WS_PATH" == /* ]] || XRAY_CF_WS_PATH="/$XRAY_CF_WS_PATH"
CADDYFILE="${CADDYFILE_PATH:-$CADDYFILE}"

echo "=== 1/4 refresh Xray (includes vless-cf-ws inbound) ==="
export XRAY_CF_HOST XRAY_CF_WS_PORT XRAY_CF_WS_PATH
bash "$XRAY_SETUP"

echo "=== 2/4 Caddy site for ${XRAY_CF_HOST} ==="
if [[ ! -f "$CADDYFILE" ]]; then
  echo "Caddyfile missing at $CADDYFILE" >&2
  exit 1
fi

python3 - <<PY
from pathlib import Path
caddy = Path("$CADDYFILE")
text = caddy.read_text(encoding="utf-8")
begin = "$MARKER_BEGIN"
end = "$MARKER_END"
host = "$XRAY_CF_HOST"
port = "$XRAY_CF_WS_PORT"
path = "$XRAY_CF_WS_PATH"
block = f"""{begin}
{host} {{
\tencode gzip
\t@cfws path {path} {path}/*
\thandle @cfws {{
\t\treverse_proxy 127.0.0.1:{port}
\t}}
\thandle {{
\t\trespond "cf-cdn" 200
\t}}
}}
{end}
"""
if begin in text and end in text:
    pre = text[: text.index(begin)]
    post = text[text.index(end) + len(end) :]
    text = pre + block + post
else:
    if not text.endswith("\n"):
        text += "\n"
    text += "\n" + block + "\n"
caddy.write_text(text, encoding="utf-8")
print(f"wrote {caddy} block for {host}")
PY

# Validate + reload Caddy (docker truemail or host caddy)
reload_caddy() {
  if command -v caddy >/dev/null 2>&1 && [[ -f "$CADDYFILE" ]]; then
    caddy validate --config "$CADDYFILE" 2>&1 | tail -5 || true
  fi
  # Prefer dockerized Caddy used by truemail/portal stack
  for c in $(docker ps --format '{{.Names}}' 2>/dev/null | grep -iE 'caddy|truemail' || true); do
    if docker exec "$c" caddy validate --config /etc/caddy/Caddyfile >/dev/null 2>&1 \
      || docker exec "$c" test -f /etc/caddy/Caddyfile; then
      # Sync host Caddyfile into container mount if same path, else copy
      docker exec "$c" caddy reload --config /etc/caddy/Caddyfile 2>/dev/null \
        && echo "reloaded caddy container $c" && return 0
    fi
  done
  if systemctl is-active --quiet caddy 2>/dev/null; then
    systemctl reload caddy && echo "reloaded host caddy" && return 0
  fi
  echo "WARN: could not reload Caddy automatically — reload manually" >&2
  return 0
}
reload_caddy

echo "=== 3/4 Cloudflare orange-cloud A record ==="
python3 - <<'PY'
import json, os, urllib.request, urllib.error

token = (os.environ.get("CF_API_TOKEN") or "").strip()
zone_id = (os.environ.get("CF_ZONE_ID") or "").strip()
zone_name = (os.environ.get("CF_ZONE_NAME") or "vpstruelord.com").strip()
host = (os.environ.get("XRAY_CF_HOST") or "cdn.vpstruelord.com").strip().lower()
ip = (os.environ.get("VPS_PUBLIC_IP") or "74.208.76.213").strip()

if not token:
    print("CF_API_TOKEN missing — create orange-cloud A manually:")
    print(f"  {host} → {ip} (Proxied / orange cloud)")
    raise SystemExit(0)

def cf(method, path, body=None):
    req = urllib.request.Request(
        f"https://api.cloudflare.com/client/v4{path}",
        data=None if body is None else json.dumps(body).encode(),
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        raise SystemExit(f"CF API {method} {path} failed: {e.code} {raw[:400]}")

if not zone_id:
    data = cf("GET", f"/zones?name={zone_name}")
    zones = data.get("result") or []
    if not zones:
        raise SystemExit(f"zone not found: {zone_name}")
    zone_id = zones[0]["id"]
    print(f"resolved zone {zone_name} → {zone_id}")

listed = cf("GET", f"/zones/{zone_id}/dns_records?type=A&name={host}")
recs = listed.get("result") or []
payload = {
    "type": "A",
    "name": host,
    "content": ip,
    "ttl": 1,
    "proxied": True,
}
if recs:
    rid = recs[0]["id"]
    same = (
        str(recs[0].get("content") or "") == ip
        and bool(recs[0].get("proxied")) is True
    )
    if same:
        print(f"{host}: A {ip} already proxied")
    else:
        cf("PUT", f"/zones/{zone_id}/dns_records/{rid}", payload)
        print(f"{host}: updated A → {ip} (proxied)")
else:
    cf("POST", f"/zones/{zone_id}/dns_records", payload)
    print(f"{host}: created A → {ip} (proxied)")
PY

echo "=== 4/4 env hints ==="
if [[ -f "$ENV_FILE" ]]; then
  python3 - <<PY
from pathlib import Path
p = Path("$ENV_FILE")
wanted = {
    "XRAY_CF_HOST": "$XRAY_CF_HOST",
    "XRAY_CF_WS_PORT": "$XRAY_CF_WS_PORT",
    "XRAY_CF_WS_PATH": "$XRAY_CF_WS_PATH",
}
lines = p.read_text(encoding="utf-8").splitlines()
out, seen = [], set()
for line in lines:
    if "=" in line and not line.strip().startswith("#"):
        k = line.split("=", 1)[0].strip()
        if k in wanted:
            out.append(f'{k}="{wanted[k]}"')
            seen.add(k)
            continue
    out.append(line)
for k, v in wanted.items():
    if k not in seen:
        out.append(f'{k}="{v}"')
p.write_text("\n".join(out) + "\n", encoding="utf-8")
print(f"updated {p}")
PY
fi

echo
echo "Cloudflare CDN bypass ready."
echo "  Host:  ${XRAY_CF_HOST}:443 (orange-cloud)"
echo "  Path:  ${XRAY_CF_WS_PATH}"
echo "  Local: 127.0.0.1:${XRAY_CF_WS_PORT}"
echo "Import the CF CDN link from portal Xray page (same UUID as REALITY)."
echo "SSL/TLS mode in Cloudflare dashboard should be Full (strict)."
