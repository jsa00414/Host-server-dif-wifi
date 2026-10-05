#!/usr/bin/env bash
# Force portal.vpstruelord.com to ALPN http/1.1 only.
# Surface/Chrome HTTP/2 over the Flint socat relay + campus-WAN abort path
# surfaces as ERR_HTTP2_PROTOCOL_ERROR; h1 avoids that class of failure.
set -euo pipefail

CADDYFILE="${CADDYFILE_PATH:-/opt/truemail/Caddyfile}"
CADDY_CTR="${CADDY_CONTAINER:-truemail-caddy-1}"
export CADDYFILE

python3 <<'PY'
from pathlib import Path
import os
import re
import sys

path = Path(os.environ["CADDYFILE"])
text = path.read_text()
if "portal.vpstruelord.com" not in text:
    print("ensure-portal-http1-alpn: no portal site; skip")
    sys.exit(0)

m = re.search(r"portal\.vpstruelord\.com \{(.{0,300})", text, re.S)
if m and "alpn http/1.1" in m.group(1):
    print("ensure-portal-http1-alpn: already set")
    sys.exit(0)

pat = re.compile(r"(portal\.vpstruelord\.com \{\n(?:\theader Alt-Svc \"clear\"\n)?)")

def repl(match: re.Match) -> str:
    return match.group(1) + "\ttls {\n\t\talpn http/1.1\n\t}\n"

new, n = pat.subn(repl, text, count=1)
if n != 1:
    print(f"ensure-portal-http1-alpn: replace failed n={n}", file=sys.stderr)
    sys.exit(1)
path.write_text(new)
print("ensure-portal-http1-alpn: patched", path)
PY

if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$CADDY_CTR"; then
  docker exec "$CADDY_CTR" caddy reload --config /etc/caddy/Caddyfile >/dev/null
  echo "ensure-portal-http1-alpn: caddy reloaded"
fi
