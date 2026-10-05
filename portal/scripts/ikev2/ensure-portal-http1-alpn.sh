#!/usr/bin/env bash
# Keep portal.vpstruelord.com reachable from Flint LAN even when Surface
# Secure DNS / cache sends traffic via campus WAN 192.81.235.246.
#
# - TLS ALPN http/1.1 only (avoids ERR_HTTP2_PROTOCOL_ERROR on abort/relay)
# - No @denied_wan abort on portal (that became ERR_EMPTY_RESPONSE under h1)
#   Auth still required; other sites keep campus deny.
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

changed = False

# 1) Strip @denied_wan from the portal site only (keep on other sites).
lines = text.splitlines(True)
out: list[str] = []
i = 0
while i < len(lines):
    line = lines[i]
    if line.startswith("portal.vpstruelord.com {"):
        out.append(line)
        i += 1
        depth = 1
        while i < len(lines) and depth > 0:
            l = lines[i]
            if depth == 1 and (
                "Hard-deny shared campus" in l
                or l.strip().startswith("@denied_wan")
            ):
                if "Hard-deny" in l:
                    i += 1
                    changed = True
                    continue
                if l.strip().startswith("@denied_wan"):
                    i += 1
                    if i < len(lines) and "handle @denied_wan" in lines[i]:
                        i += 1
                        while i < len(lines) and lines[i].strip() != "}":
                            i += 1
                        if i < len(lines) and lines[i].strip() == "}":
                            i += 1
                        if i < len(lines) and lines[i].strip() == "":
                            i += 1
                        changed = True
                        continue
            depth += l.count("{") - l.count("}")
            out.append(l)
            i += 1
        continue
    out.append(line)
    i += 1
text = "".join(out)

# 2) Ensure Alt-Svc clear + ALPN http/1.1 at portal site head.
m = re.search(r"portal\.vpstruelord\.com \{(.{0,400})", text, re.S)
head = m.group(1) if m else ""
if "alpn http/1.1" not in head:
    pat = re.compile(r"(portal\.vpstruelord\.com \{\n(?:\theader Alt-Svc \"clear\"\n)?)")

    def repl(match: re.Match) -> str:
        base = match.group(1)
        if "header Alt-Svc" not in base:
            base = "portal.vpstruelord.com {\n\theader Alt-Svc \"clear\"\n"
        return base + "\ttls {\n\t\talpn http/1.1\n\t}\n"

    text2, n = pat.subn(repl, text, count=1)
    if n != 1:
        print(f"ensure-portal-http1-alpn: alpn insert failed n={n}", file=sys.stderr)
        sys.exit(1)
    text = text2
    changed = True

if not changed:
    print("ensure-portal-http1-alpn: already ok")
else:
    path.write_text(text)
    print("ensure-portal-http1-alpn: patched", path)
PY

if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$CADDY_CTR"; then
  docker exec "$CADDY_CTR" caddy validate --config /etc/caddy/Caddyfile >/dev/null
  docker exec "$CADDY_CTR" caddy reload --config /etc/caddy/Caddyfile >/dev/null
  echo "ensure-portal-http1-alpn: caddy reloaded"
fi
