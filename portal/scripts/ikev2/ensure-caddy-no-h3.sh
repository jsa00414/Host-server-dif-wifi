#!/usr/bin/env bash
# Disable Caddy HTTP/3. UDP/443 on this host is WireGuard (redirect), not QUIC.
# Chrome follows Alt-Svc: h3=":443" after the first HTTPS hit, then the portal
# tab briefly loads and dies ("popped out then disappeared").
set -euo pipefail

CADDYFILE="${CADDYFILE:-/opt/truemail/Caddyfile}"

python3 - <<'PY'
from pathlib import Path
import re
import subprocess

path = Path("/opt/truemail/Caddyfile")
text = path.read_text()
changed = False

if not re.search(r"(?m)^\s*protocols\s+h1\s+h2\s*$", text):
    text2, n = re.subn(
        r"(?m)^(servers\s*\{\s*\n)",
        r"\1\tprotocols h1 h2\n",
        text,
        count=1,
    )
    if n == 0:
        raise SystemExit("servers block not found in Caddyfile")
    text = text2
    changed = True
    print("inserted protocols h1 h2")
else:
    print("protocols h1 h2 already set")

# Drop diagnostic Forbidden body if present
text2 = text.replace(
    'respond "Forbidden client={client_ip}" 403',
    'respond "Forbidden" 403',
)
if text2 != text:
    text = text2
    changed = True
    print("restored plain Forbidden response")

if changed:
    path.write_text(text)
    r = subprocess.run(
        [
            "docker",
            "exec",
            "truemail-caddy-1",
            "caddy",
            "reload",
            "--config",
            "/etc/caddy/Caddyfile",
        ],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        print(r.stderr or r.stdout)
        raise SystemExit("caddy reload failed")
    print("caddy reloaded")
else:
    print("no change")
PY
