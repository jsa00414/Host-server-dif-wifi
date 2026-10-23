#!/usr/bin/env bash
# Stop publishing remote-desktop TCP :5000 on all interfaces.
# Caddy reaches it on the Docker network (remote-desktop:5000).
# WireGuard tunnel stays on UDP :5000 (untouched).
# Safe to re-run.
set -euo pipefail

COMPOSE="${REMOTE_DESKTOP_COMPOSE:-/opt/remote-desktop/docker-compose.yml}"
PORT="${REMOTE_DESKTOP_PORT:-5000}"
VPN_UFW_FROM="${VPN_UFW_FROM:-10.8.0.0/24 10.9.0.0/24 100.64.0.0/10 192.168.8.0/24}"
EXTRA_ALLOW="${REMOTE_DESKTOP_EXTRA_ALLOW:-10.42.42.0/24 172.16.0.0/12 127.0.0.1}"

if [[ ! -f "$COMPOSE" ]]; then
  echo "skip: missing $COMPOSE"
  exit 0
fi

python3 - "$COMPOSE" "$PORT" <<'PY'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
port = sys.argv[2]
text = path.read_text(encoding="utf-8")
pat = re.compile(
    rf'(?m)^(\s*-\s*)["\']?(?:0\.0\.0\.0:)?{re.escape(port)}:{re.escape(port)}["\']?\s*$'
)
repl = rf'\1"127.0.0.1:{port}:{port}"'
out = pat.sub(repl, text)
out = out.replace(f'""127.0.0.1:{port}:{port}""', f'"127.0.0.1:{port}:{port}"')
if out != text:
    path.write_text(out, encoding="utf-8")
    print(f"updated {path}: bind 127.0.0.1:{port}:{port}")
else:
    if f"127.0.0.1:{port}:{port}" in text:
        print(f"already localhost-bound: {path}")
    else:
        print(f"WARN: no {port}:{port} mapping matched in {path}", file=sys.stderr)
for i, line in enumerate(out.splitlines(), 1):
    if "ports" in line or port in line:
        print(f"{i}:{line}")
PY

cd "$(dirname "$COMPOSE")"
if docker compose version >/dev/null 2>&1; then
  docker compose up -d --force-recreate remote-desktop
else
  docker-compose up -d --force-recreate remote-desktop
fi

sources=()
for p in ${VPN_UFW_FROM//,/ }; do
  [[ -n "${p// }" ]] && sources+=("$p")
done
for p in ${EXTRA_ALLOW//,/ }; do
  [[ -n "${p// }" ]] && sources+=("$p")
done

# Belt-and-suspenders: DOCKER-USER DROP for TCP :5000 (not UDP WireGuard).
if iptables -nL DOCKER-USER >/dev/null 2>&1; then
  while read -r line; do
    [[ -z "$line" ]] && continue
    eval "iptables ${line/-A/-D}" 2>/dev/null || true
  done < <(iptables -S DOCKER-USER | grep -E "SM-RD-5000" || true)

  if ! iptables -C DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN 2>/dev/null; then
    iptables -I DOCKER-USER 1 -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
  fi
  for src in "${sources[@]}"; do
    if ! iptables -C DOCKER-USER -s "$src" -p tcp --dport "$PORT" -m comment --comment "SM-RD-5000-ALLOW" -j RETURN 2>/dev/null; then
      iptables -I DOCKER-USER 2 -s "$src" -p tcp --dport "$PORT" -m comment --comment "SM-RD-5000-ALLOW" -j RETURN
    fi
  done
  if ! iptables -C DOCKER-USER -p tcp --dport "$PORT" -m comment --comment "SM-RD-5000-DROP" -j DROP 2>/dev/null; then
    iptables -A DOCKER-USER -p tcp --dport "$PORT" -m comment --comment "SM-RD-5000-DROP" -j DROP
  fi
  echo "docker-user: ${PORT}/tcp DROP except VPN/LAN/Docker"
  iptables -S DOCKER-USER | grep -E "SM-RD-5000|RELATED" || true
fi

# VPN-gate remote.truemailor.com in Caddy (host :5000 is no longer public;
# without this the app stays world-reachable on 443).
CADDYFILE="${CADDYFILE:-/opt/truemail/Caddyfile}"
if [[ -f "$CADDYFILE" ]] && grep -q 'remote.truemailor.com' "$CADDYFILE"; then
  python3 - "$CADDYFILE" <<'PY'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
block_re = re.compile(
    r"remote\.truemailor\.com\s*\{.*?^\}",
    re.M | re.S,
)
m = block_re.search(text)
if not m:
    print("caddy: remote.truemailor.com block not found")
    raise SystemExit(0)
block = m.group(0)
if "@vpn_clients" in block and "Forbidden" in block:
    print("caddy: remote.truemailor.com already VPN-gated")
    raise SystemExit(0)
new_block = """remote.truemailor.com {
	encode gzip
	@vpn_clients remote_ip 10.8.0.0/24 10.42.42.0/24 192.168.8.0/24 10.9.0.0/24 100.64.0.0/10 172.18.0.1/32 127.0.0.1/32
	handle @vpn_clients {
		reverse_proxy remote-desktop:5000
	}
	handle {
		respond "Forbidden" 403
	}
	header {
		Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
		X-Content-Type-Options nosniff
		Referrer-Policy strict-origin-when-cross-origin
		X-Frame-Options DENY
	}
}"""
path.write_text(text[: m.start()] + new_block + text[m.end() :], encoding="utf-8")
print("caddy: remote.truemailor.com VPN-gated")
PY
  caddy_ctr=""
  for c in truemail-caddy-1 caddy; do
    if docker ps --format '{{.Names}}' | grep -qx "$c"; then
      caddy_ctr="$c"
      break
    fi
  done
  if [[ -n "$caddy_ctr" ]]; then
    if ! docker exec "$caddy_ctr" caddy reload --config /etc/caddy/Caddyfile >/dev/null 2>&1; then
      docker restart "$caddy_ctr" >/dev/null
    fi
    echo "caddy: reloaded/restarted $caddy_ctr"
  fi
fi

ss -lntp | grep ":${PORT}" || true
docker ps --filter name=remote-desktop --format '{{.Names}} {{.Ports}}'
echo "remote-desktop localhost/VPN harden complete"
