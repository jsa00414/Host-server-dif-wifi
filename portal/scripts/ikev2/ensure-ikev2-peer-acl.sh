#!/usr/bin/env bash
# Allow active IKEv2 peer *public* IPs through Caddy @vpn_clients.
#
# Windows/iOS exclude the VPN gateway public IP from the tunnel, so HTTPS to
# portal.vpstruelord.com often arrives from the peer WAN IP (not 10.10.0.x).
# Split-DNS helps when the client uses VPN DNS; this ACL covers DoH / DNS-leak /
# gateway-exclusion cases while an SA is up.
#
# Sticky IPs in /opt/servermanager/panel/caddy-sticky-vpn-ips.txt survive
# disconnects (home WAN) so router/portal keep working without a live SA.
set -euo pipefail

CADDYFILE="${CADDYFILE:-/opt/truemail/Caddyfile}"
ENV_FILE="${PORTAL_ENV_FILE:-/opt/wireguard/port-forward-ui.env}"
STATE_DIR="${IKEV2_PEER_ACL_DIR:-/var/lib/servermanager}"
STATE_FILE="${STATE_DIR}/ikev2-peer-ips.txt"
STICKY_FILE="${STICKY_VPN_IPS_FILE:-/opt/servermanager/panel/caddy-sticky-vpn-ips.txt}"
BASE_CIDRS_DEFAULT="10.8.0.0/24 10.42.42.0/24 192.168.8.0/24 10.9.0.0/24 10.10.0.0/24 100.64.0.0/10 127.0.0.1/32 74.208.76.213/32"

export CADDYFILE PORTAL_ENV_FILE="$ENV_FILE" STATE_FILE STICKY_FILE BASE_CIDRS_DEFAULT

mkdir -p "$STATE_DIR" "$(dirname "$STICKY_FILE")"

python3 - <<'PY'
import os
import re
import subprocess
from pathlib import Path

caddyfile = Path(os.environ.get("CADDYFILE", "/opt/truemail/Caddyfile"))
env_file = Path(os.environ.get("PORTAL_ENV_FILE", "/opt/wireguard/port-forward-ui.env"))
state_file = Path(os.environ.get("STATE_FILE", "/var/lib/servermanager/ikev2-peer-ips.txt"))
sticky_file = Path(
    os.environ.get("STICKY_FILE", "/opt/servermanager/panel/caddy-sticky-vpn-ips.txt")
)
base_default = os.environ.get(
    "BASE_CIDRS_DEFAULT",
    "10.8.0.0/24 10.42.42.0/24 192.168.8.0/24 10.9.0.0/24 10.10.0.0/24 100.64.0.0/10 127.0.0.1/32 74.208.76.213/32",
)

PRIVATE = [
    re.compile(r"^10\."),
    re.compile(r"^127\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[0-1])\."),
    re.compile(r"^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\."),
]


def is_public_ipv4(ip: str) -> bool:
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
        return False
    return not any(p.match(ip) for p in PRIVATE)


def peer_ips() -> list[str]:
    try:
        out = subprocess.check_output(
            ["ipsec", "statusall"], text=True, stderr=subprocess.STDOUT
        )
    except Exception:
        try:
            out = subprocess.check_output(
                ["ipsec", "status"], text=True, stderr=subprocess.STDOUT
            )
        except Exception:
            return []
    found = []
    # e.g. 74.208.76.213[portal...]...192.81.235.246[172.16.17.228]
    for m in re.finditer(r"\.\.\.(\d{1,3}(?:\.\d{1,3}){3})\[", out):
        ip = m.group(1)
        if is_public_ipv4(ip) and ip not in found:
            found.append(ip)
    return found


def load_sticky_cidrs() -> list[str]:
    out: list[str] = []
    if not sticky_file.is_file():
        return out
    for line in sticky_file.read_text().splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        if "/" not in raw:
            raw = f"{raw}/32"
        if raw not in out:
            out.append(raw)
    return out


def load_base_cidrs() -> list[str]:
    base = base_default.split()
    sticky = set(load_sticky_cidrs())
    if env_file.is_file():
        for line in env_file.read_text().splitlines():
            if line.startswith("VPN_CLIENT_CIDRS="):
                raw = line.split("=", 1)[1].strip().strip('"').strip("'")
                parts = raw.split()
                # Drop previously injected peer /32s (public singles), but keep
                # the VPS public /32 and sticky home-WAN entries.
                cleaned = []
                for p in parts:
                    if p.endswith("/32"):
                        ip = p[:-3]
                        if is_public_ipv4(ip) and ip != "74.208.76.213" and p not in sticky:
                            continue
                    cleaned.append(p)
                if cleaned:
                    base = cleaned
                break
    # Ensure IKEv2 pool + VPS public IP (hairpin) always present
    if "10.10.0.0/24" not in base:
        base.append("10.10.0.0/24")
    if "74.208.76.213/32" not in base:
        base.append("74.208.76.213/32")
    for s in sticky:
        if s not in base:
            base.append(s)
    return base


peers = peer_ips()
base = load_base_cidrs()
peer_cidrs = [f"{ip}/32" for ip in peers]
sticky_cidrs = load_sticky_cidrs()
combined = base[:]
for c in peer_cidrs + sticky_cidrs:
    if c not in combined:
        combined.append(c)
combined_s = " ".join(combined)

prev = state_file.read_text().strip() if state_file.is_file() else ""
cur = "\n".join(peers)
if prev == cur and caddyfile.is_file():
    text = caddyfile.read_text()
    needed = peers + [c[:-3] for c in sticky_cidrs if c.endswith("/32")]
    if needed and all(f"{ip}/32" in text for ip in needed):
        print(f"OK unchanged ({len(peers)} peers, {len(sticky_cidrs)} sticky)")
        raise SystemExit(0)

state_file.write_text(cur + ("\n" if cur else ""))

# Update env VPN_CLIENT_CIDRS
if env_file.is_file():
    lines = env_file.read_text().splitlines()
    out_lines = []
    found = False
    for line in lines:
        if line.startswith("VPN_CLIENT_CIDRS="):
            out_lines.append(f'VPN_CLIENT_CIDRS="{combined_s}"')
            found = True
        else:
            out_lines.append(line)
    if not found:
        out_lines.append(f'VPN_CLIENT_CIDRS="{combined_s}"')
    env_file.write_text("\n".join(out_lines) + "\n")
    print(f"updated {env_file}")

# Patch every @vpn_clients client_ip/remote_ip line (prefer client_ip + PROXY)
if not caddyfile.is_file():
    print(f"missing {caddyfile}")
    raise SystemExit(1)

text = caddyfile.read_text()


def _repl(m):
    return f"{m.group(1)}@vpn_clients client_ip {combined_s}"


pat = re.compile(r"^([ \t]*)@vpn_clients (?:client_ip|remote_ip) (.+)$", re.M)
new_text, n = pat.subn(_repl, text)
if n == 0:
    print("WARN: no @vpn_clients client_ip/remote_ip lines found")
else:
    caddyfile.write_text(new_text)
    print(f"patched {n} Caddy @vpn_clients lines")

print("peers:", ", ".join(peers) if peers else "(none)")
print("sticky:", ", ".join(sticky_cidrs) if sticky_cidrs else "(none)")
print("cidrs:", combined_s)

# Reload Caddy
reload = subprocess.run(
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
if reload.returncode != 0:
    print("caddy reload failed:", (reload.stderr or reload.stdout)[:300])
    subprocess.check_call(["docker", "restart", "truemail-caddy-1"])
    print("restarted truemail-caddy-1")
else:
    print("caddy reloaded")
PY
