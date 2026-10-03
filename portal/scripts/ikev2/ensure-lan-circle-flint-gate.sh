#!/usr/bin/env bash
# Block pending/denied home-LAN clients from reaching the portal on Flint
# *before* NAT. Caddy only sees the sealed router WAN after MASQUERADE, so
# per-device pending cannot be enforced in @vpn_clients alone.
#
# Approved LAN /32s are NOT blocked (and are also synced into Caddy for any
# path that preserves the real LAN source IP).
set -euo pipefail

ENV_FILE="${PORTAL_ENV_FILE:-/opt/wireguard/port-forward-ui.env}"
ALLOWLIST_FILE="${VPN_ALLOWLIST_FILE:-/opt/servermanager/panel/vpn-allowlist.json}"
BLOCK_FILE="${LAN_CIRCLE_BLOCK_FILE:-/opt/servermanager/panel/lan-circle-block.txt}"
OVPN_GW="${OVPN_FLINT_IP:-10.9.0.2}"
VPS_IP="${VPS_PUBLIC_IP:-74.208.76.213}"
CHAIN="${LAN_CIRCLE_IPT_CHAIN:-SM-LAN-CIRCLE}"

# shellcheck disable=SC1090
set -a
[ -f "$ENV_FILE" ] && . "$ENV_FILE"
set +a

PASS="${ROUTER_PASS:-}"
if [ -z "$PASS" ] && [ -n "${ROUTER_PASS_B64:-}" ]; then
  PASS="$(
    ROUTER_PASS_B64="$ROUTER_PASS_B64" python3 -c \
      'import os,base64; print(base64.b64decode(os.environ["ROUTER_PASS_B64"]).decode())' \
      2>/dev/null || true
  )"
fi
[ -n "$PASS" ] || {
  echo "lan-circle: no ROUTER_PASS — skip Flint gate"
  exit 0
}
command -v sshpass >/dev/null 2>&1 || {
  echo "lan-circle: sshpass missing — skip Flint gate"
  exit 0
}

export ALLOWLIST_FILE BLOCK_FILE VPS_IP
BLOCK_LIST="$(
  python3 - <<'PY'
import json
import os
import re
from pathlib import Path

allow = Path(os.environ.get("ALLOWLIST_FILE", "/opt/servermanager/panel/vpn-allowlist.json"))
block_file = Path(os.environ.get("BLOCK_FILE", "/opt/servermanager/panel/lan-circle-block.txt"))
vps = os.environ.get("VPS_IP", "74.208.76.213").strip() or "74.208.76.213"


def norm(raw: str) -> str:
    raw = (raw or "").strip()
    if "/" in raw:
        raw = raw.split("/", 1)[0]
    return raw


def is_home_lan(ip: str) -> bool:
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip or ""):
        return False
    parts = [int(x) for x in ip.split(".")]
    if parts[0] != 192 or parts[1] != 168 or parts[2] != 8:
        return False
    return parts[3] not in (0, 1, 255)


data = {"allowed": [], "denied": [], "pending": []}
if allow.is_file():
    try:
        loaded = json.loads(allow.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            for key in data:
                if isinstance(loaded.get(key), list):
                    data[key] = loaded[key]
    except Exception:
        pass

allowed = {
    norm(r.get("ip", ""))
    for r in (data.get("allowed") or [])
    if isinstance(r, dict) and is_home_lan(norm(r.get("ip", "")))
}
blocked: list[str] = []
seen = set()
for key in ("pending", "denied"):
    for row in data.get(key) or []:
        if not isinstance(row, dict):
            continue
        ip = norm(row.get("ip", ""))
        if not is_home_lan(ip) or ip in allowed or ip in seen:
            continue
        # denied rows are also mirrored into pending with status=denied
        if key == "pending" and str(row.get("status") or "") == "allowed":
            continue
        seen.add(ip)
        blocked.append(ip)

block_file.parent.mkdir(parents=True, exist_ok=True)
lines = [
    "# Managed by ensure-lan-circle-flint-gate.sh",
    f"# Reject these LAN sources to {vps}:80,443 on Flint (pre-NAT).",
    "# one IPv4 per line",
]
lines.extend(blocked)
block_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
print("\n".join(blocked))
PY
)"

export SSHPASS="$PASS"
# Prefer OpenVPN VIP; fall back to LAN admin IP / ROUTER_HOSTS.
FLINT_HOST=""
HOST_CANDIDATES=("$OVPN_GW" "192.168.8.1")
if [ -n "${ROUTER_HOSTS:-}" ]; then
  IFS=',' read -r -a _extra <<< "$ROUTER_HOSTS"
  HOST_CANDIDATES+=("${_extra[@]}")
fi
for h in "${HOST_CANDIDATES[@]}"; do
  h="$(echo "$h" | tr -d '[:space:]')"
  [ -n "$h" ] || continue
  if sshpass -e ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no -o ConnectTimeout=5 "root@${h}" "echo ok" >/dev/null 2>&1; then
    FLINT_HOST="$h"
    break
  fi
done
[ -n "$FLINT_HOST" ] || {
  echo "lan-circle: Flint unreachable — block list written, gate not applied"
  exit 0
}

# Build remote script with embedded block list + VPS IP.
REMOTE_SCRIPT="$(
  BLOCK_LIST="$BLOCK_LIST" VPS_IP="$VPS_IP" CHAIN="$CHAIN" python3 - <<'PY'
import os

vps = os.environ.get("VPS_IP", "74.208.76.213")
chain = os.environ.get("CHAIN", "SM-LAN-CIRCLE")
blocks = [b.strip() for b in (os.environ.get("BLOCK_LIST") or "").splitlines() if b.strip()]
print("set -e")
print(f'VPS="{vps}"')
print(f'CHAIN="{chain}"')
print("iptables -t filter -N \"$CHAIN\" 2>/dev/null || iptables -t filter -F \"$CHAIN\"")
print("# Ensure jump exists near the top of forwarding (GL.iNet uses forwarding_rule)")
print("if iptables -t filter -L forwarding_rule -n >/dev/null 2>&1; then")
print("  iptables -t filter -C forwarding_rule -j \"$CHAIN\" 2>/dev/null || iptables -t filter -I forwarding_rule 1 -j \"$CHAIN\"")
print("else")
print("  iptables -t filter -C FORWARD -j \"$CHAIN\" 2>/dev/null || iptables -t filter -I FORWARD 1 -j \"$CHAIN\"")
print("fi")
for ip in blocks:
    print(
        f'iptables -t filter -A "$CHAIN" -s {ip}/32 -d "$VPS"/32 -p tcp '
        f'-m multiport --dports 80,443 -j REJECT --reject-with tcp-reset'
    )
    print(
        f'iptables -t filter -A "$CHAIN" -s {ip}/32 -d "$VPS"/32 -p udp '
        f'-m multiport --dports 80,443 -j REJECT --reject-with icmp-port-unreachable'
    )
print(f'echo "lan-circle: blocked {len(blocks)} LAN IP(s) to {vps}:80,443 on Flint"')
print('iptables -t filter -S "$CHAIN" | head -40')
PY
)"

echo "$REMOTE_SCRIPT" | sshpass -e ssh -o StrictHostKeyChecking=no \
  -o PreferredAuthentications=password -o PubkeyAuthentication=no \
  -o ConnectTimeout=8 "root@${FLINT_HOST}" sh -s

echo "lan-circle: applied via ${FLINT_HOST} ($(echo "$BLOCK_LIST" | grep -c . || true) blocked)"
