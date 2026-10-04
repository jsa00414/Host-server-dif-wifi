#!/usr/bin/env bash
# Home-LAN trust circle gate on Flint (pre-NAT):
#   1) REJECT pending/denied/keyless LAN sources to VPS :80,:443
#   2) Force those same LAN IPs onto guest DNS (public resolver) so they
#      do not receive AdGuard admin rewrites (proxmox/plex/portal VIP names)
#
# Enrolled Authenticator LAN IPs and the timed enroll-unlock window are
# exempt (phones must reach portal/keys and may keep circle DNS).
# Key-bound allowlisted LAN /32s are NOT gated.
set -euo pipefail

ENV_FILE="${PORTAL_ENV_FILE:-/opt/wireguard/port-forward-ui.env}"
ALLOWLIST_FILE="${VPN_ALLOWLIST_FILE:-/opt/servermanager/panel/vpn-allowlist.json}"
AUTH_APP_DEVICES_FILE="${AUTH_APP_DEVICES_FILE:-/opt/servermanager/panel/auth-app-devices.json}"
SSH_PANEL_2FA_FILE="${SSH_PANEL_2FA_FILE:-/opt/servermanager/panel/ssh-panel-2fa.json}"
BLOCK_FILE="${LAN_CIRCLE_BLOCK_FILE:-/opt/servermanager/panel/lan-circle-block.txt}"
OVPN_GW="${OVPN_FLINT_IP:-10.9.0.2}"
VPS_IP="${VPS_PUBLIC_IP:-74.208.76.213}"
CHAIN="${LAN_CIRCLE_IPT_CHAIN:-SM-LAN-CIRCLE}"
GUEST_DNS="${VPN_GUEST_DNS:-1.1.1.1}"
GUEST_DNS_CHAIN="${LAN_GUEST_DNS_IPT_CHAIN:-SM-LAN-GUEST-DNS}"

# shellcheck disable=SC1090
set -a
[ -f "$ENV_FILE" ] && . "$ENV_FILE"
set +a

# Re-read after env file (env may override defaults).
GUEST_DNS="${VPN_GUEST_DNS:-$GUEST_DNS}"
GUEST_DNS="${GUEST_DNS:-1.1.1.1}"

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

export ALLOWLIST_FILE AUTH_APP_DEVICES_FILE SSH_PANEL_2FA_FILE BLOCK_FILE VPS_IP GUEST_DNS
BLOCK_LIST="$(
  python3 - <<'PY'
import json
import os
import re
from pathlib import Path

allow = Path(os.environ.get("ALLOWLIST_FILE", "/opt/servermanager/panel/vpn-allowlist.json"))
auth_dev = Path(
    os.environ.get("AUTH_APP_DEVICES_FILE", "/opt/servermanager/panel/auth-app-devices.json")
)
ssh_2fa = Path(
    os.environ.get("SSH_PANEL_2FA_FILE", "/opt/servermanager/panel/ssh-panel-2fa.json")
)
block_file = Path(os.environ.get("BLOCK_FILE", "/opt/servermanager/panel/lan-circle-block.txt"))
vps = os.environ.get("VPS_IP", "74.208.76.213").strip() or "74.208.76.213"
guest_dns = os.environ.get("GUEST_DNS", "1.1.1.1").strip() or "1.1.1.1"


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

# Enrolled Authenticator phones keep portal + circle DNS while remaining pending.
enrolled: set[str] = set()
if auth_dev.is_file():
    try:
        loaded = json.loads(auth_dev.read_text(encoding="utf-8"))
        for row in (loaded.get("devices") or []) if isinstance(loaded, dict) else []:
            if not isinstance(row, dict):
                continue
            ip = norm(row.get("ip", ""))
            if is_home_lan(ip):
                enrolled.add(ip)
    except Exception:
        pass

# While new-device enrollment is unlocked, do not block pending LAN (phones must
# reach /auth-app to paste the secret). Denied IPs stay blocked.
# Honor device_enroll_unlocked_at + AUTH_APP_ENROLL_UNLOCK_SECONDS so an
# abandoned unlock cannot leave Flint open indefinitely.
enroll_unlocked = False
enroll_ttl = int(os.environ.get("AUTH_APP_ENROLL_UNLOCK_SECONDS", "900") or "900")
enroll_ttl = max(60, enroll_ttl)
if ssh_2fa.is_file():
    try:
        st = json.loads(ssh_2fa.read_text(encoding="utf-8"))
        if isinstance(st, dict) and st.get("device_enroll_unlocked"):
            unlocked_at = int(st.get("device_enroll_unlocked_at") or 0)
            import time as _time

            if unlocked_at > 0 and (_time.time() - unlocked_at) <= enroll_ttl:
                enroll_unlocked = True
            else:
                # Expired or legacy unlock without timestamp — relock on disk
                # so subsequent gate runs and portal reads stay consistent.
                st["device_enroll_unlocked"] = False
                st["device_enroll_unlocked_at"] = 0
                st["updated_at"] = int(_time.time())
                tmp = ssh_2fa.with_suffix(".tmp")
                tmp.write_text(json.dumps(st, indent=2) + "\n", encoding="utf-8")
                tmp.replace(ssh_2fa)
                try:
                    os.chmod(ssh_2fa, 0o600)
                except Exception:
                    pass
                enroll_unlocked = False
    except Exception:
        enroll_unlocked = False

# Circle membership is key-bound only — keyless "allowed" rows are not trusted.
allowed = {
    norm(r.get("ip", ""))
    for r in (data.get("allowed") or [])
    if isinstance(r, dict)
    and is_home_lan(norm(r.get("ip", "")))
    and str(r.get("pubkey") or "").strip()
}
# Keyless allowlist rows must still be blocked until demoted to pending.
keyless_allowed = {
    norm(r.get("ip", ""))
    for r in (data.get("allowed") or [])
    if isinstance(r, dict)
    and is_home_lan(norm(r.get("ip", "")))
    and not str(r.get("pubkey") or "").strip()
}
blocked: list[str] = []
seen = set()

# Denied LAN IPs are always blocked (unless later approved).
for row in data.get("denied") or []:
    if not isinstance(row, dict):
        continue
    ip = norm(row.get("ip", ""))
    if not is_home_lan(ip) or ip in allowed or ip in seen:
        continue
    seen.add(ip)
    blocked.append(ip)

# Keyless circle rows + pending LAN IPs are blocked unless an enrolled
# Authenticator owns that IP, or new-device enrollment is currently unlocked.
for ip in sorted(keyless_allowed):
    if ip in allowed or ip in seen:
        continue
    if ip in enrolled or enroll_unlocked:
        continue
    seen.add(ip)
    blocked.append(ip)

for row in data.get("pending") or []:
    if not isinstance(row, dict):
        continue
    ip = norm(row.get("ip", ""))
    if not is_home_lan(ip) or ip in allowed or ip in seen:
        continue
    if str(row.get("status") or "") == "denied":
        continue
    if ip in enrolled or enroll_unlocked:
        continue
    seen.add(ip)
    blocked.append(ip)

block_file.parent.mkdir(parents=True, exist_ok=True)
lines = [
    "# Managed by ensure-lan-circle-flint-gate.sh",
    f"# Reject these LAN sources to {vps}:80,443 on Flint (pre-NAT).",
    f"# Same set is forced to guest DNS {guest_dns} (no AdGuard admin rewrites).",
    f"# Enrolled Authenticators exempt: {', '.join(sorted(enrolled)) or '(none)'}",
    f"# enroll_unlocked={int(enroll_unlocked)}",
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

# Build remote script with embedded block list + VPS IP + guest DNS.
REMOTE_SCRIPT="$(
  BLOCK_LIST="$BLOCK_LIST" VPS_IP="$VPS_IP" CHAIN="$CHAIN" \
  GUEST_DNS="$GUEST_DNS" GUEST_DNS_CHAIN="$GUEST_DNS_CHAIN" python3 - <<'PY'
import os

vps = os.environ.get("VPS_IP", "74.208.76.213")
chain = os.environ.get("CHAIN", "SM-LAN-CIRCLE")
guest = os.environ.get("GUEST_DNS", "1.1.1.1").strip() or "1.1.1.1"
gd_chain = os.environ.get("GUEST_DNS_CHAIN", "SM-LAN-GUEST-DNS")
blocks = [b.strip() for b in (os.environ.get("BLOCK_LIST") or "").splitlines() if b.strip()]
print("set -e")
print(f'VPS="{vps}"')
print(f'CHAIN="{chain}"')
print(f'GUEST_DNS="{guest}"')
print(f'GD_CHAIN="{gd_chain}"')

# --- Portal HTTPS reject (filter) ---
print('iptables -t filter -N "$CHAIN" 2>/dev/null || iptables -t filter -F "$CHAIN"')
print("# Ensure jump exists near the top of forwarding (GL.iNet uses forwarding_rule)")
print("if iptables -t filter -L forwarding_rule -n >/dev/null 2>&1; then")
print('  iptables -t filter -C forwarding_rule -j "$CHAIN" 2>/dev/null || iptables -t filter -I forwarding_rule 1 -j "$CHAIN"')
print("else")
print('  iptables -t filter -C FORWARD -j "$CHAIN" 2>/dev/null || iptables -t filter -I FORWARD 1 -j "$CHAIN"')
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

# --- Guest DNS (nat): same blocked set → public resolver, skip AdGuard ---
print('iptables -t nat -N "$GD_CHAIN" 2>/dev/null || iptables -t nat -F "$GD_CHAIN"')
print('iptables -t nat -C PREROUTING -j "$GD_CHAIN" 2>/dev/null || iptables -t nat -I PREROUTING 1 -j "$GD_CHAIN"')
# Drop stale SM-LAN-GUEST-DNS helpers from dns_dispatcher / POSTROUTING / filter
print(
    r"""
# Clear prior per-IP helpers tagged SM-LAN-GUEST-DNS (idempotent rebuild).
_clear_comment() {
  table="$1"; chain="$2"; tag="$3"
  while true; do
    line="$(iptables -t "$table" -S "$chain" 2>/dev/null | grep -F "$tag" | head -1 || true)"
    [ -n "$line" ] || break
    # Convert -A/-I listing to -D delete
    del="$(echo "$line" | sed 's/^-A /-D /; s/^-I /-D /')"
    eval "iptables -t $table $del" 2>/dev/null || break
  done
}
if iptables -t nat -L dns_dispatcher -n >/dev/null 2>&1; then
  _clear_comment nat dns_dispatcher SM-LAN-GUEST-DNS
fi
_clear_comment nat POSTROUTING SM-LAN-GUEST-DNS
if iptables -t filter -L forwarding_rule -n >/dev/null 2>&1; then
  _clear_comment filter forwarding_rule SM-LAN-GUEST-DNS
else
  _clear_comment filter FORWARD SM-LAN-GUEST-DNS
fi
"""
)
for ip in blocks:
    # Skip Flint's AdGuard / dns_dispatcher force for this LAN client.
    print(
        "if iptables -t nat -L dns_dispatcher -n >/dev/null 2>&1; then\n"
        f'  iptables -t nat -C dns_dispatcher -s {ip}/32 -m comment '
        f'--comment SM-LAN-GUEST-DNS -j RETURN 2>/dev/null || '
        f'iptables -t nat -I dns_dispatcher 1 -s {ip}/32 -m comment '
        f'--comment SM-LAN-GUEST-DNS -j RETURN\n'
        "fi"
    )
    print(
        f'iptables -t nat -A "$GD_CHAIN" -s {ip}/32 -p udp --dport 53 '
        f'-m comment --comment SM-LAN-GUEST-DNS -j DNAT --to-destination "$GUEST_DNS":53'
    )
    print(
        f'iptables -t nat -A "$GD_CHAIN" -s {ip}/32 -p tcp --dport 53 '
        f'-m comment --comment SM-LAN-GUEST-DNS -j DNAT --to-destination "$GUEST_DNS":53'
    )
    print(
        f'iptables -t nat -C POSTROUTING -s {ip}/32 -d "$GUEST_DNS"/32 -p udp --dport 53 '
        f'-m comment --comment SM-LAN-GUEST-DNS -j MASQUERADE 2>/dev/null || '
        f'iptables -t nat -I POSTROUTING 1 -s {ip}/32 -d "$GUEST_DNS"/32 -p udp --dport 53 '
        f'-m comment --comment SM-LAN-GUEST-DNS -j MASQUERADE'
    )
    print(
        f'iptables -t nat -C POSTROUTING -s {ip}/32 -d "$GUEST_DNS"/32 -p tcp --dport 53 '
        f'-m comment --comment SM-LAN-GUEST-DNS -j MASQUERADE 2>/dev/null || '
        f'iptables -t nat -I POSTROUTING 1 -s {ip}/32 -d "$GUEST_DNS"/32 -p tcp --dport 53 '
        f'-m comment --comment SM-LAN-GUEST-DNS -j MASQUERADE'
    )
    print(
        "if iptables -t filter -L forwarding_rule -n >/dev/null 2>&1; then\n"
        f'  iptables -t filter -C forwarding_rule -s {ip}/32 -d "$GUEST_DNS"/32 -p udp --dport 53 '
        f'-m comment --comment SM-LAN-GUEST-DNS -j ACCEPT 2>/dev/null || '
        f'iptables -t filter -I forwarding_rule 1 -s {ip}/32 -d "$GUEST_DNS"/32 -p udp --dport 53 '
        f'-m comment --comment SM-LAN-GUEST-DNS -j ACCEPT\n'
        f'  iptables -t filter -C forwarding_rule -s {ip}/32 -d "$GUEST_DNS"/32 -p tcp --dport 53 '
        f'-m comment --comment SM-LAN-GUEST-DNS -j ACCEPT 2>/dev/null || '
        f'iptables -t filter -I forwarding_rule 1 -s {ip}/32 -d "$GUEST_DNS"/32 -p tcp --dport 53 '
        f'-m comment --comment SM-LAN-GUEST-DNS -j ACCEPT\n'
        "else\n"
        f'  iptables -t filter -C FORWARD -s {ip}/32 -d "$GUEST_DNS"/32 -p udp --dport 53 '
        f'-m comment --comment SM-LAN-GUEST-DNS -j ACCEPT 2>/dev/null || '
        f'iptables -t filter -I FORWARD 1 -s {ip}/32 -d "$GUEST_DNS"/32 -p udp --dport 53 '
        f'-m comment --comment SM-LAN-GUEST-DNS -j ACCEPT\n'
        f'  iptables -t filter -C FORWARD -s {ip}/32 -d "$GUEST_DNS"/32 -p tcp --dport 53 '
        f'-m comment --comment SM-LAN-GUEST-DNS -j ACCEPT 2>/dev/null || '
        f'iptables -t filter -I FORWARD 1 -s {ip}/32 -d "$GUEST_DNS"/32 -p tcp --dport 53 '
        f'-m comment --comment SM-LAN-GUEST-DNS -j ACCEPT\n'
        "fi"
    )

print(
    f'echo "lan-circle: blocked {len(blocks)} LAN IP(s) to {vps}:80,443; '
    f'guest DNS {guest} for same set"'
)
print('iptables -t filter -S "$CHAIN" | head -40')
print('iptables -t nat -S "$GD_CHAIN" | head -40')
PY
)"

echo "$REMOTE_SCRIPT" | sshpass -e ssh -o StrictHostKeyChecking=no \
  -o PreferredAuthentications=password -o PubkeyAuthentication=no \
  -o ConnectTimeout=8 "root@${FLINT_HOST}" sh -s

echo "lan-circle: applied via ${FLINT_HOST} ($(echo "$BLOCK_LIST" | grep -c . || true) blocked + guest DNS ${GUEST_DNS})"
