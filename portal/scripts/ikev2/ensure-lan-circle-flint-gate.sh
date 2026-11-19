#!/usr/bin/env bash
# Home-LAN trust circle gate on Flint (pre-NAT):
#   1) REJECT only *denied* LAN sources to VPS :80,:443 AND portal VIP
#   2) Force pending/denied/keyless LAN IPs onto guest DNS (sm-guest-dns)
#      which NXDOMAINs portal/router/admin names (real browser DNS error page)
#      and does not apply AdGuard admin rewrites.
#
# Pending (not denied) may still reach plex.vpstruelord.com — Caddy keeps
# 192.168.8.0/24 on the plex site only; portal/admin stay /32-gated and are
# NXDOMAIN'd by guest DNS. Do not REJECT pending on :443 or Plex breaks.
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
PORTAL_VIP="${VPN_INTERNAL_IP:-10.11.0.1}"
CHAIN="${LAN_CIRCLE_IPT_CHAIN:-SM-LAN-CIRCLE}"
GUEST_DNS="${VPN_GUEST_DNS:-10.42.42.45}"
GUEST_DNS_CHAIN="${LAN_GUEST_DNS_IPT_CHAIN:-SM-LAN-GUEST-DNS}"

# shellcheck disable=SC1090
set -a
[ -f "$ENV_FILE" ] && . "$ENV_FILE"
set +a

# Re-read after env file (env may override defaults).
GUEST_DNS="${VPN_GUEST_DNS:-$GUEST_DNS}"
GUEST_DNS="${GUEST_DNS:-10.42.42.45}"

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
guest_dns = os.environ.get("GUEST_DNS", "10.42.42.45").strip() or "10.42.42.45"


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
# REJECT on :80/:443 — denied only (pending must reach plex.vpstruelord.com).
reject_ips: list[str] = []
reject_seen: set[str] = set()
# Guest DNS — pending + keyless + denied (NXDOMAIN portal/admin names).
guest_ips: list[str] = []
guest_seen: set[str] = set()

# Denied LAN IPs: reject HTTPS + guest DNS (unless later approved).
for row in data.get("denied") or []:
    if not isinstance(row, dict):
        continue
    ip = norm(row.get("ip", ""))
    if not is_home_lan(ip) or ip in allowed:
        continue
    if ip not in reject_seen:
        reject_seen.add(ip)
        reject_ips.append(ip)
    if ip not in guest_seen:
        guest_seen.add(ip)
        guest_ips.append(ip)

# Keyless circle rows + pending LAN IPs → guest DNS only (not REJECT),
# unless an enrolled Authenticator owns that IP or enroll is unlocked.
for ip in sorted(keyless_allowed):
    if ip in allowed or ip in guest_seen:
        continue
    if ip in enrolled or enroll_unlocked:
        continue
    guest_seen.add(ip)
    guest_ips.append(ip)

for row in data.get("pending") or []:
    if not isinstance(row, dict):
        continue
    ip = norm(row.get("ip", ""))
    if not is_home_lan(ip) or ip in allowed or ip in guest_seen:
        continue
    if str(row.get("status") or "") == "denied":
        continue
    if ip in enrolled or enroll_unlocked:
        continue
    guest_seen.add(ip)
    guest_ips.append(ip)

block_file.parent.mkdir(parents=True, exist_ok=True)
lines = [
    "# Managed by ensure-lan-circle-flint-gate.sh",
    f"# REJECT (denied only) to {vps}/VIP:80,443 — pending may use Plex.",
    f"# Guest DNS {guest_dns} for pending+denied (no AdGuard admin rewrites).",
    f"# Enrolled Authenticators exempt: {', '.join(sorted(enrolled)) or '(none)'}",
    f"# enroll_unlocked={int(enroll_unlocked)}",
    "# reject IPv4s (one per line) follow 'REJECT:'; guest IPs follow 'GUEST:'",
    "REJECT:",
]
lines.extend(reject_ips)
lines.append("GUEST:")
lines.extend(guest_ips)
block_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
# stdout consumed by caller: first section reject, then guest (separated).
print("REJECT")
print("\n".join(reject_ips))
print("GUEST")
print("\n".join(guest_ips))
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
  BLOCK_LIST="$BLOCK_LIST" VPS_IP="$VPS_IP" PORTAL_VIP="$PORTAL_VIP" CHAIN="$CHAIN" \
  GUEST_DNS="$GUEST_DNS" GUEST_DNS_CHAIN="$GUEST_DNS_CHAIN" python3 - <<'PY'
import os
import re

vps = os.environ.get("VPS_IP", "74.208.76.213")
vip = os.environ.get("PORTAL_VIP", "10.11.0.1").strip() or "10.11.0.1"
chain = os.environ.get("CHAIN", "SM-LAN-CIRCLE")
guest = os.environ.get("GUEST_DNS", "10.42.42.45").strip() or "10.42.42.45"
gd_chain = os.environ.get("GUEST_DNS_CHAIN", "SM-LAN-GUEST-DNS")
raw = [b.strip() for b in (os.environ.get("BLOCK_LIST") or "").splitlines() if b.strip()]
reject_ips: list[str] = []
guest_ips: list[str] = []
section = "guest"  # legacy flat lists → guest DNS (+ no reject unless marked)
if raw and raw[0] in {"REJECT", "GUEST"}:
    section = "reject" if raw[0] == "REJECT" else "guest"
    for line in raw[1:]:
        if line == "REJECT":
            section = "reject"
            continue
        if line == "GUEST":
            section = "guest"
            continue
        if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", line):
            continue
        if section == "reject":
            reject_ips.append(line)
        else:
            guest_ips.append(line)
else:
    # Backward compat: flat IP list → guest DNS only (do not REJECT pending).
    guest_ips = [b for b in raw if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", b)]

print("set -e")
print(f'VPS="{vps}"')
print(f'VIP="{vip}"')
print(f'CHAIN="{chain}"')
print(f'GUEST_DNS="{guest}"')
print(f'GD_CHAIN="{gd_chain}"')

# --- HTTPS reject (filter): denied IPs only ---
# Pending stay off portal via guest DNS NXDOMAIN; they must reach Plex on :443.
print('iptables -t filter -N "$CHAIN" 2>/dev/null || iptables -t filter -F "$CHAIN"')
print(
    r"""
if iptables -t filter -L forwarding_rule -n >/dev/null 2>&1; then
  FWD=forwarding_rule
else
  FWD=FORWARD
fi
# Drop blanket LAN→VPS/VIP ACCEPTs that short-circuit the circle gate.
iptables -t filter -D "$FWD" -s 192.168.8.0/24 -d "$VPS"/32 -o ovpnclient1 -j ACCEPT 2>/dev/null || true
iptables -t filter -D "$FWD" -s 192.168.8.0/24 -d "$VIP"/32 -o ovpnclient1 -j ACCEPT 2>/dev/null || true
iptables -t filter -D "$FWD" -s 192.168.8.0/24 -d "$VPS"/32 -j ACCEPT 2>/dev/null || true
iptables -t filter -D "$FWD" -s 192.168.8.0/24 -d "$VIP"/32 -j ACCEPT 2>/dev/null || true
# Always put the circle jump first ( -C leaves a stale mid-chain jump in place).
while iptables -t filter -S "$FWD" 2>/dev/null | grep -q "$CHAIN"; do
  line="$(iptables -t filter -S "$FWD" | grep "$CHAIN" | head -1)"
  eval "iptables -t filter ${line/-A/-D}" 2>/dev/null || break
done
iptables -t filter -I "$FWD" 1 -j "$CHAIN"
"""
)
for ip in reject_ips:
    for dest_var in ("$VPS", "$VIP"):
        print(
            f'iptables -t filter -A "$CHAIN" -s {ip}/32 -d {dest_var}/32 -p tcp '
            f'-m multiport --dports 80,443 -j REJECT --reject-with tcp-reset'
        )
        print(
            f'iptables -t filter -A "$CHAIN" -s {ip}/32 -d {dest_var}/32 -p udp '
            f'-m multiport --dports 80,443 -j REJECT --reject-with icmp-port-unreachable'
        )

# --- Guest DNS: pending+denied → sm-guest-dns (.45), skip AdGuard ---
# GL.iNet VPN dns-mark puts LAN :53 into conntrack zone 0xa000; DNAT+MASQ to
# the OVPN VIP then never gets replies. Force CT zone 0 + mark 0x8000 (main)
# before DNAT so guest DNS answers return to the LAN client.
print(
    r"""
iptables -t nat -N "$GD_CHAIN" 2>/dev/null || iptables -t nat -F "$GD_CHAIN"
iptables -t mangle -N "$GD_CHAIN" 2>/dev/null || iptables -t mangle -F "$GD_CHAIN"
iptables -t raw -N "$GD_CHAIN" 2>/dev/null || iptables -t raw -F "$GD_CHAIN"
# Always place guest-DNS jumps first so CT zone/mark run before GL VPN dns-mark.
for _t in raw mangle nat; do
  while iptables -t "$_t" -C PREROUTING -j "$GD_CHAIN" 2>/dev/null; do
    iptables -t "$_t" -D PREROUTING -j "$GD_CHAIN" || break
  done
  iptables -t "$_t" -I PREROUTING 1 -j "$GD_CHAIN"
done
# Clear prior per-IP helpers tagged SM-LAN-GUEST-DNS (idempotent rebuild).
_clear_comment() {
  table="$1"; chain="$2"; tag="$3"
  while true; do
    line="$(iptables -t "$table" -S "$chain" 2>/dev/null | grep -F "$tag" | head -1 || true)"
    [ -n "$line" ] || break
    del="$(echo "$line" | sed 's/^-A /-D /; s/^-I /-D /')"
    eval "iptables -t $table $del" 2>/dev/null || break
  done
}
if iptables -t nat -L dns_dispatcher -n >/dev/null 2>&1; then
  _clear_comment nat dns_dispatcher SM-LAN-GUEST-DNS
fi
# Drop legacy MASQ that broke guest DNS replies via OVPN LOCAL/zone.
_clear_comment nat POSTROUTING SM-LAN-GUEST-DNS
if iptables -t filter -L forwarding_rule -n >/dev/null 2>&1; then
  _clear_comment filter forwarding_rule SM-LAN-GUEST-DNS
else
  _clear_comment filter FORWARD SM-LAN-GUEST-DNS
fi
# Host routes so mark 0x8000 (main table) still reaches VPS DNS VIPs.
ip route replace "$GUEST_DNS" via 10.9.0.1 dev ovpnclient1 metric 5 2>/dev/null || true
ip route replace 10.42.42.44 via 10.9.0.1 dev ovpnclient1 metric 5 2>/dev/null || true
conntrack -D -s 192.168.8.0/24 -p udp --dport 53 >/dev/null 2>&1 || true
"""
)
for ip in guest_ips:
    print(
        "if iptables -t nat -L dns_dispatcher -n >/dev/null 2>&1; then\n"
        f'  iptables -t nat -C dns_dispatcher -s {ip}/32 -m comment '
        f'--comment SM-LAN-GUEST-DNS -j RETURN 2>/dev/null || '
        f'iptables -t nat -I dns_dispatcher 1 -s {ip}/32 -m comment '
        f'--comment SM-LAN-GUEST-DNS -j RETURN\n'
        "fi"
    )
    # Escape VPN dns-mark zone before DNAT.
    print(
        f'iptables -t raw -A "$GD_CHAIN" -s {ip}/32 -p udp --dport 53 '
        f'-m comment --comment SM-LAN-GUEST-DNS -j CT --zone 0'
    )
    print(
        f'iptables -t raw -A "$GD_CHAIN" -s {ip}/32 -p tcp --dport 53 '
        f'-m comment --comment SM-LAN-GUEST-DNS -j CT --zone 0'
    )
    print(
        f'iptables -t mangle -A "$GD_CHAIN" -s {ip}/32 -p udp --dport 53 '
        f'-m comment --comment SM-LAN-GUEST-DNS -j MARK --set-xmark 0x8000/0xf000'
    )
    print(
        f'iptables -t mangle -A "$GD_CHAIN" -s {ip}/32 -p tcp --dport 53 '
        f'-m comment --comment SM-LAN-GUEST-DNS -j MARK --set-xmark 0x8000/0xf000'
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
    f'echo "lan-circle: reject {len(reject_ips)} denied to {vps}/VIP:80,443; '
    f'guest DNS {guest} for {len(guest_ips)} pending/denied"'
)
# Keep circle jump first after guest-DNS ACCEPTs were inserted at position 1.
print(
    r"""
if iptables -t filter -L forwarding_rule -n >/dev/null 2>&1; then FWD=forwarding_rule; else FWD=FORWARD; fi
while iptables -t filter -S "$FWD" 2>/dev/null | grep -q "$CHAIN"; do
  line="$(iptables -t filter -S "$FWD" | grep "$CHAIN" | head -1)"
  eval "iptables -t filter ${line/-A/-D}" 2>/dev/null || break
done
iptables -t filter -I "$FWD" 1 -j "$CHAIN"
"""
)
print('iptables -t filter -S "$CHAIN" | head -40')
print('iptables -t nat -S "$GD_CHAIN" | head -40')
PY
)"

echo "$REMOTE_SCRIPT" | sshpass -e ssh -o StrictHostKeyChecking=no \
  -o PreferredAuthentications=password -o PubkeyAuthentication=no \
  -o ConnectTimeout=8 "root@${FLINT_HOST}" sh -s

echo "lan-circle: applied via ${FLINT_HOST} (guest DNS ${GUEST_DNS}; pending may reach Plex)"
