#!/usr/bin/env bash
# Cap public VPN listener ports (must stay world-reachable so clients can dial in):
#   UDP 500/4500  — IKEv2
#   UDP 5000      — WireGuard
#   UDP 443       — WireGuard school-friendly (NAT redirect → 5000)
#   TCP 8443      — OpenVPN
# Does NOT touch TCP/443 (HTTPS + sslh OpenVPN mux) — capped separately.
#
# Modes (VPN_RATE_CAP_MODE):
#   off    — plain ALLOW, no connlimit/hashlimit (default; was breaking real clients)
#   loose  — high connlimits, soft flood brakes
#   strict — original tight caps
set -euo pipefail

BEFORE_RULES="${BEFORE_RULES:-/etc/ufw/before.rules}"
MARKER_BEGIN="# BEGIN sm-vpn-port-cap"
MARKER_END="# END sm-vpn-port-cap"
MODE="${VPN_RATE_CAP_MODE:-off}"

# Concurrent sessions / conntrack entries per source IP (used by loose/strict)
VPN_CONNLIMIT_IKE="${VPN_CONNLIMIT_IKE:-}"
VPN_CONNLIMIT_WG="${VPN_CONNLIMIT_WG:-}"
VPN_CONNLIMIT_OVPN="${VPN_CONNLIMIT_OVPN:-}"
IKE_FLOOD_ABOVE="${IKE_FLOOD_ABOVE:-}"
IKE_FLOOD_BURST="${IKE_FLOOD_BURST:-}"
WG_FLOOD_ABOVE="${WG_FLOOD_ABOVE:-}"
WG_FLOOD_BURST="${WG_FLOOD_BURST:-}"
OVPN_FLOOD_ABOVE="${OVPN_FLOOD_ABOVE:-}"
OVPN_FLOOD_BURST="${OVPN_FLOOD_BURST:-}"

case "$MODE" in
  off|loose|strict) ;;
  *)
    echo "VPN_RATE_CAP_MODE must be off|loose|strict (got: $MODE)" >&2
    exit 1
    ;;
esac

if [[ "$MODE" == "strict" ]]; then
  VPN_CONNLIMIT_IKE="${VPN_CONNLIMIT_IKE:-20}"
  VPN_CONNLIMIT_WG="${VPN_CONNLIMIT_WG:-16}"
  VPN_CONNLIMIT_OVPN="${VPN_CONNLIMIT_OVPN:-10}"
  IKE_FLOOD_ABOVE="${IKE_FLOOD_ABOVE:-30/sec}"
  IKE_FLOOD_BURST="${IKE_FLOOD_BURST:-60}"
  WG_FLOOD_ABOVE="${WG_FLOOD_ABOVE:-40/sec}"
  WG_FLOOD_BURST="${WG_FLOOD_BURST:-80}"
  OVPN_FLOOD_ABOVE="${OVPN_FLOOD_ABOVE:-10/min}"
  OVPN_FLOOD_BURST="${OVPN_FLOOD_BURST:-15}"
elif [[ "$MODE" == "loose" ]]; then
  VPN_CONNLIMIT_IKE="${VPN_CONNLIMIT_IKE:-200}"
  VPN_CONNLIMIT_WG="${VPN_CONNLIMIT_WG:-200}"
  VPN_CONNLIMIT_OVPN="${VPN_CONNLIMIT_OVPN:-100}"
  IKE_FLOOD_ABOVE="${IKE_FLOOD_ABOVE:-200/sec}"
  IKE_FLOOD_BURST="${IKE_FLOOD_BURST:-400}"
  WG_FLOOD_ABOVE="${WG_FLOOD_ABOVE:-200/sec}"
  WG_FLOOD_BURST="${WG_FLOOD_BURST:-400}"
  OVPN_FLOOD_ABOVE="${OVPN_FLOOD_ABOVE:-60/min}"
  OVPN_FLOOD_BURST="${OVPN_FLOOD_BURST:-120}"
fi

export VPN_CONNLIMIT_IKE VPN_CONNLIMIT_WG VPN_CONNLIMIT_OVPN
export IKE_FLOOD_ABOVE IKE_FLOOD_BURST WG_FLOOD_ABOVE WG_FLOOD_BURST
export OVPN_FLOOD_ABOVE OVPN_FLOOD_BURST MODE

if ! command -v ufw >/dev/null 2>&1; then
  echo "ufw not installed" >&2
  exit 1
fi
if [[ ! -f "$BEFORE_RULES" ]]; then
  echo "missing $BEFORE_RULES" >&2
  exit 1
fi

echo "vpn ports rate-cap mode=${MODE} ike=${VPN_CONNLIMIT_IKE:-n/a} wg=${VPN_CONNLIMIT_WG:-n/a} ovpn=${VPN_CONNLIMIT_OVPN:-n/a}"

delete_ufw_matching() {
  local pattern="$1"
  local _
  for _ in $(seq 1 50); do
    local numbered num
    numbered="$(ufw status numbered 2>/dev/null || true)"
    num="$(
      printf '%s\n' "$numbered" | awk -v re="$pattern" '
        /^\[[[:space:]]*[0-9]+\]/ {
          line=$0
          if (line ~ re) {
            if (match(line, /\[[[:space:]]*[0-9]+\]/)) {
              n=substr(line, RSTART+1, RLENGTH-2)
              gsub(/[[:space:]]/, "", n)
              print n+0
            }
          }
        }' | sort -nr | head -1
    )"
    [[ -z "${num:-}" ]] && break
    ufw --force delete "$num" >/dev/null || true
  done
}

# Remove unlimited allow / prior limit rules for these VPN listeners (v4+v6).
# Avoid matching 443/tcp (HTTPS) — only 443/udp.
delete_ufw_matching '5000/udp'
delete_ufw_matching '443/udp'
delete_ufw_matching '(^|[[:space:]])500/udp'
delete_ufw_matching '4500/udp'
delete_ufw_matching '8443/tcp'

# Plain ALLOW for all VPN listeners. UFW "limit" on UDP/TCP VPN ports was
# dropping real mobile rekeys / OpenVPN reconnect storms.
ufw allow 500/udp comment 'IKEv2-IKE' >/dev/null || true
ufw allow 4500/udp comment 'IKEv2-NATT' >/dev/null || true
ufw allow 5000/udp comment 'WireGuard' >/dev/null || true
ufw allow 443/udp comment 'WG-udp443' >/dev/null || true
ufw allow 8443/tcp comment 'OpenVPN-tcp' >/dev/null || true

# --- optional concurrent / flood caps in before.rules ---
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

python3 - "$BEFORE_RULES" "$tmp" "$MARKER_BEGIN" "$MARKER_END" <<'PY'
import os
import sys
from pathlib import Path

src, dst = Path(sys.argv[1]), Path(sys.argv[2])
begin, end = sys.argv[3], sys.argv[4]
mode = os.environ.get("MODE", "off")

text = src.read_text(encoding="utf-8")
while begin in text and end in text:
    a = text.index(begin)
    b = text.index(end, a) + len(end)
    if b < len(text) and text[b] == "\n":
        b += 1
    text = text[:a] + text[b:]

if mode == "off":
    dst.write_text(text, encoding="utf-8")
    print("before.rules: removed VPN connlimit/hashlimit block (mode=off)")
else:
    ike = os.environ["VPN_CONNLIMIT_IKE"]
    wg = os.environ["VPN_CONNLIMIT_WG"]
    ovpn = os.environ["VPN_CONNLIMIT_OVPN"]
    lines = [
        begin + f" — managed by harden-vpn-ports-rate-cap.sh mode={mode}; do not edit by hand",
        (
            f"-A ufw-before-input -p udp --dport 500 "
            f"-m connlimit --connlimit-above {ike} --connlimit-mask 32 "
            f"-j REJECT"
        ),
        (
            f"-A ufw-before-input -p udp --dport 4500 "
            f"-m connlimit --connlimit-above {ike} --connlimit-mask 32 "
            f"-j REJECT"
        ),
        (
            f"-A ufw-before-input -p udp --dport 5000 "
            f"-m connlimit --connlimit-above {wg} --connlimit-mask 32 "
            f"-j REJECT"
        ),
        (
            f"-A ufw-before-input -p udp --dport 443 "
            f"-m connlimit --connlimit-above {wg} --connlimit-mask 32 "
            f"-j REJECT"
        ),
        (
            f"-A ufw-before-input -p tcp --dport 8443 "
            f"-m connlimit --connlimit-above {ovpn} --connlimit-mask 32 "
            f"-j REJECT --reject-with tcp-reset"
        ),
        (
            "-A ufw-before-input -p udp -m multiport --dports 500,4500 "
            "-m hashlimit --hashlimit-name sm-ike-flood "
            f"--hashlimit-above {os.environ['IKE_FLOOD_ABOVE']} "
            f"--hashlimit-burst {os.environ['IKE_FLOOD_BURST']} "
            "--hashlimit-mode srcip --hashlimit-htable-expire 60000 -j REJECT"
        ),
        (
            "-A ufw-before-input -p udp -m multiport --dports 5000,443 "
            "-m hashlimit --hashlimit-name sm-wg-flood "
            f"--hashlimit-above {os.environ['WG_FLOOD_ABOVE']} "
            f"--hashlimit-burst {os.environ['WG_FLOOD_BURST']} "
            "--hashlimit-mode srcip --hashlimit-htable-expire 60000 -j REJECT"
        ),
        (
            "-A ufw-before-input -p tcp --dport 8443 -m state --state NEW "
            "-m hashlimit --hashlimit-name sm-ovpn-flood "
            f"--hashlimit-above {os.environ['OVPN_FLOOD_ABOVE']} "
            f"--hashlimit-burst {os.environ['OVPN_FLOOD_BURST']} "
            "--hashlimit-mode srcip --hashlimit-htable-expire 120000 "
            "-j REJECT --reject-with tcp-reset"
        ),
        end,
    ]
    block = "\n".join(lines) + "\n"
    needle = "# don't delete the 'COMMIT' line or these rules won't be processed"
    if needle in text:
        text = text.replace(needle, block + "\n" + needle, 1)
    else:
        idx = text.rfind("COMMIT")
        if idx < 0:
            raise SystemExit("could not find COMMIT in before.rules")
        text = text[:idx] + block + "\n" + text[idx:]
    dst.write_text(text, encoding="utf-8")
    print(f"before.rules: wrote VPN connlimit + hashlimit block (mode={mode})")
PY

cp "$tmp" "$BEFORE_RULES"
chmod 640 "$BEFORE_RULES"
ufw reload >/dev/null

echo
echo "--- ufw (vpn ports) ---"
ufw status numbered | grep -E '500/udp|4500/udp|5000/udp|443/udp|8443/tcp' || true
echo
echo "--- before.rules block ---"
if grep -q "$MARKER_BEGIN" "$BEFORE_RULES"; then
  sed -n "/${MARKER_BEGIN}/,/${MARKER_END}/p" "$BEFORE_RULES"
else
  echo "(none — caps off)"
fi
echo
iptables -L ufw-before-input -n 2>/dev/null | grep -E 'dpt:(500|4500|5000|443|8443)|sm-ike|sm-wg|sm-ovpn' || echo "(no vpn connlimit/hashlimit in live filter)"
echo
echo "vpn ports rate-cap complete (mode=${MODE}; still public for client dial-in)"
