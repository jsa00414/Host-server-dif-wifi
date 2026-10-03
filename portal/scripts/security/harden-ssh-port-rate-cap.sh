#!/usr/bin/env bash
# Cap public SSH (:22) without making it VPN-only (keeps break-glass / CI access):
#   1) UFW "limit" instead of unlimited allow (~6 new conns / 30s / IP)
#   2) Per-IP concurrent connection cap via ufw-before-input connlimit
#   3) Harden sshd: X11Forwarding no, MaxAuthTries 3, ClientAlive*
# Safe to re-run. Does NOT move SSH behind VPN (that can lock out cloud agents).
set -euo pipefail

SSH_PORT="${SSH_PORT:-22}"
SSH_CONNLIMIT="${SSH_CONNLIMIT:-8}"
BEFORE_RULES="${BEFORE_RULES:-/etc/ufw/before.rules}"
MARKER_BEGIN="# BEGIN sm-ssh-port-cap"
MARKER_END="# END sm-ssh-port-cap"
SSHD_DROPIN_DIR="${SSHD_DROPIN_DIR:-/etc/ssh/sshd_config.d}"
SSHD_DROPIN="${SSHD_DROPIN:-${SSHD_DROPIN_DIR}/10-servermanager-ssh-harden.conf}"

if ! command -v ufw >/dev/null 2>&1; then
  echo "ufw not installed" >&2
  exit 1
fi
if [[ ! -f "$BEFORE_RULES" ]]; then
  echo "missing $BEFORE_RULES" >&2
  exit 1
fi

echo "ssh port ${SSH_PORT}: UFW limit + connlimit=${SSH_CONNLIMIT}"

# --- delete matching UFW numbered rules (highest first) ---
delete_ufw_matching() {
  local pattern="$1"
  local _
  for _ in $(seq 1 40); do
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

# Drop unlimited allow / previous limit on SSH (v4 + v6). Match comment "# SSH"
# and bare 22/tcp rules, but not flint-fwd 2222.
delete_ufw_matching "(^|[[:space:]])${SSH_PORT}/tcp"

# Rate-limit new SSH connections per IP.
ufw limit "${SSH_PORT}"/tcp comment 'SSH-ratecap' >/dev/null || true

# --- concurrent connection cap ---
export SSH_PORT SSH_CONNLIMIT
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

python3 - "$BEFORE_RULES" "$tmp" "$MARKER_BEGIN" "$MARKER_END" <<'PY'
import os
import sys
from pathlib import Path

src, dst = Path(sys.argv[1]), Path(sys.argv[2])
begin, end = sys.argv[3], sys.argv[4]
port = os.environ.get("SSH_PORT", "22")
limit = os.environ.get("SSH_CONNLIMIT", "8")

text = src.read_text(encoding="utf-8")
while begin in text and end in text:
    a = text.index(begin)
    b = text.index(end, a) + len(end)
    if b < len(text) and text[b] == "\n":
        b += 1
    text = text[:a] + text[b:]

block = "\n".join(
    [
        begin + " — managed by harden-ssh-port-rate-cap.sh; do not edit by hand",
        (
            f"-A ufw-before-input -p tcp --dport {port} "
            f"-m connlimit --connlimit-above {limit} --connlimit-mask 32 "
            f"-j REJECT --reject-with tcp-reset"
        ),
        end,
        "",
    ]
)

needle = "# don't delete the 'COMMIT' line or these rules won't be processed"
if needle in text:
    text = text.replace(needle, block + needle, 1)
else:
    idx = text.rfind("COMMIT")
    if idx < 0:
        raise SystemExit("could not find COMMIT in before.rules")
    text = text[:idx] + block + text[idx:]

dst.write_text(text, encoding="utf-8")
print(f"before.rules: wrote SSH connlimit (>{limit}/IP on :{port})")
PY

cp "$tmp" "$BEFORE_RULES"
chmod 640 "$BEFORE_RULES"

# --- sshd harden drop-in (complement existing ServerManager login drop-in) ---
mkdir -p "$SSHD_DROPIN_DIR"
cat >"$SSHD_DROPIN" <<'EOF'
# Managed by harden-ssh-port-rate-cap.sh — do not edit by hand
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 20
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
chmod 644 "$SSHD_DROPIN"

if ! sshd -t 2>/dev/null; then
  echo "sshd config test failed — leaving drop-in in place but not reloading" >&2
  sshd -t || true
  exit 1
fi

# Reload firewall + sshd. Prefer reload over restart to keep this session.
ufw reload >/dev/null
systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true

echo
echo "--- ufw (ssh) ---"
ufw status numbered | grep -E "${SSH_PORT}/tcp|SSH" || true
echo
echo "--- connlimit ---"
sed -n "/${MARKER_BEGIN}/,/${MARKER_END}/p" "$BEFORE_RULES"
iptables -L ufw-before-input -n -v 2>/dev/null | grep "dpt:${SSH_PORT}" || true
echo
echo "--- sshd ---"
sshd -T 2>/dev/null | grep -iE 'x11forwarding|maxauthtries|logingracetime|clientalive|passwordauthentication|permitrootlogin' | sort
echo
echo "ssh :${SSH_PORT} rate-cap complete (still public; keys-only + fail2ban + UFW limit)"
echo "Note: full VPN-only SSH is stronger but can lock out cloud/CI — not enabled here."
