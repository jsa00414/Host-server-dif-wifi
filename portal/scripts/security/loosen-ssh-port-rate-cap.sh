#!/usr/bin/env bash
# Remove SSH :22 UFW "limit" rate-cap and before.rules connlimit.
# Keeps :22 publicly allowed (break-glass / cloud agents). Safe to re-run.
# Does NOT change sshd auth settings or fail2ban.
set -euo pipefail

SSH_PORT="${SSH_PORT:-22}"
BEFORE_RULES="${BEFORE_RULES:-/etc/ufw/before.rules}"
MARKER_BEGIN="# BEGIN sm-ssh-port-cap"
MARKER_END="# END sm-ssh-port-cap"

if ! command -v ufw >/dev/null 2>&1; then
  echo "ufw not installed" >&2
  exit 1
fi

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

echo "ssh port ${SSH_PORT}: removing UFW limit + connlimit; allowing unlimited"

# Drop limit/allow rules for :22 only (not flint-fwd 2222).
delete_ufw_matching "(^|[[:space:]])${SSH_PORT}/tcp"

ufw allow "${SSH_PORT}"/tcp comment 'SSH' >/dev/null || true

if [[ -f "$BEFORE_RULES" ]] && grep -q "$MARKER_BEGIN" "$BEFORE_RULES"; then
  python3 - "$BEFORE_RULES" "$MARKER_BEGIN" "$MARKER_END" <<'PY'
import sys
from pathlib import Path
src = Path(sys.argv[1])
begin, end = sys.argv[2], sys.argv[3]
text = src.read_text(encoding="utf-8")
while begin in text and end in text:
    a = text.index(begin)
    b = text.index(end, a) + len(end)
    if b < len(text) and text[b] == "\n":
        b += 1
    # also drop leading newline if present
    if a > 0 and text[a - 1] == "\n":
        a -= 1
    text = text[:a] + text[b:]
src.write_text(text, encoding="utf-8")
print(f"before.rules: removed {begin} … {end}")
PY
fi

ufw reload >/dev/null

echo
echo "--- ufw (ssh) ---"
ufw status numbered | grep -E "${SSH_PORT}/tcp|SSH" || true
echo
echo "--- before.rules ssh cap ---"
if grep -q "$MARKER_BEGIN" "$BEFORE_RULES" 2>/dev/null; then
  sed -n "/${MARKER_BEGIN}/,/${MARKER_END}/p" "$BEFORE_RULES"
else
  echo "(no sm-ssh-port-cap block)"
fi
iptables -L ufw-user-input -n 2>/dev/null | grep "dpt:${SSH_PORT}" || true
iptables -L ufw-before-input -n 2>/dev/null | grep "dpt:${SSH_PORT}" || echo "(no :${SSH_PORT} connlimit in ufw-before-input)"
echo
echo "ssh :${SSH_PORT} rate-cap removed (plain ALLOW; fail2ban unchanged)"
