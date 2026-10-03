#!/usr/bin/env bash
# Cap public mail client ports (465 SMTPS, 587 submission, 993 IMAPS):
#   1) UFW "limit" instead of unlimited allow (default ~6 new conns / 30s / IP)
#   2) Per-IP concurrent connection caps via ufw-before-input connlimit rules
# Port 25 (SMTP receive) stays unlimited allow — remote MTAs need many parallels.
# Safe to re-run.
set -euo pipefail

MAIL_LIMIT_PORTS="${MAIL_LIMIT_PORTS:-465 587 993}"
# Concurrent TCP sessions per source IP (connlimit counts per /32).
MAIL_CONNLIMIT_465="${MAIL_CONNLIMIT_465:-12}"
MAIL_CONNLIMIT_587="${MAIL_CONNLIMIT_587:-12}"
MAIL_CONNLIMIT_993="${MAIL_CONNLIMIT_993:-20}"
BEFORE_RULES="${BEFORE_RULES:-/etc/ufw/before.rules}"
MARKER_BEGIN="# BEGIN sm-mail-port-cap"
MARKER_END="# END sm-mail-port-cap"

export MAIL_CONNLIMIT_465 MAIL_CONNLIMIT_587 MAIL_CONNLIMIT_993

if ! command -v ufw >/dev/null 2>&1; then
  echo "ufw not installed" >&2
  exit 1
fi
if [[ ! -f "$BEFORE_RULES" ]]; then
  echo "missing $BEFORE_RULES" >&2
  exit 1
fi

echo "mail client ports to rate-cap: ${MAIL_LIMIT_PORTS}"
echo "connlimits: 465=${MAIL_CONNLIMIT_465} 587=${MAIL_CONNLIMIT_587} 993=${MAIL_CONNLIMIT_993}"

# --- helpers: delete matching UFW numbered rules (highest first) ---
delete_ufw_matching() {
  local pattern="$1"
  local _
  for _ in $(seq 1 60); do
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

# Drop multiport bundle that opened 25+client ports together, and any
# unlimited allow / previous limit on the client ports (v4 + v6).
delete_ufw_matching '25,465,587,993'
for p in $MAIL_LIMIT_PORTS; do
  delete_ufw_matching "(^|[[:space:]])${p}/tcp"
done

# Ensure inbound SMTP receive (25) remains open without a rate cap.
if ! ufw status | grep -qE '(^|[[:space:]])25/tcp[[:space:]].*ALLOW[[:space:]].*Anywhere'; then
  ufw allow 25/tcp comment 'SMTP' >/dev/null || true
fi

# Rate-limit client/auth ports (smtps / submission / imaps).
for p in $MAIL_LIMIT_PORTS; do
  case "$p" in
    465) cmt="SMTPS-ratecap" ;;
    587) cmt="submission-ratecap" ;;
    993) cmt="IMAPS-ratecap" ;;
    *) cmt="mail-${p}-ratecap" ;;
  esac
  ufw limit "$p"/tcp comment "$cmt" >/dev/null || true
done

# --- concurrent connection caps in before.rules ---
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

python3 - "$BEFORE_RULES" "$tmp" "$MARKER_BEGIN" "$MARKER_END" $MAIL_LIMIT_PORTS <<'PY'
import os
import sys
from pathlib import Path

src = Path(sys.argv[1])
dst = Path(sys.argv[2])
begin, end = sys.argv[3], sys.argv[4]
ports = sys.argv[5:]
limits = {
    "465": os.environ.get("MAIL_CONNLIMIT_465", "12"),
    "587": os.environ.get("MAIL_CONNLIMIT_587", "12"),
    "993": os.environ.get("MAIL_CONNLIMIT_993", "20"),
}

text = src.read_text(encoding="utf-8")
while begin in text and end in text:
    a = text.index(begin)
    b = text.index(end, a) + len(end)
    if b < len(text) and text[b] == "\n":
        b += 1
    text = text[:a] + text[b:]

lines = [
    begin + " — managed by harden-mail-ports-rate-cap.sh; do not edit by hand",
]
for p in ports:
    n = limits.get(p, "10")
    lines.append(
        f"-A ufw-before-input -p tcp --dport {p} "
        f"-m connlimit --connlimit-above {n} --connlimit-mask 32 "
        f"-j REJECT --reject-with tcp-reset"
    )
lines.append(end)
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
print(f"before.rules: wrote connlimit block for ports {', '.join(ports)}")
PY

cp "$tmp" "$BEFORE_RULES"
chmod 640 "$BEFORE_RULES"

# Reload UFW so limit rules + before.rules take effect.
ufw reload >/dev/null

echo
echo "--- ufw (mail ports) ---"
ufw status numbered | grep -E '25/tcp|465/tcp|587/tcp|993/tcp|25,465' || true
echo
echo "--- connlimit in before.rules ---"
sed -n "/${MARKER_BEGIN}/,/${MARKER_END}/p" "$BEFORE_RULES"
echo
echo "mail ports rate-cap complete (465/587/993 limited; 25 still ALLOW)"
