#!/usr/bin/env bash
# Cap concurrent connections on public HTTP/HTTPS (80/443).
# Do NOT use UFW "limit" here — it is too aggressive for browsers / ACME.
# Safe to re-run.
set -euo pipefail

HTTP_CONNLIMIT="${HTTP_CONNLIMIT:-80}"
HTTPS_CONNLIMIT="${HTTPS_CONNLIMIT:-80}"
BEFORE_RULES="${BEFORE_RULES:-/etc/ufw/before.rules}"
MARKER_BEGIN="# BEGIN sm-http-port-cap"
MARKER_END="# END sm-http-port-cap"

if [[ ! -f "$BEFORE_RULES" ]]; then
  echo "missing $BEFORE_RULES" >&2
  exit 1
fi

echo "http/https connlimits: 80=${HTTP_CONNLIMIT} 443=${HTTPS_CONNLIMIT}"

export HTTP_CONNLIMIT HTTPS_CONNLIMIT
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

python3 - "$BEFORE_RULES" "$tmp" "$MARKER_BEGIN" "$MARKER_END" <<'PY'
import os
import sys
from pathlib import Path

src, dst = Path(sys.argv[1]), Path(sys.argv[2])
begin, end = sys.argv[3], sys.argv[4]
http_n = os.environ.get("HTTP_CONNLIMIT", "80")
https_n = os.environ.get("HTTPS_CONNLIMIT", "80")

text = src.read_text(encoding="utf-8")
while begin in text and end in text:
    a = text.index(begin)
    b = text.index(end, a) + len(end)
    if b < len(text) and text[b] == "\n":
        b += 1
    text = text[:a] + text[b:]

block = "\n".join(
    [
        begin + " — managed by harden-http-ports-conn-cap.sh; do not edit by hand",
        (
            f"-A ufw-before-input -p tcp --dport 80 "
            f"-m connlimit --connlimit-above {http_n} --connlimit-mask 32 "
            f"-j REJECT --reject-with tcp-reset"
        ),
        (
            f"-A ufw-before-input -p tcp --dport 443 "
            f"-m connlimit --connlimit-above {https_n} --connlimit-mask 32 "
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
print("before.rules: wrote http/https connlimit block")
PY

cp "$tmp" "$BEFORE_RULES"
chmod 640 "$BEFORE_RULES"

if command -v ufw >/dev/null 2>&1; then
  ufw reload >/dev/null
fi

echo
sed -n "/${MARKER_BEGIN}/,/${MARKER_END}/p" "$BEFORE_RULES"
iptables -L ufw-before-input -n -v 2>/dev/null | grep -E 'dpt:(80|443)' || true
echo "http/https conn-cap complete"
