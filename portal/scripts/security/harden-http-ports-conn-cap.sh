#!/usr/bin/env bash
# Cap concurrent connections on public HTTP/HTTPS (80/443).
# Do NOT use UFW "limit" here — it is too aggressive for browsers / ACME.
#
# Modes (HTTP_RATE_CAP_MODE):
#   off    — no connlimit (default; 443 is shared by Caddy + sslh OpenVPN)
#   loose  — high per-IP concurrent caps
#   strict — original 80/80 caps
set -euo pipefail

HTTP_RATE_CAP_MODE="${HTTP_RATE_CAP_MODE:-off}"
HTTP_CONNLIMIT="${HTTP_CONNLIMIT:-}"
HTTPS_CONNLIMIT="${HTTPS_CONNLIMIT:-}"
BEFORE_RULES="${BEFORE_RULES:-/etc/ufw/before.rules}"
MARKER_BEGIN="# BEGIN sm-http-port-cap"
MARKER_END="# END sm-http-port-cap"

case "$HTTP_RATE_CAP_MODE" in
  off|loose|strict) ;;
  *)
    echo "HTTP_RATE_CAP_MODE must be off|loose|strict (got: $HTTP_RATE_CAP_MODE)" >&2
    exit 1
    ;;
esac

if [[ "$HTTP_RATE_CAP_MODE" == "strict" ]]; then
  HTTP_CONNLIMIT="${HTTP_CONNLIMIT:-80}"
  HTTPS_CONNLIMIT="${HTTPS_CONNLIMIT:-80}"
elif [[ "$HTTP_RATE_CAP_MODE" == "loose" ]]; then
  HTTP_CONNLIMIT="${HTTP_CONNLIMIT:-500}"
  HTTPS_CONNLIMIT="${HTTPS_CONNLIMIT:-500}"
fi

if [[ ! -f "$BEFORE_RULES" ]]; then
  echo "missing $BEFORE_RULES" >&2
  exit 1
fi

echo "http/https conn-cap mode=${HTTP_RATE_CAP_MODE} 80=${HTTP_CONNLIMIT:-n/a} 443=${HTTPS_CONNLIMIT:-n/a}"

export HTTP_CONNLIMIT HTTPS_CONNLIMIT HTTP_RATE_CAP_MODE
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

python3 - "$BEFORE_RULES" "$tmp" "$MARKER_BEGIN" "$MARKER_END" <<'PY'
import os
import sys
from pathlib import Path

src, dst = Path(sys.argv[1]), Path(sys.argv[2])
begin, end = sys.argv[3], sys.argv[4]
mode = os.environ.get("HTTP_RATE_CAP_MODE", "off")

text = src.read_text(encoding="utf-8")
while begin in text and end in text:
    a = text.index(begin)
    b = text.index(end, a) + len(end)
    if b < len(text) and text[b] == "\n":
        b += 1
    text = text[:a] + text[b:]

if mode == "off":
    dst.write_text(text, encoding="utf-8")
    print("before.rules: removed http/https connlimit block (mode=off)")
else:
    http_n = os.environ["HTTP_CONNLIMIT"]
    https_n = os.environ["HTTPS_CONNLIMIT"]
    block = "\n".join(
        [
            begin + f" — managed by harden-http-ports-conn-cap.sh mode={mode}; do not edit by hand",
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
    print(f"before.rules: wrote http/https connlimit block (mode={mode})")
PY

cp "$tmp" "$BEFORE_RULES"
chmod 640 "$BEFORE_RULES"

if command -v ufw >/dev/null 2>&1; then
  ufw reload >/dev/null
fi

echo
if grep -q "$MARKER_BEGIN" "$BEFORE_RULES"; then
  sed -n "/${MARKER_BEGIN}/,/${MARKER_END}/p" "$BEFORE_RULES"
else
  echo "(none — http/https caps off)"
fi
iptables -L ufw-before-input -n -v 2>/dev/null | grep -E 'dpt:(80|443).*conn' || echo "(no http/https connlimit in live filter)"
echo "http/https conn-cap complete (mode=${HTTP_RATE_CAP_MODE})"
