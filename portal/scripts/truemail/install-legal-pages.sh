#!/usr/bin/env bash
# Publish Truemailor Privacy + Terms pages for Twilio A2P 10DLC.
#
# Prefer remove-traceface.sh (replaces TraceFace on truemailor.com and
# publishes legal pages). This script remains as a legal-pages-only helper.
#
#   sudo bash portal/scripts/truemail/install-legal-pages.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
if [[ "${TRUEMAIL_REMOVE_TRACEFACE:-1}" == "1" && -x "$ROOT/scripts/truemail/remove-traceface.sh" ]]; then
  exec bash "$ROOT/scripts/truemail/remove-traceface.sh"
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CADDYFILE="${CADDYFILE:-/opt/truemail/Caddyfile}"
LEGAL_DIR="${LEGAL_DIR:-/opt/truemail/www/legal}"
SRC_PRIVACY="${ROOT}/static/privacy.html"
SRC_TERMS="${ROOT}/static/terms.html"

if [[ ! -f "$SRC_PRIVACY" || ! -f "$SRC_TERMS" ]]; then
  echo "Missing privacy/terms HTML under ${ROOT}/static/" >&2
  exit 1
fi

mkdir -p "$LEGAL_DIR"
install -m 0644 "$SRC_PRIVACY" "$LEGAL_DIR/privacy.html"
install -m 0644 "$SRC_TERMS" "$LEGAL_DIR/terms.html"
# Short paths without .html for campaign forms that prefer /privacy
ln -sfn privacy.html "$LEGAL_DIR/privacy"
ln -sfn terms.html "$LEGAL_DIR/terms"
echo "Installed legal pages in ${LEGAL_DIR}"

# Also drop into common static roots so SPA try_files can serve real files.
for webroot in \
  /opt/truemail/www \
  /opt/truemail/public \
  /var/www/truemailor \
  /opt/traceface/dist \
  /opt/traceface/public
 do
  if [[ -d "$webroot" ]]; then
    install -m 0644 "$SRC_PRIVACY" "$webroot/privacy.html"
    install -m 0644 "$SRC_TERMS" "$webroot/terms.html"
    echo "Copied into ${webroot}"
  fi
done

if [[ ! -f "$CADDYFILE" ]]; then
  echo "No Caddyfile at ${CADDYFILE}; files installed only." >&2
  exit 0
fi

export CADDYFILE LEGAL_DIR
python3 - <<'PY'
from pathlib import Path
import os
import re

caddy = Path(os.environ.get("CADDYFILE", "/opt/truemail/Caddyfile"))
legal = os.environ.get("LEGAL_DIR", "/opt/truemail/www/legal")
text = caddy.read_text(encoding="utf-8", errors="replace")
marker = "# BEGIN truemailor-legal-pages"
end = "# END truemailor-legal-pages"
snippet = f"""{marker}
# Public A2P legal pages (Twilio campaign Privacy / Terms URLs)
(truemailor_legal_pages) {{
\thandle /privacy.html {{
\t\troot * {legal}
\t\tfile_server
\t}}
\thandle /terms.html {{
\t\troot * {legal}
\t\tfile_server
\t}}
\thandle /privacy {{
\t\trewrite * /privacy.html
\t\troot * {legal}
\t\tfile_server
\t}}
\thandle /terms {{
\t\trewrite * /terms.html
\t\troot * {legal}
\t\tfile_server
\t}}
}}
{end}
"""

if marker in text:
    text = re.sub(
        re.escape(marker) + r".*?" + re.escape(end),
        snippet.strip(),
        text,
        count=1,
        flags=re.S,
    )
else:
    text = snippet + "\n" + text

def ensure_import(block_name: str, host: str, body: str) -> str:
    # Insert `import truemailor_legal_pages` as first line inside host block.
    pattern = re.compile(
        rf"(?m)^({re.escape(host)}\s*\{{)\n",
    )
    if not pattern.search(body):
        return body
    # Already imported?
    host_pat = re.compile(
        rf"(?ms)^({re.escape(host)}\s*\{{)(.*?)(^\}})",
    )
    m = host_pat.search(body)
    if not m:
        return body
    inner = m.group(2)
    if "import truemailor_legal_pages" in inner:
        return body
    new_inner = "\timport truemailor_legal_pages\n" + inner
    return body[: m.start()] + m.group(1) + new_inner + m.group(3) + body[m.end() :]

for host in ("mail.truemailor.com", "truemailor.com", "www.truemailor.com"):
    text = ensure_import("truemailor_legal_pages", host, text)

caddy.write_text(text, encoding="utf-8")
print(f"Updated {caddy}")
PY

# Validate + reload caddy if container exists
if command -v docker >/dev/null 2>&1; then
  for c in truemail-caddy-1 caddy; do
    if docker ps --format '{{.Names}}' | grep -qx "$c"; then
      docker exec "$c" caddy validate --config /etc/caddy/Caddyfile
      docker exec "$c" caddy reload --config /etc/caddy/Caddyfile \
        || docker kill -s HUP "$c" || true
      echo "Reloaded ${c}"
      break
    fi
  done
fi

echo
echo "Use these URLs in the Twilio A2P campaign:"
echo "  Privacy Policy: https://mail.truemailor.com/privacy.html"
echo "  Terms:          https://mail.truemailor.com/terms.html"
