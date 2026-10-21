#!/usr/bin/env bash
# Remove TraceFace from truemailor.com and publish the Truemailor public site
# (landing + Privacy/Terms for Twilio A2P).
#
#   sudo bash portal/scripts/truemail/remove-traceface.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CADDYFILE="${CADDYFILE:-/opt/truemail/Caddyfile}"
SITE_DIR="${SITE_DIR:-/opt/truemail/www/site}"
LEGAL_DIR="${LEGAL_DIR:-/opt/truemail/www/legal}"
SRC_SITE="${ROOT}/static/truemailor"
SRC_PRIVACY="${ROOT}/static/privacy.html"
SRC_TERMS="${ROOT}/static/terms.html"
BACKUP_ROOT="${BACKUP_ROOT:-/opt/truemail/backups/traceface-$(date +%Y%m%d%H%M%S)}"

if [[ ! -f "${SRC_SITE}/index.html" ]]; then
  echo "Missing Truemailor site at ${SRC_SITE}/index.html" >&2
  exit 1
fi
if [[ ! -f "$SRC_PRIVACY" || ! -f "$SRC_TERMS" ]]; then
  echo "Missing privacy/terms HTML under ${ROOT}/static/" >&2
  exit 1
fi

echo "Publishing Truemailor site → ${SITE_DIR}"
mkdir -p "$SITE_DIR" "$LEGAL_DIR" "$BACKUP_ROOT"

install -m 0644 "${SRC_SITE}/index.html" "$SITE_DIR/index.html"
install -m 0644 "$SRC_PRIVACY" "$SITE_DIR/privacy.html"
install -m 0644 "$SRC_TERMS" "$SITE_DIR/terms.html"
install -m 0644 "$SRC_PRIVACY" "$LEGAL_DIR/privacy.html"
install -m 0644 "$SRC_TERMS" "$LEGAL_DIR/terms.html"
# Pretty paths
ln -sfn privacy.html "$SITE_DIR/privacy"
ln -sfn terms.html "$SITE_DIR/terms"
ln -sfn privacy.html "$LEGAL_DIR/privacy"
ln -sfn terms.html "$LEGAL_DIR/terms"

# Discover and neutralize TraceFace static roots.
mapfile -t TRACE_ROOTS < <(
  python3 - <<'PY'
from pathlib import Path
candidates = [
    Path("/opt/traceface/dist"),
    Path("/opt/traceface/public"),
    Path("/opt/traceface/www"),
    Path("/var/www/truemailor"),
    Path("/var/www/traceface"),
    Path("/opt/truemail/www"),
    Path("/opt/truemail/public"),
    Path("/opt/truemail/traceface"),
]
found = []
for root in candidates:
    if not root.is_dir():
        continue
    for name in ("index.html", "index.htm"):
        p = root / name
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "TraceFace" in text or "Trace<span>Face" in text or "traceface" in text.lower():
            found.append(str(root))
            break
print("\n".join(dict.fromkeys(found)))
PY
)

for root in "${TRACE_ROOTS[@]:-}"; do
  [[ -z "${root:-}" ]] && continue
  echo "Backing up TraceFace root: ${root} → ${BACKUP_ROOT}/"
  mkdir -p "$BACKUP_ROOT"
  base="$(basename "$root")"
  # Avoid copying our new site dir into itself.
  if [[ "$(realpath -m "$root")" == "$(realpath -m "$SITE_DIR")" ]]; then
    echo "  skip (same as SITE_DIR)"
    continue
  fi
  if [[ "$(realpath -m "$root")" == "$(realpath -m "$LEGAL_DIR")" ]]; then
    echo "  skip (same as LEGAL_DIR)"
    continue
  fi
  cp -a "$root" "$BACKUP_ROOT/${base}"
  # Replace TraceFace index and remove app assets so SPA cannot resurrect.
  for f in index.html index.htm app.js styles.css main.js bundle.js; do
    if [[ -e "$root/$f" ]]; then
      rm -f "$root/$f"
      echo "  removed ${root}/${f}"
    fi
  done
  # Drop Truemailor pages into old webroots that Caddy may still point at.
  install -m 0644 "${SRC_SITE}/index.html" "$root/index.html"
  install -m 0644 "$SRC_PRIVACY" "$root/privacy.html"
  install -m 0644 "$SRC_TERMS" "$root/terms.html"
  echo "  replaced with Truemailor pages"
done

# Stop/remove TraceFace containers if present.
if command -v docker >/dev/null 2>&1; then
  while read -r name; do
    [[ -z "$name" ]] && continue
    echo "Stopping container ${name}"
    docker stop "$name" >/dev/null 2>&1 || true
    docker rm "$name" >/dev/null 2>&1 || true
  done < <(docker ps -a --format '{{.Names}}' | grep -Ei 'traceface|trace-face' || true)
fi

# Point truemailor.com / www at the new site directory in Caddy.
if [[ -f "$CADDYFILE" ]]; then
  export CADDYFILE SITE_DIR LEGAL_DIR
  python3 - <<'PY'
from pathlib import Path
import os
import re

caddy = Path(os.environ["CADDYFILE"])
site = os.environ["SITE_DIR"]
legal = os.environ["LEGAL_DIR"]
text = caddy.read_text(encoding="utf-8", errors="replace")

marker = "# BEGIN truemailor-public-site"
end = "# END truemailor-public-site"
snippet = f"""{marker}
# Truemailor public site (replaces TraceFace) + A2P legal pages
(truemailor_public_site) {{
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
\thandle {{
\t\troot * {site}
\t\ttry_files {{path}} /index.html
\t\tfile_server
\t}}
}}
{end}
"""

# Drop old legal-only snippet if present (superseded).
old_marker = "# BEGIN truemailor-legal-pages"
old_end = "# END truemailor-legal-pages"
if old_marker in text:
    text = re.sub(
        re.escape(old_marker) + r".*?" + re.escape(old_end) + r"\n?",
        "",
        text,
        count=1,
        flags=re.S,
    )

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

# Remove TraceFace reverse_proxy / root lines that mention traceface.
text = re.sub(r"(?mi)^[ \t]*#.*traceface.*\n", "", text)
text = re.sub(r"(?mi)^[ \t]*reverse_proxy[^\n]*traceface[^\n]*\n", "", text)
text = re.sub(r"(?mi)^[ \t]*root[ \t]+\*[ \t]+/opt/traceface[^\n]*\n", "", text)

def rewrite_host_block(body: str, host: str) -> str:
    host_pat = re.compile(rf"(?ms)^({re.escape(host)}\s*\{{)(.*?)(^\}})")
    m = host_pat.search(body)
    if not m:
        # Create a minimal host block if missing.
        addition = (
            f"\n{host} {{\n"
            f"\timport truemailor_public_site\n"
            f"}}\n"
        )
        return body + addition
    inner = m.group(2)
    # Strip prior TraceFace / file_server SPA config; keep TLS / header lines.
    keep_lines = []
    for line in inner.splitlines(True):
        low = line.lower()
        if "import truemailor_public_site" in low or "import truemailor_legal_pages" in low:
            continue
        if "traceface" in low:
            continue
        if re.search(r"^\s*root\s+\*", line):
            continue
        if re.search(r"^\s*try_files\b", line):
            continue
        if re.search(r"^\s*file_server\b", line):
            continue
        if re.search(r"^\s*handle\b", line) and ("privacy" in low or "terms" in low):
            # old legal handles removed; snippet provides them
            continue
        keep_lines.append(line)
    new_inner = "\timport truemailor_public_site\n" + "".join(keep_lines)
    # Avoid double blank noise
    new_inner = re.sub(r"\n{3,}", "\n\n", new_inner)
    return body[: m.start()] + m.group(1) + "\n" + new_inner + m.group(3) + body[m.end() :]

for host in ("truemailor.com", "www.truemailor.com"):
    text = rewrite_host_block(text, host)

# Ensure mail host still gets legal pages (not full site replace of webmail).
mail_pat = re.compile(r"(?ms)^(mail\.truemailor\.com\s*\{)(.*?)(^\})")
mm = mail_pat.search(text)
if mm:
    inner = mm.group(2)
    if "import truemailor_public_site" not in inner and "import truemailor_legal_pages" not in inner:
        # Only legal handles for mail — inject a mail-safe import via dedicated snippet.
        pass

# Add mail-only legal snippet import
mail_legal_marker = "# BEGIN truemailor-mail-legal"
mail_legal_end = "# END truemailor-mail-legal"
mail_legal = f"""{mail_legal_marker}
(truemailor_mail_legal) {{
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
{mail_legal_end}
"""
if mail_legal_marker in text:
    text = re.sub(
        re.escape(mail_legal_marker) + r".*?" + re.escape(mail_legal_end),
        mail_legal.strip(),
        text,
        count=1,
        flags=re.S,
    )
else:
    text = mail_legal + "\n" + text

if mm:
    inner = mm.group(2)
    if "import truemailor_mail_legal" not in inner:
        # Re-find after text mutations
        mm2 = re.search(r"(?ms)^(mail\.truemailor\.com\s*\{)(.*?)(^\})", text)
        if mm2:
            new_inner = "\timport truemailor_mail_legal\n" + mm2.group(2)
            text = text[: mm2.start()] + mm2.group(1) + "\n" + new_inner + mm2.group(3) + text[mm2.end() :]

caddy.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
print(f"Updated {caddy}")
PY
else
  echo "No Caddyfile at ${CADDYFILE}; site files installed only." >&2
fi

# Reload Caddy
if command -v docker >/dev/null 2>&1; then
  for c in truemail-caddy-1 caddy; do
    if docker ps --format '{{.Names}}' | grep -qx "$c"; then
      if docker exec "$c" caddy validate --config /etc/caddy/Caddyfile; then
        docker exec "$c" caddy reload --config /etc/caddy/Caddyfile \
          || docker kill -s HUP "$c" || true
        echo "Reloaded ${c}"
      else
        echo "Caddy validate failed — check ${CADDYFILE}" >&2
        exit 1
      fi
      break
    fi
  done
fi

echo
echo "TraceFace removed. Public URLs:"
echo "  https://truemailor.com/"
echo "  https://truemailor.com/privacy.html"
echo "  https://truemailor.com/terms.html"
echo "  https://mail.truemailor.com/privacy.html"
if [[ -d "$BACKUP_ROOT" ]]; then
  echo "Backup: ${BACKUP_ROOT}"
fi
