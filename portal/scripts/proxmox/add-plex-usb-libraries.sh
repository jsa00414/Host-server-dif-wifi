#!/bin/bash
# Create four Plex libraries from the Elements USB media folders:
#   Movies, Kids Movies, TV Shows, KIDS TV SHOWS
set -euo pipefail

CTID="${CTID:-101}"

pct exec "$CTID" -- bash -s <<'REMOTE'
set -euo pipefail
CT_MNT="/mnt/usb"

TOKEN=$(python3 - <<'PY'
import re, pathlib
p = pathlib.Path("/var/lib/plexmediaserver/Library/Application Support/Plex Media Server/Preferences.xml")
t = p.read_text(errors="replace")
m = re.search(r'PlexOnlineToken="([^"]+)"', t)
print(m.group(1) if m else "")
PY
)
if [[ -z "$TOKEN" ]]; then
  echo "No PlexOnlineToken — claim server first" >&2
  exit 1
fi

if ! mountpoint -q "$CT_MNT"; then
  echo "$CT_MNT is not mounted" >&2
  exit 1
fi

echo "==> Top-level USB:"
ls -1 "$CT_MNT" | head -80

# Four primary library folders (exact names on the Elements drive)
declare -a libs=(
  "Movies|1|USB Movies|tv.plex.agents.movie|Plex Movie"
  "Kids Movies|1|USB Kids Movies|tv.plex.agents.movie|Plex Movie"
  "TV Shows|2|USB TV|tv.plex.agents.series|Plex TV Series"
  "KIDS TV SHOWS|2|USB Kids TV|tv.plex.agents.series|Plex TV Series"
)

existing=$(curl -sk --max-time 30 "http://127.0.0.1:32400/library/sections?X-Plex-Token=$TOKEN" || true)
echo "==> Existing sections snippet:"
echo "$existing" | head -c 1500; echo

q() { python3 -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))' "$1"; }

section_key() {
  local name="$1"
  printf '%s' "$existing" | python3 -c '
import re, sys
xml = sys.stdin.read()
name = sys.argv[1]
pat1 = r"<Directory[^>]*title=\"%s\"[^>]*key=\"(\d+)\"" % re.escape(name)
pat2 = r"<Directory[^>]*key=\"(\d+)\"[^>]*title=\"%s\"" % re.escape(name)
m = re.search(pat1, xml) or re.search(pat2, xml)
print(m.group(1) if m else "")
' "$name"
}

create_or_add() {
  local name="$1" type="$2" agent="$3" scanner="$4" language="$5" loc="$6"
  local key
  key=$(section_key "$name")
  if [[ -n "$key" ]]; then
    echo "==> Section '$name' exists (key=$key); ensuring location $loc…"
    code=$(curl -sk -o /tmp/plex-loc.out -w '%{http_code}' -X POST \
      "http://127.0.0.1:32400/library/sections/${key}/location?X-Plex-Token=$TOKEN&location=$(q "$loc")" || true)
    echo "    add $loc -> HTTP $code"
    head -c 200 /tmp/plex-loc.out 2>/dev/null; echo
    curl -sk "http://127.0.0.1:32400/library/sections/${key}/refresh?X-Plex-Token=$TOKEN" >/dev/null || true
  else
    echo "==> Creating section '$name' type=$type location=$loc"
    qs="name=$(q "$name")&type=$type&agent=$(q "$agent")&scanner=$(q "$scanner")&language=$(q "$language")&location=$(q "$loc")&X-Plex-Token=$TOKEN"
    code=$(curl -sk -o /tmp/plex-create.out -w '%{http_code}' -X POST "http://127.0.0.1:32400/library/sections?$qs" || true)
    echo "    HTTP $code"
    cat /tmp/plex-create.out; echo
  fi
}

hooked=0
for entry in "${libs[@]}"; do
  IFS='|' read -r folder type title agent scanner <<<"$entry"
  path="$CT_MNT/$folder"
  if [[ -d "$path" ]]; then
    echo "==> Hookup folder: $folder → Plex '$title'"
    create_or_add "$title" "$type" "$agent" "$scanner" "en-US" "$path"
    hooked=$((hooked + 1))
  else
    echo "==> Missing folder (skip): $folder"
  fi
done

if [[ "$hooked" -eq 0 ]]; then
  echo "No known media folders found" >&2
  exit 1
fi

existing=$(curl -sk --max-time 30 "http://127.0.0.1:32400/library/sections?X-Plex-Token=$TOKEN" || true)
curl -sk "http://127.0.0.1:32400/library/sections/all/refresh?X-Plex-Token=$TOKEN" >/dev/null || true

echo "==> Final sections:"
printf '%s' "$existing" | python3 - <<'PY'
import sys, re
xml = sys.stdin.read()
for m in re.finditer(r'<Directory\b([^>]*)>', xml):
    attrs = m.group(1)
    def g(k):
        mm = re.search(rf'{k}="([^"]*)"', attrs)
        return mm.group(1) if mm else ""
    print(f"  key={g('key')} title={g('title')!r} type={g('type')} locations={g('locations')}")
for m in re.finditer(r'<Location\b([^>]*)>', xml):
    attrs = m.group(1)
    def g(k):
        mm = re.search(rf'{k}="([^"]*)"', attrs)
        return mm.group(1) if mm else ""
    print(f"    Location id={g('id')} path={g('path')}")
PY
echo "DONE hooked=${hooked}"
REMOTE
