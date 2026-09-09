#!/bin/bash
# Create Plex libraries from known video folders on the WD USB mount.
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

# Explicit media roots (skip CinemaCave app copies / installers)
movie_candidates=(
  "Movies"
  "New Movies"
  "Kids Movies"
  "kids mp4"
  "LEAVING NETFLEX"
  "inport"
)
tv_candidates=(
  "TV Shows"
  "KIDS TV SHOWS"
)

movie_locs=()
tv_locs=()
for name in "${movie_candidates[@]}"; do
  p="$CT_MNT/$name"
  if [[ -d "$p" ]]; then
    movie_locs+=("$p")
  fi
done
for name in "${tv_candidates[@]}"; do
  p="$CT_MNT/$name"
  if [[ -d "$p" ]]; then
    tv_locs+=("$p")
  fi
done

echo "movie_locs:"
printf '  %s\n' "${movie_locs[@]:-(none)}"
echo "tv_locs:"
printf '  %s\n' "${tv_locs[@]:-(none)}"

if [[ ${#movie_locs[@]} -eq 0 && ${#tv_locs[@]} -eq 0 ]]; then
  echo "No known media folders found" >&2
  exit 1
fi

# Ensure plex user can read (ntfs often nobody:nogroup 755 — OK for dirs)
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
  local name="$1" type="$2" agent="$3" scanner="$4" language="$5"
  shift 5
  local locs=("$@")
  [[ ${#locs[@]} -eq 0 ]] && return 0
  local key
  key=$(section_key "$name")
  if [[ -n "$key" ]]; then
    echo "==> Section '$name' exists (key=$key); adding locations…"
    for loc in "${locs[@]}"; do
      code=$(curl -sk -o /tmp/plex-loc.out -w '%{http_code}' -X POST \
        "http://127.0.0.1:32400/library/sections/${key}/location?X-Plex-Token=$TOKEN&location=$(q "$loc")" || true)
      echo "    add $loc -> HTTP $code"
      head -c 200 /tmp/plex-loc.out 2>/dev/null; echo
    done
    curl -sk "http://127.0.0.1:32400/library/sections/${key}/refresh?X-Plex-Token=$TOKEN" >/dev/null || true
  else
    echo "==> Creating section '$name' type=$type"
    qs="name=$(q "$name")&type=$type&agent=$(q "$agent")&scanner=$(q "$scanner")&language=$(q "$language")&X-Plex-Token=$TOKEN"
    for loc in "${locs[@]}"; do
      qs+="&location=$(q "$loc")"
      echo "    location: $loc"
    done
    code=$(curl -sk -o /tmp/plex-create.out -w '%{http_code}' -X POST "http://127.0.0.1:32400/library/sections?$qs" || true)
    echo "    HTTP $code"
    cat /tmp/plex-create.out; echo
  fi
}

if [[ ${#movie_locs[@]} -gt 0 ]]; then
  create_or_add "USB Movies" 1 "tv.plex.agents.movie" "Plex Movie" "en-US" "${movie_locs[@]}"
fi
if [[ ${#tv_locs[@]} -gt 0 ]]; then
  create_or_add "USB TV" 2 "tv.plex.agents.series" "Plex TV Series" "en-US" "${tv_locs[@]}"
fi

# Refresh existing XML cache for section_key of newly created
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
echo "DONE"
REMOTE
