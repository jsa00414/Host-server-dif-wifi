#!/usr/bin/env bash
# Remove all operational references to the retired VPS 74.208.54.132.
# Safe to re-run. Does not change external DNS (truemailor.com is a different zone).
set -euo pipefail

OLD_IP="${RETIRED_VPS_IP:-74.208.54.132}"
NEW_IP="${VPS_PUBLIC_IP:-74.208.76.213}"

echo "Retiring ${OLD_IP} → keep ${NEW_IP} only"

# --- WireGuard dual-run bridge to old VPS ---
for conf in /etc/wireguard/vps2-to-old.conf /etc/wireguard/*old*.conf; do
  [[ -f "$conf" ]] || continue
  if grep -qF "$OLD_IP" "$conf" 2>/dev/null; then
    base="$(basename "$conf" .conf)"
    systemctl disable --now "wg-quick@${base}" 2>/dev/null || true
    mv -f "$conf" "${conf}.retired-$(date +%Y%m%d%H%M%S)"
    echo "disabled/moved $conf"
  fi
done

# --- Caddy: drop old IP from allowlists / blocks ---
CADDYFILE="${CADDYFILE:-/opt/truemail/Caddyfile}"
if [[ -f "$CADDYFILE" ]]; then
  if grep -qF "$OLD_IP" "$CADDYFILE"; then
    cp -a "$CADDYFILE" "${CADDYFILE}.bak.retire-old-ip-$(date +%Y%m%d%H%M%S)"
    # Remove " IP/32" allowlist entries and bare IP mentions.
    sed -i -E "s/[[:space:]]+${OLD_IP//./\\.}\/32//g" "$CADDYFILE"
    sed -i "s/${OLD_IP//./\\.}/${NEW_IP}/g" "$CADDYFILE"
    # Drop dual-run site blocks that only existed for the old host IP.
    python3 - "$CADDYFILE" "$OLD_IP" <<'PY'
import re, sys
from pathlib import Path
path = Path(sys.argv[1])
old = sys.argv[2]
text = path.read_text(encoding="utf-8")
# Remove http://OLD_IP { ... } blocks if any remain.
pat = re.compile(rf"http://{re.escape(old)}\s*\{{.*?\n\}}", re.S)
out, n = pat.subn("", text)
if n:
    path.write_text(out, encoding="utf-8")
    print(f"caddy: removed {n} http://{old} site block(s)")
else:
    print("caddy: no old-IP site blocks")
PY
    caddy_ctr=""
    for c in truemail-caddy-1 caddy; do
      if docker ps --format '{{.Names}}' | grep -qx "$c"; then
        caddy_ctr="$c"
        break
      fi
    done
    if [[ -n "$caddy_ctr" ]]; then
      docker exec "$caddy_ctr" caddy validate --config /etc/caddy/Caddyfile >/dev/null
      docker exec "$caddy_ctr" caddy reload --config /etc/caddy/Caddyfile >/dev/null \
        || docker restart "$caddy_ctr" >/dev/null
      echo "caddy: reloaded $caddy_ctr"
    fi
  else
    echo "caddy: no ${OLD_IP} references"
  fi
fi

# --- remote-desktop: point leftover docs/certs at new IP / domain ---
RD_ROOT="${REMOTE_DESKTOP_ROOT:-/opt/remote-desktop}"
if [[ -d "$RD_ROOT" ]]; then
  while IFS= read -r f; do
    [[ -f "$f" ]] || continue
    if grep -qF "$OLD_IP" "$f"; then
      sed -i "s/${OLD_IP//./\\.}/${NEW_IP}/g" "$f"
      echo "updated $f"
    fi
  done < <(grep -rlF "$OLD_IP" "$RD_ROOT" --include='*.js' --include='*.html' --include='*.sh' --include='*.md' 2>/dev/null || true)
fi

# --- portal / wireguard tree: rewrite live defaults (skip .bak* and this script) ---
SELF="$(readlink -f "$0" 2>/dev/null || realpath "$0" 2>/dev/null || echo "$0")"
for root in /opt/wireguard/port-forward-ui /opt/wireguard/scripts /opt/wireguard/.env.example; do
  [[ -e "$root" ]] || continue
  if [[ -f "$root" ]]; then
    files=("$root")
  else
    mapfile -t files < <(grep -rlF "$OLD_IP" "$root" 2>/dev/null | grep -Ev '\.bak(\.|$)|retired-|retire-old-vps-ip\.sh' || true)
  fi
  for f in "${files[@]:-}"; do
    [[ -f "$f" ]] || continue
    [[ "$(readlink -f "$f" 2>/dev/null || echo "$f")" == "$SELF" ]] && continue
    [[ "$(basename "$f")" == "retire-old-vps-ip.sh" ]] && continue
    sed -i "s/${OLD_IP//./\\.}/${NEW_IP}/g" "$f"
    echo "updated $f"
  done
done

# --- truemail docs that still list the old A-record target ---
for f in /opt/truemail/CLOUDFLARE-DNS.md /opt/truemail/README.md; do
  [[ -f "$f" ]] || continue
  if grep -qF "$OLD_IP" "$f"; then
    sed -i "s/${OLD_IP//./\\.}/${NEW_IP}/g" "$f"
    echo "updated $f"
  fi
done

# --- report leftovers (non-bak) ---
echo "--- remaining ${OLD_IP} (excluding backups) ---"
grep -rnlF "$OLD_IP" /opt/wireguard /opt/truemail /opt/remote-desktop /etc/wireguard 2>/dev/null \
  | grep -Ev '\.bak(\.|$)|retired-|\.bak-' \
  || echo "(none)"

echo "retire-old-vps-ip complete"
echo "NOTE: update truemailor.com DNS A records to ${NEW_IP} at that zone's provider (token cannot)."
