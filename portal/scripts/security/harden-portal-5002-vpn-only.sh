#!/usr/bin/env bash
# Restrict portal cleartext HTTP (:5002) to LAN/VPN clients.
# Caddy → portal still works via existing Docker bridge UFW allows
# (172.16.0.0/12). Safe to re-run.
set -euo pipefail

VPN_UFW_FROM="${VPN_UFW_FROM:-10.8.0.0/24 10.9.0.0/24 100.64.0.0/10 192.168.8.0/24}"
# Extra: WG-easy docker net + docker bridges (Caddy reverse_proxy to :5002)
PORTAL_EXTRA_ALLOW="${PORTAL_EXTRA_ALLOW:-10.42.42.0/24 172.16.0.0/12}"
COMMENT="portal-http-vpn"
PORT=5002

sources=()
for p in ${VPN_UFW_FROM//,/ }; do
  [[ -n "${p// }" ]] && sources+=("$p")
done
for p in ${PORTAL_EXTRA_ALLOW//,/ }; do
  [[ -n "${p// }" ]] && sources+=("$p")
done
declare -A seen=()
uniq_sources=()
for s in "${sources[@]}"; do
  [[ -n "${seen[$s]:-}" ]] && continue
  seen[$s]=1
  uniq_sources+=("$s")
done
sources=("${uniq_sources[@]}")

echo "portal :${PORT} allow sources: ${sources[*]}"

if ! command -v ufw >/dev/null 2>&1; then
  echo "ufw not installed" >&2
  exit 1
fi

# Delete all existing 5002 allows (Anywhere + CIDR + v6)
for _ in $(seq 1 40); do
  numbered="$(ufw status numbered 2>/dev/null || true)"
  num="$(
    printf '%s\n' "$numbered" | awk -v p="$PORT" '
      /^\[[[:space:]]*[0-9]+\]/ {
        line=$0
        if (line ~ ("(^|[[:space:]])" p "/tcp") || line ~ ("(^|[[:space:]])" p "([[:space:]]|\\()")) {
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

for src in "${sources[@]}"; do
  ufw allow from "$src" to any port "$PORT" proto tcp comment "$COMMENT" >/dev/null || true
done

echo "ufw: ${PORT}/tcp restricted to VPN/LAN/Docker"
ufw status numbered | grep -E "${PORT}/tcp|${PORT} " || true
ss -lntp | grep ":${PORT}" || true
echo "portal :${PORT} VPN-only harden complete"
