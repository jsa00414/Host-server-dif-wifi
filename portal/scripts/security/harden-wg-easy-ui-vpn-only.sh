#!/usr/bin/env bash
# Restrict WireGuard Easy UI (:5001/tcp) to LAN/VPN clients.
# Keeps :5000/udp public — that is the WireGuard tunnel itself.
# Caddy → vpn.vpstruelord.com still reaches the UI via Docker bridge allows.
# Safe to re-run.
set -euo pipefail

VPN_UFW_FROM="${VPN_UFW_FROM:-10.8.0.0/24 10.9.0.0/24 100.64.0.0/10 192.168.8.0/24}"
EXTRA_ALLOW="${WG_UI_EXTRA_ALLOW:-10.42.42.0/24 172.16.0.0/12}"
PORT="${WG_UI_PORT:-5001}"
COMMENT="wg-easy-ui-vpn"

sources=()
for p in ${VPN_UFW_FROM//,/ }; do
  [[ -n "${p// }" ]] && sources+=("$p")
done
for p in ${EXTRA_ALLOW//,/ }; do
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

echo "wg-easy UI :${PORT} allow sources: ${sources[*]}"

if ! command -v ufw >/dev/null 2>&1; then
  echo "ufw not installed" >&2
  exit 1
fi

needles=(
  "${PORT}/tcp"
  "wg-easy-ui"
  "wg-easy-ui-vpn"
)

for _ in $(seq 1 40); do
  numbered="$(ufw status numbered 2>/dev/null || true)"
  num=""
  while IFS= read -r line; do
    [[ "$line" == \[* ]] || continue
    hit=0
    for n in "${needles[@]}"; do
      if [[ "$line" == *"$n"* ]]; then
        hit=1
        break
      fi
    done
    [[ "$hit" -eq 1 ]] || continue
    nraw="${line%%]*}"
    nraw="${nraw#[}"
    nraw="${nraw// /}"
    [[ "$nraw" =~ ^[0-9]+$ ]] || continue
    if [[ -z "$num" || "$nraw" -gt "$num" ]]; then
      num="$nraw"
    fi
  done <<< "$numbered"
  [[ -z "${num:-}" ]] && break
  ufw --force delete "$num" >/dev/null || true
done

for src in "${sources[@]}"; do
  ufw allow from "$src" to any port "$PORT" proto tcp comment "$COMMENT" >/dev/null || true
done

echo "ufw: ${PORT}/tcp restricted to VPN/LAN/Docker (5000/udp tunnel left public)"
ufw status numbered | grep -E "${PORT}/tcp|5000/udp|wg-easy|WireGuard" || true
ss -lntp | grep ":${PORT}" || true
echo "wg-easy UI VPN-only harden complete"
