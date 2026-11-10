#!/usr/bin/env bash
# Restrict Flint/LAN DNAT public ports to VPN/LAN sources:
#   8080/tcp flint-http  -> 192.168.8.1:80
#   2222/tcp flint-ssh   -> 10.8.0.3:22
#   8084/tcp new-rule    -> 192.168.8.232:8080
# Leaves OpenVPN :8443/tcp public (school VPN).
# Safe to re-run.
set -euo pipefail

VPN_UFW_FROM="${VPN_UFW_FROM:-10.8.0.0/24 10.9.0.0/24 100.64.0.0/10 192.168.8.0/24 10.42.42.0/24 172.16.0.0/12}"
PORTS="${FLINT_VPN_ONLY_PORTS:-8080 2222 8084}"
APPLY="${APPLY_LAN_FORWARDS:-/opt/wireguard/scripts/apply-lan-forwards.sh}"

sources=()
for p in ${VPN_UFW_FROM//,/ }; do
  [[ -n "${p// }" ]] && sources+=("$p")
done

echo "flint forwards VPN-only ports: ${PORTS}"
echo "allow sources: ${sources[*]}"

if ! command -v ufw >/dev/null 2>&1; then
  echo "ufw not installed" >&2
  exit 1
fi

# Delete Anywhere / broad allows for these ports (keep VPN-scoped rules).
for port in $PORTS; do
  for _ in $(seq 1 40); do
    numbered="$(ufw status numbered 2>/dev/null || true)"
    num=""
    while IFS= read -r line; do
      [[ "$line" == \[* ]] || continue
      [[ "$line" == *"${port}/tcp"* ]] || continue
      # Keep rules that already name a private/VPN source.
      keep=0
      for src in "${sources[@]}"; do
        if [[ "$line" == *"$src"* ]]; then
          keep=1
          break
        fi
      done
      [[ "$keep" -eq 1 ]] && continue
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
done

for port in $PORTS; do
  for src in "${sources[@]}"; do
    if ! ufw status | grep -qE "${port}/tcp.*${src}|${src}.*${port}/tcp"; then
      ufw allow from "$src" to any port "$port" proto tcp comment "flint-fwd-vpn ${port}" >/dev/null || true
    fi
  done
done

# Re-apply DNAT with VPN-only source matches for these ports.
if [[ -x "$APPLY" ]]; then
  VPN_ONLY_FORWARD_PORTS="${VPN_ONLY_FORWARD_PORTS:-1445 3389 4000 ${PORTS}}" \
    bash "$APPLY"
else
  echo "WARN: missing $APPLY — UFW restricted, DNAT not reapplied" >&2
fi

echo "--- ufw (flint ports) ---"
ufw status numbered | grep -E '8080/tcp|2222/tcp|8084/tcp' || true
echo "--- dnat ---"
iptables -t nat -S SERVERMANAGER_DNAT 2>/dev/null | grep -E 'dport (8080|2222|8084)' || true
echo "flint forwards VPN-only harden complete"
