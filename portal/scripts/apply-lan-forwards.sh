#!/usr/bin/env bash
# VPS public ports -> Flint WireGuard (10.8.0.3) -> Flint Port Forward -> LAN
#
# IMPORTANT: Never `wg set` a stale/wrong peer pubkey. That creates a ghost peer
# whose AllowedIPs steal the LAN routes from the live Flint client (AllowedIPs
# become "(none)" on the real peer → "No route to host" for 192.168.8.x).
set -euo pipefail

CONF="/opt/wireguard/scripts/forwards.conf"
WG_GW="10.42.42.42"
ROUTER_WG="10.8.0.3"
LAN_CIDR="10.0.0.0/24"
WG_CIDR="10.8.0.0/24"
# Current GL-MT6000 pubkey from wg-easy (override via ROUTER_WG_PUBKEY)
ROUTER_PUBKEY_FALLBACK="42M88B4u4+M7G4pVKv2ZHnffXwQkiMc+UB1/Gsbur1c="
VPS_IP="${VPS_PUBLIC_IP:-74.208.76.213}"
CHAIN="SERVERMANAGER_DNAT"
WG_CONTAINER="${WG_EASY_CONTAINER:-wg-easy}"
WANT_ALLOWED="${ROUTER_WG}/32,${LAN_CIDR},192.168.8.0/24,fdcc:ad94:bacf:61a4::cafe:3/128"

resolve_router_pubkey() {
  if [[ -n "${ROUTER_WG_PUBKEY:-}" ]]; then
    echo "$ROUTER_WG_PUBKEY"
    return
  fi
  # Prefer live peer that already advertises the tunnel IP
  local pub
  pub=$(docker exec "$WG_CONTAINER" wg show wg0 dump 2>/dev/null | awk -v ip="${ROUTER_WG}/32" '
    NR > 1 && index($4, ip) { print $1; exit }
  ' || true)
  if [[ -n "${pub:-}" ]]; then
    echo "$pub"
    return
  fi
  # wg-easy API (no auth needed on localhost for some installs; ignore failures)
  pub=$(curl -fsS --max-time 3 "http://127.0.0.1:5001/api/client" 2>/dev/null \
    | python3 -c "
import json,sys
try:
    clients=json.load(sys.stdin)
except Exception:
    raise SystemExit(0)
for c in clients or []:
    if str(c.get('ipv4Address') or '') == '${ROUTER_WG}' or str(c.get('name') or '') == 'GL-MT6000':
        print(c.get('publicKey') or '')
        break
" 2>/dev/null || true)
  if [[ -n "${pub:-}" ]]; then
    echo "$pub"
    return
  fi
  echo "$ROUTER_PUBKEY_FALLBACK"
}

ROUTER_PUBKEY="$(resolve_router_pubkey)"

# Update AllowedIPs only on an existing peer — never create a new one.
if docker exec "$WG_CONTAINER" wg show wg0 peers 2>/dev/null | grep -qxF "$ROUTER_PUBKEY"; then
  docker exec "$WG_CONTAINER" wg set wg0 peer "$ROUTER_PUBKEY" allowed-ips "$WANT_ALLOWED" 2>/dev/null || true
else
  echo "WARN: Flint peer ${ROUTER_PUBKEY} not present in wg0; skip AllowedIPs update" >&2
fi

# Drop any OTHER peer that currently holds the LAN AllowedIPs (ghost peers)
while read -r other; do
  [[ -z "$other" || "$other" == "$ROUTER_PUBKEY" ]] && continue
  oips=$(docker exec "$WG_CONTAINER" wg show wg0 dump | awk -v p="$other" '$1==p {print $4}')
  if [[ "$oips" == *"192.168.8.0/24"* || "$oips" == *"${ROUTER_WG}/32"* ]]; then
    echo "Removing conflicting WG peer ${other} (held LAN AllowedIPs)"
    docker exec "$WG_CONTAINER" wg set wg0 peer "$other" remove 2>/dev/null || true
  fi
done < <(docker exec "$WG_CONTAINER" wg show wg0 peers 2>/dev/null || true)

ip route replace "${WG_CIDR}" via "${WG_GW}"
ip route replace "${LAN_CIDR}" via "${WG_GW}"
ip route replace "192.168.8.0/24" via "${WG_GW}" 2>/dev/null || true

iptables -C FORWARD -d "${WG_CIDR}" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -d "${WG_CIDR}" -j ACCEPT
iptables -C FORWARD -s "${WG_CIDR}" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -s "${WG_CIDR}" -j ACCEPT
iptables -C FORWARD -d "${LAN_CIDR}" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -d "${LAN_CIDR}" -j ACCEPT
iptables -C FORWARD -s "${LAN_CIDR}" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -s "${LAN_CIDR}" -j ACCEPT
iptables -C FORWARD -d "192.168.8.0/24" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -d "192.168.8.0/24" -j ACCEPT
iptables -C FORWARD -s "192.168.8.0/24" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -s "192.168.8.0/24" -j ACCEPT

docker exec "$WG_CONTAINER" sh -c "
  ip route replace 10.0.0.0/24 dev wg0
  ip route replace 192.168.8.0/24 dev wg0 2>/dev/null || true
  iptables -C FORWARD -i eth0 -o wg0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i eth0 -o wg0 -j ACCEPT
  iptables -C FORWARD -i wg0 -o eth0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i wg0 -o eth0 -j ACCEPT
  iptables -t nat -C POSTROUTING -o wg0 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o wg0 -j MASQUERADE
" || true

# Dedicated DNAT chain so we do not hijack Docker->LAN proxies (Caddy etc.)
iptables -t nat -N "$CHAIN" 2>/dev/null || iptables -t nat -F "$CHAIN"
if ! iptables -t nat -C PREROUTING -j "$CHAIN" 2>/dev/null; then
  iptables -t nat -I PREROUTING 1 -j "$CHAIN"
fi

# Remove legacy unscoped DNAT rules for ports we manage (they steal Caddy upstreams)
while read -r pub proto dest_ip dest_port name; do
  [[ -z "${pub:-}" || "$pub" =~ ^# ]] && continue
  for _ in 1 2 3 4 5 6 7 8; do
    line=$(iptables -t nat -S PREROUTING | grep -E -- "--dport ${pub} .*-j DNAT" | grep -v "$CHAIN" | head -n 1 || true)
    [[ -z "$line" ]] && break
    eval "iptables -t nat ${line/-A/-D}" 2>/dev/null || break
  done
done < "$CONF"

iptables -t nat -F "$CHAIN"

apply_one() {
  local pub="$1" proto="$2" dest_ip="$3" dest_port="$4" name="$5"
  echo "forward ${pub}/${proto} -> ${dest_ip}:${dest_port} (${name}) [only ${VPS_IP}]"
  iptables -t nat -A "$CHAIN" -d "$VPS_IP" -p "$proto" --dport "$pub" -j DNAT --to-destination "${dest_ip}:${dest_port}"

  iptables -t nat -C POSTROUTING -p "$proto" -d "$dest_ip" --dport "$dest_port" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -p "$proto" -d "$dest_ip" --dport "$dest_port" -j MASQUERADE

  iptables -C FORWARD -p "$proto" -d "$dest_ip" --dport "$dest_port" -j ACCEPT 2>/dev/null \
    || iptables -A FORWARD -p "$proto" -d "$dest_ip" --dport "$dest_port" -j ACCEPT
  iptables -C FORWARD -p "$proto" -s "$dest_ip" --sport "$dest_port" -j ACCEPT 2>/dev/null \
    || iptables -A FORWARD -p "$proto" -s "$dest_ip" --sport "$dest_port" -j ACCEPT

  if command -v ufw >/dev/null 2>&1; then
    ufw status | grep -q "${pub}/${proto}" || ufw allow "${pub}/${proto}" comment "GL forward ${name}" >/dev/null
  fi
}

while read -r pub proto dest_ip dest_port name; do
  [[ -z "${pub:-}" || "$pub" =~ ^# ]] && continue
  apply_one "$pub" "$proto" "$dest_ip" "$dest_port" "${name:-fwd}"
done < "$CONF"

echo "OK: routes and forwards applied (Flint peer ${ROUTER_PUBKEY})"
ip route | grep -E "10.8.0.|10.0.0.|192.168.8." || true
docker exec "$WG_CONTAINER" wg show | awk '/peer:|allowed ips:|endpoint:|latest handshake:/ {print}'
