#!/bin/bash
# Surfshark WireGuard config helper (manual .conf files from Surfshark dashboard)
set -euo pipefail

ROOT="/opt/surfshark"
CONF_DIR="${ROOT}/conf"
RUNTIME_DIR="/etc/wireguard"
STATE_FILE="${ROOT}/ss-vpn-exit.state"

mkdir -p "$CONF_DIR"

list_servers() {
  shopt -s nullglob
  for f in "$CONF_DIR"/*.conf; do
    base="$(basename "$f" .conf)"
    endpoint=""
    endpoint=$(grep -E '^Endpoint\s*=' "$f" 2>/dev/null | head -1 | sed 's/.*=\s*//' | tr -d ' ')
    echo "${base}|${endpoint}"
  done
}

runtime_conf() {
  local name="$1"
  local src="${CONF_DIR}/${name}.conf"
  local dst="${RUNTIME_DIR}/ss-${name}.conf"
  if [[ ! -f "$src" ]]; then
    echo "missing config: $src" >&2
    return 2
  fi
  python3 - "$src" "$dst" <<'PY'
import re, sys
src, dst = sys.argv[1:3]
text = open(src, encoding="utf-8", errors="replace").read()
text = re.sub(r"(?m)^AllowedIPs\s*=\s*0\.0\.0\.0/0.*$", "AllowedIPs = 128.0.0.0/1, 0.0.0.0/1", text)
text = re.sub(r"(?m)^AllowedIPs\s*=\s*::/0.*$", "", text)
if re.search(r"(?m)^Table\s*=", text):
    text = re.sub(r"(?m)^Table\s*=.*$", "Table = off", text)
else:
    text = re.sub(r"(\[Interface\]\s*\n)", r"\1Table = off\n", text, count=1)
text = re.sub(r"(?m)^Name\s*=.*\n", "", text)
text = re.sub(r"(?m)^DNS\s*=.*\n", "", text)
open(dst, "w", encoding="utf-8").write(text)
PY
  chmod 600 "$dst"
  echo "$dst"
}

current_iface() {
  if [[ -f "$STATE_FILE" ]]; then
    grep '^IFACE=' "$STATE_FILE" 2>/dev/null | cut -d= -f2-
  fi
}

connect() {
  local name="$1"
  local dst
  dst="$(runtime_conf "$name")"
  local ifname="ss-${name}"
  wg-quick down "$ifname" 2>/dev/null || true
  wg-quick up "$ifname"
  echo "connected ${ifname}"
}

disconnect() {
  shopt -s nullglob
  for f in "$RUNTIME_DIR"/ss-*.conf; do
    base="$(basename "$f" .conf)"
    wg-quick down "$base" 2>/dev/null || true
  done
  echo "disconnected"
}

status() {
  echo "configs:"
  list_servers || true
  echo "--- wg ---"
  wg show 2>/dev/null || echo "(none)"
}

ACTION="${1:-status}"
case "$ACTION" in
  list) list_servers ;;
  connect) connect "${2:?server name}" ;;
  disconnect) disconnect ;;
  status) status ;;
  *) echo "usage: $0 list|connect <name>|disconnect|status" >&2; exit 2 ;;
esac
