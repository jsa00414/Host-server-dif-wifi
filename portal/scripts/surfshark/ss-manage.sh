#!/bin/bash
# Surfshark WireGuard config helper (manual .conf files from Surfshark dashboard)
set -euo pipefail

ROOT="/opt/surfshark"
CONF_DIR="${ROOT}/conf"
RUNTIME_DIR="${ROOT}/runtime"
STATE_FILE="${ROOT}/ss-vpn-exit.state"

mkdir -p "$CONF_DIR" "$RUNTIME_DIR"

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
  python3 - "$src" "$dst" "ss-${name}" <<'PY'
import re, sys
src, dst, ifname = sys.argv[1:4]
text = open(src, encoding="utf-8", errors="replace").read()
# Strip full-tunnel AllowedIPs default route from peer — policy routing handles egress
text = re.sub(r"(?m)^AllowedIPs\s*=\s*0\.0\.0\.0/0.*$", "AllowedIPs = 128.0.0.0/1, 0.0.0.0/1", text)
text = re.sub(r"(?m)^AllowedIPs\s*=\s*::/0.*$", "", text)
if re.search(r"(?m)^Table\s*=", text):
    text = re.sub(r"(?m)^Table\s*=.*$", "Table = off", text)
else:
    text = re.sub(r"(\[Interface\]\s*\n)", r"\1Table = off\n", text, count=1)
if re.search(r"(?m)^Name\s*=", text):
    text = re.sub(r"(?m)^Name\s*=.*$", f"Name = {ifname}", text)
else:
    text = re.sub(r"(\[Interface\]\s*\n)", rf"\1Name = {ifname}\n", text, count=1)
# Avoid Surfshark pushing DNS onto the VPS host
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
  # Drop any previous surfshark iface
  wg-quick down "$dst" 2>/dev/null || true
  wg-quick up "$dst"
  echo "connected ${ifname}"
}

disconnect() {
  local ifname
  ifname="$(current_iface)"
  shopt -s nullglob
  for f in "$RUNTIME_DIR"/ss-*.conf; do
    wg-quick down "$f" 2>/dev/null || true
  done
  if [[ -n "$ifname" ]]; then
    ip link del "$ifname" 2>/dev/null || true
  fi
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
