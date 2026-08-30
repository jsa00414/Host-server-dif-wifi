#!/bin/bash
# Deploy portal snapshot to a VPS. Usage:
#   VPS=root@74.208.76.213 ./portal/deploy-to-vps.sh   # primary VPS
# Credentials (environment secrets):
#   VPS_SSH_PRIVATE_KEY  — preferred (root SSH private key)
#   VPS_SSH_PASSWORD     — alternative (root password)
#   VPS_HOST / VPS_USER / VPS_PORT — optional overrides
set -euo pipefail

VPS="${VPS:-root@74.208.76.213}"
ROOT="$(cd "$(dirname "$0")" && pwd)"
REMOTE_UI="/opt/wireguard/port-forward-ui"

if [[ -n "${VPS_SSH_PRIVATE_KEY:-}" || -n "${VPS_SSH_PASSWORD:-}" ]]; then
  export VPS_HOST="${VPS_HOST:-${VPS#*@}}"
  export VPS_USER="${VPS_USER:-${VPS%@*}}"
  exec python3 "$ROOT/deploy-to-vps.py"
fi

SSH_OPTS=()
if [[ -n "${VPS_SSH_KEY_FILE:-}" && -f "${VPS_SSH_KEY_FILE}" ]]; then
  SSH_OPTS=(-i "$VPS_SSH_KEY_FILE")
fi

echo "Deploying portal to ${VPS}:${REMOTE_UI} …"
ssh "${SSH_OPTS[@]}" "$VPS" "mkdir -p ${REMOTE_UI}/static ${REMOTE_UI}/scripts/nas"
scp "${SSH_OPTS[@]}" "$ROOT/server.py" "${VPS}:${REMOTE_UI}/server.py"
scp "${SSH_OPTS[@]}" "$ROOT/static/index.html" "${VPS}:${REMOTE_UI}/static/index.html"
scp "${SSH_OPTS[@]}" "$ROOT/static/files.html" "${VPS}:${REMOTE_UI}/static/files.html"
scp "${SSH_OPTS[@]}" "$ROOT/static/nas-windows.html" "${VPS}:${REMOTE_UI}/static/nas-windows.html"
scp "${SSH_OPTS[@]}" "$ROOT/scripts/nas/Setup-ServerManagerNas.ps1" "${VPS}:${REMOTE_UI}/scripts/nas/Setup-ServerManagerNas.ps1"
# Keep public-IP literals aligned with the target host when present in server.py
case "$VPS" in
  *74.208.76.213*)
    ssh "${SSH_OPTS[@]}" "$VPS" "sed -i 's/74\\.208\\.54\\.132/74.208.76.213/g' ${REMOTE_UI}/server.py || true"
    REFRESH_HINT="http://74.208.76.213/"
    ;;
  *)
    REFRESH_HINT="https://portal.vpstruelord.com/"
    ;;
esac
ssh "${SSH_OPTS[@]}" "$VPS" "systemctl restart port-forward-ui && systemctl is-active port-forward-ui"
echo "Done. Hard-refresh ${REFRESH_HINT} (Ctrl+Shift+R)."
