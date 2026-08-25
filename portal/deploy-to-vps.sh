#!/bin/bash
# Deploy portal snapshot to VPS. Usage:
#   VPS=root@74.208.54.132 ./portal/deploy-to-vps.sh
set -euo pipefail

VPS="${VPS:-root@74.208.54.132}"
ROOT="$(cd "$(dirname "$0")" && pwd)"
REMOTE_UI="/opt/wireguard/port-forward-ui"

echo "Deploying portal to ${VPS}:${REMOTE_UI} …"
ssh "$VPS" "mkdir -p ${REMOTE_UI}/static"
scp "$ROOT/server.py" "${VPS}:${REMOTE_UI}/server.py"
scp "$ROOT/static/index.html" "${VPS}:${REMOTE_UI}/static/index.html"
ssh "$VPS" "systemctl restart port-forward-ui && systemctl is-active port-forward-ui"
echo "Done. Hard-refresh https://portal.vpstruelord.com/ (Ctrl+Shift+R)."
