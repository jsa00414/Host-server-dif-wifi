#!/bin/bash
# Deploy portal snapshot to the primary VPS. Usage:
#   VPS=root@74.208.76.213 ./portal/deploy-to-vps.sh
set -euo pipefail

VPS="${VPS:-root@74.208.76.213}"
ROOT="$(cd "$(dirname "$0")" && pwd)"
REMOTE_UI="/opt/wireguard/port-forward-ui"
REMOTE_SCRIPTS="/opt/wireguard/scripts"

echo "Deploying portal to ${VPS}:${REMOTE_UI} …"
ssh "$VPS" "mkdir -p ${REMOTE_UI}/static ${REMOTE_SCRIPTS}"
scp "$ROOT/server.py" "${VPS}:${REMOTE_UI}/server.py"
scp "$ROOT/static/index.html" "${VPS}:${REMOTE_UI}/static/index.html"
if [[ -f "$ROOT/scripts/apply-lan-forwards.sh" ]]; then
  scp "$ROOT/scripts/apply-lan-forwards.sh" "${VPS}:${REMOTE_SCRIPTS}/apply-lan-forwards.sh"
  ssh "$VPS" "chmod +x ${REMOTE_SCRIPTS}/apply-lan-forwards.sh"
fi
ssh "$VPS" "sed -i 's/74\\.208\\.54\\.132/74.208.76.213/g' ${REMOTE_UI}/server.py || true"
ssh "$VPS" "systemctl restart port-forward-ui && systemctl is-active port-forward-ui"
echo "Done. Hard-refresh https://portal.vpstruelord.com/ (Ctrl+Shift+R)."
