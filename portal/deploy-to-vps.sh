#!/bin/bash
# Deploy portal snapshot to a VPS. Usage:
#   VPS=root@74.208.54.132 ./portal/deploy-to-vps.sh   # old (DNS primary)
#   VPS=root@74.208.76.213 ./portal/deploy-to-vps.sh   # new dual-run clone
set -euo pipefail

VPS="${VPS:-root@74.208.54.132}"
ROOT="$(cd "$(dirname "$0")" && pwd)"
REMOTE_UI="/opt/wireguard/port-forward-ui"

echo "Deploying portal to ${VPS}:${REMOTE_UI} …"
ssh "$VPS" "mkdir -p ${REMOTE_UI}/static"
scp "$ROOT/server.py" "${VPS}:${REMOTE_UI}/server.py"
scp "$ROOT/static/index.html" "${VPS}:${REMOTE_UI}/static/index.html"
# Keep public-IP literals aligned with the target host when present in server.py
case "$VPS" in
  *74.208.76.213*)
    ssh "$VPS" "sed -i 's/74\\.208\\.54\\.132/74.208.76.213/g' ${REMOTE_UI}/server.py || true"
    REFRESH_HINT="http://74.208.76.213/"
    ;;
  *)
    REFRESH_HINT="https://portal.vpstruelord.com/"
    ;;
esac
ssh "$VPS" "systemctl restart port-forward-ui && systemctl is-active port-forward-ui"
echo "Done. Hard-refresh ${REFRESH_HINT} (Ctrl+Shift+R)."
