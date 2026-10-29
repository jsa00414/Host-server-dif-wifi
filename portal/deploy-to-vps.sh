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
ssh "${SSH_OPTS[@]}" "$VPS" "mkdir -p ${REMOTE_UI}/static/truemailor ${REMOTE_UI}/sm ${REMOTE_UI}/scripts/nas ${REMOTE_UI}/scripts/truemail ${REMOTE_UI}/scripts/xray"
scp "${SSH_OPTS[@]}" "$ROOT/server.py" "${VPS}:${REMOTE_UI}/server.py"
scp "${SSH_OPTS[@]}" "$ROOT/media_tmdb.py" "${VPS}:${REMOTE_UI}/media_tmdb.py"
scp "${SSH_OPTS[@]}" "$ROOT/sm/__init__.py" "$ROOT/sm/auth.py" "$ROOT/sm/nas.py" "$ROOT/sm/vpn_circle.py" "$ROOT/sm/twilio_sms.py" "${VPS}:${REMOTE_UI}/sm/"
scp "${SSH_OPTS[@]}" "$ROOT/static/index.html" "${VPS}:${REMOTE_UI}/static/index.html"
scp "${SSH_OPTS[@]}" "$ROOT/static/login.html" "${VPS}:${REMOTE_UI}/static/login.html"
scp "${SSH_OPTS[@]}" "$ROOT/static/files.html" "${VPS}:${REMOTE_UI}/static/files.html"
scp "${SSH_OPTS[@]}" "$ROOT/static/nas-windows.html" "${VPS}:${REMOTE_UI}/static/nas-windows.html"
scp "${SSH_OPTS[@]}" "$ROOT/static/xray.html" "${VPS}:${REMOTE_UI}/static/xray.html"
scp "${SSH_OPTS[@]}" "$ROOT/scripts/xray/setup-xray.sh" "$ROOT/scripts/xray/ensure-xray-config.sh" "$ROOT/scripts/xray/README.md" "${VPS}:${REMOTE_UI}/scripts/xray/"
ssh "${SSH_OPTS[@]}" "$VPS" "chmod +x ${REMOTE_UI}/scripts/xray/*.sh"
scp "${SSH_OPTS[@]}" "$ROOT/static/email-code-test.html" "${VPS}:${REMOTE_UI}/static/email-code-test.html"
scp "${SSH_OPTS[@]}" "$ROOT/static/sms-code-test.html" "${VPS}:${REMOTE_UI}/static/sms-code-test.html"
scp "${SSH_OPTS[@]}" "$ROOT/static/privacy.html" "${VPS}:${REMOTE_UI}/static/privacy.html"
scp "${SSH_OPTS[@]}" "$ROOT/static/terms.html" "${VPS}:${REMOTE_UI}/static/terms.html"
scp "${SSH_OPTS[@]}" "$ROOT/static/truemailor/index.html" "${VPS}:${REMOTE_UI}/static/truemailor/index.html"
scp "${SSH_OPTS[@]}" "$ROOT/scripts/truemail/install-legal-pages.sh" "${VPS}:${REMOTE_UI}/scripts/truemail/install-legal-pages.sh"
scp "${SSH_OPTS[@]}" "$ROOT/scripts/truemail/remove-traceface.sh" "${VPS}:${REMOTE_UI}/scripts/truemail/remove-traceface.sh"
scp "${SSH_OPTS[@]}" "$ROOT/scripts/nas/Setup-ServerManagerNas.ps1" "${VPS}:${REMOTE_UI}/scripts/nas/Setup-ServerManagerNas.ps1"
# Replace TraceFace on truemailor.com with Truemailor landing + A2P legal pages.
ssh "${SSH_OPTS[@]}" "$VPS" "chmod +x ${REMOTE_UI}/scripts/truemail/remove-traceface.sh && bash ${REMOTE_UI}/scripts/truemail/remove-traceface.sh" || true
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
