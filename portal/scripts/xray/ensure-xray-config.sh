#!/usr/bin/env bash
# Rebuild /opt/xray/config.json from clients.json + reality.keys and reload Xray.
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

XRAY_DIR="${XRAY_DIR:-/opt/xray}"
SETUP="${XRAY_SETUP_SCRIPT:-$XRAY_DIR/setup-xray.sh}"
# Prefer packaged script next to this file when present.
HERE="$(cd "$(dirname "$0")" && pwd)"
if [[ -x "$HERE/setup-xray.sh" ]]; then
  SETUP="$HERE/setup-xray.sh"
fi

# Re-run the config writer only (setup is idempotent).
bash "$SETUP"
