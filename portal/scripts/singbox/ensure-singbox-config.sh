#!/usr/bin/env bash
# Rebuild /opt/singbox/config.json from clients.json + reality.keys and reload sing-box.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec bash "$SCRIPT_DIR/setup-singbox.sh"
