#!/usr/bin/env bash
# Deprecated wrapper — LAN must use OVPN (VPS exit), not school WAN.
# Kept so older docs/cron still resolve; delegates to VPN-only helper.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
exec bash "$SCRIPT_DIR/ensure-flint-lan-vpn-internet.sh" "$@"
