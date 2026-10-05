#!/usr/bin/env bash
# Remove IKEv2 / WireGuard / OpenVPN session + flood caps that were dropping
# real clients. Equivalent to: VPN_RATE_CAP_MODE=off bash harden-vpn-ports-rate-cap.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec env VPN_RATE_CAP_MODE=off bash "$ROOT/harden-vpn-ports-rate-cap.sh"
