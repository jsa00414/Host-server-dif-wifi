#!/usr/bin/env bash
# Remove HTTP/HTTPS per-IP connlimits in front of Caddy / sslh (:80/:443).
# Equivalent to: HTTP_RATE_CAP_MODE=off bash harden-http-ports-conn-cap.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec env HTTP_RATE_CAP_MODE=off bash "$ROOT/harden-http-ports-conn-cap.sh"
