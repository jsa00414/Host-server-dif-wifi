#!/usr/bin/env bash
# Compare sticky VPN IPs vs key-bound allowlist vs Caddy @vpn_clients /32s.
# Writes Prometheus textfile metrics and emails on drift.
set -euo pipefail

ENV_FILE="${PORTAL_ENV_FILE:-/opt/wireguard/port-forward-ui.env}"
UI_ROOT="${PORTAL_UI_ROOT:-/opt/wireguard/port-forward-ui}"
PYTHON_BIN="${UI_ROOT}/.venv/bin/python"
[[ -x "$PYTHON_BIN" ]] || PYTHON_BIN=python3

set -a
# shellcheck disable=SC1090
[[ -f "$ENV_FILE" ]] && . "$ENV_FILE"
set +a

cd "$UI_ROOT"
export CIRCLE_DRIFT_METRICS_PATH="${CIRCLE_DRIFT_METRICS_PATH:-/var/lib/node_exporter/textfile_collector/circle_drift.prom}"
mkdir -p "$(dirname "$CIRCLE_DRIFT_METRICS_PATH")"

"$PYTHON_BIN" - <<'PY'
import os, sys
sys.path.insert(0, os.environ.get("PORTAL_UI_ROOT", "/opt/wireguard/port-forward-ui"))
import server
from sm.vpn_circle import run_circle_drift_check

to = os.environ.get("EMAIL_CODE_TO") or os.environ.get("PORTAL_LOGIN_NOTIFY_TO") or ""
report = run_circle_drift_check(
    smtp_send=server._smtp_send_email,
    email_to=to,
    email_on_drift=True,
)
print(
    "circle-drift:",
    "DRIFT" if report.get("drifted") else "ok",
    report.get("counts"),
)
if report.get("email_sent"):
    print("circle-drift: email sent")
if report.get("email_error"):
    print("circle-drift: email error:", report["email_error"])
if report.get("metrics_error"):
    print("circle-drift: metrics error:", report["metrics_error"])
sys.exit(2 if report.get("drifted") else 0)
PY
