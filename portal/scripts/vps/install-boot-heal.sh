#!/usr/bin/env bash
# Install reboot recovery for Truemailor / portal / VPN on the VPS.
# Run on the VPS as root:
#   bash install-boot-heal.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"

install -m 0755 "$ROOT/sm-boot-heal" /usr/local/sbin/sm-boot-heal
install -m 0644 "$ROOT/sm-boot-heal.service" /etc/systemd/system/sm-boot-heal.service
install -m 0644 "$ROOT/sm-boot-heal.timer" /etc/systemd/system/sm-boot-heal.timer

systemctl daemon-reload
systemctl enable sm-boot-heal.service sm-boot-heal.timer
systemctl start sm-boot-heal.service
systemctl start sm-boot-heal.timer

echo "Installed sm-boot-heal (service + 2min-after-boot timer)."
systemctl is-enabled sm-boot-heal.service sm-boot-heal.timer
systemctl is-active sm-boot-heal.service sm-boot-heal.timer || true
