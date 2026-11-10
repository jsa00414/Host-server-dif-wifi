#!/bin/bash
# Raise kernel + OpenVPN buffers so the TCP tunnel can approach ~100Mbps.
# Safe to re-run. Does not change UFW / public exposure.
set -euo pipefail
export PATH="/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

SYSCTL_FILE=/etc/sysctl.d/99-openvpn-speed.conf
cat >"$SYSCTL_FILE" <<'EOF'
# Managed by openvpn-speed-tune.sh — TCP buffers for OpenVPN site tunnel
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.ipv4.tcp_rmem = 4096 1048576 16777216
net.ipv4.tcp_wmem = 4096 1048576 16777216
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
EOF
sysctl --system >/dev/null 2>&1 || sysctl -p "$SYSCTL_FILE" >/dev/null

# Ensure tun queue is deep once the interface exists (also set in server.conf).
if ip link show tun0 >/dev/null 2>&1; then
  ip link set dev tun0 txqueuelen 10000 || true
fi

echo "openvpn speed tune applied (rmem/wmem max 16MiB, tcp_slow_start_after_idle=0)"
