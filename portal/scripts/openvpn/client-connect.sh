#!/bin/bash
# Prefer OpenVPN for home LAN while Flint is connected; keep WG as fallback.
if [ "${common_name:-}" = "flint" ]; then
  ip route replace 192.168.8.0/24 via 10.9.0.2 dev tun0 metric 5
  ip route replace 10.0.0.0/24 via 10.9.0.2 dev tun0 metric 5
  ip route replace 192.168.8.0/24 via 10.42.42.42 metric 100 2>/dev/null || true
  ip route replace 10.0.0.0/24 via 10.42.42.42 metric 100 2>/dev/null || true
fi
exit 0
