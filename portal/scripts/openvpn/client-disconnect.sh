#!/bin/bash
if [ "${common_name:-}" = "flint" ]; then
  ip route del 192.168.8.0/24 via 10.9.0.2 dev tun0 metric 5 2>/dev/null || true
  ip route del 10.0.0.0/24 via 10.9.0.2 dev tun0 metric 5 2>/dev/null || true
  ip route del 192.168.8.0/24 via 10.9.0.2 dev tun0 metric 50 2>/dev/null || true
  ip route del 10.0.0.0/24 via 10.9.0.2 dev tun0 metric 50 2>/dev/null || true
  # restore WG path as primary when OVPN drops
  ip route replace 192.168.8.0/24 via 10.42.42.42 metric 10 2>/dev/null || true
  ip route replace 10.0.0.0/24 via 10.42.42.42 metric 10 2>/dev/null || true
  ip route replace 10.8.0.0/24 via 10.42.42.42 metric 10 2>/dev/null || true
fi
exit 0
