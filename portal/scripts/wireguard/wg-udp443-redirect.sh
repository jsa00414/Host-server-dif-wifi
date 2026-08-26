#!/bin/bash
# Map UDP/443 -> WireGuard 5000.
# Campus / school networks often allow 443/udp more reliably than 5000/udp.
set -euo pipefail
ufw allow 443/udp comment "WG school-friendly" >/dev/null 2>&1 || true
iptables -t nat -C PREROUTING -p udp --dport 443 -m comment --comment SM-WG-443 -j REDIRECT --to-ports 5000 2>/dev/null \
  || iptables -t nat -I PREROUTING 1 -p udp --dport 443 -m comment --comment SM-WG-443 -j REDIRECT --to-ports 5000
