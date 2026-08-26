#!/bin/bash
# $common_name set by OpenVPN
if [ "${common_name:-}" = "flint" ]; then
  ip route replace 192.168.8.0/24 via 10.9.0.2 dev tun0 metric 50
  ip route replace 10.0.0.0/24 via 10.9.0.2 dev tun0 metric 50
fi
exit 0
