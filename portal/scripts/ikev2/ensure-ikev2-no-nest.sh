#!/usr/bin/env bash
# Block IKEv2 nesting through Flint OpenVPN (tun0 / 10.9.0.0/24).
#
# Windows MOBIKE will otherwise path-flip public IKEv2 onto 10.9.0.2 and
# report "terminated by the remote computer". Phones usually stay on WAN.
set -euo pipefail

iptables -C INPUT -i tun0 -p udp -m multiport --dports 500,4500 -m comment --comment SM-IKEV2-NO-NEST -j DROP 2>/dev/null \
  || iptables -I INPUT 1 -i tun0 -p udp -m multiport --dports 500,4500 -m comment --comment SM-IKEV2-NO-NEST -j DROP
iptables -C INPUT -s 10.9.0.0/24 -p udp -m multiport --dports 500,4500 -m comment --comment SM-IKEV2-NO-NEST -j DROP 2>/dev/null \
  || iptables -I INPUT 1 -s 10.9.0.0/24 -p udp -m multiport --dports 500,4500 -m comment --comment SM-IKEV2-NO-NEST -j DROP

echo "ikev2: blocked nested IKE via tun0/10.9.0.0/24"
