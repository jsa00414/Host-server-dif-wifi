#!/usr/bin/env bash
# ServerManager — keep Flint LAN on school WAN internet.
#
# GL route_policy default was sending all LAN traffic via ovpnclient1 with
# killswitch=1. That OVPN profile is site-to-site (portal / circle DNS only),
# not a full-tunnel internet exit — so clients lost internet while the router
# itself (local OUTPUT) still worked on eth1/apclix0.
#
# This script:
#   1) Sets route_policy default via=novpn (mark 0x8000)
#   2) Disables killswitch on the OVPN tunnel rule
#   3) Ensures TUNNEL*_ROUTE_POLICY marks WAN-direct by default
#   4) Drops LAN blackhole rules; adds pref 8900 LAN→main safety net
set -euo pipefail

OVPN_GW="${OVPN_FLINT_IP:-10.9.0.2}"
HOSTS="${ROUTER_HOSTS:-$OVPN_GW,192.168.8.1}"

pass=""
if [[ -n "${ROUTER_PASS:-}" ]]; then
  pass="$ROUTER_PASS"
elif [[ -n "${ROUTER_PASS_B64:-}" ]]; then
  pass="$(ROUTER_PASS_B64="$ROUTER_PASS_B64" python3 -c 'import os,base64; print(base64.b64decode(os.environ["ROUTER_PASS_B64"]).decode())')"
fi
[[ -n "$pass" ]] || { echo "ROUTER_PASS / ROUTER_PASS_B64 required" >&2; exit 1; }
command -v sshpass >/dev/null 2>&1 || { echo "sshpass required" >&2; exit 1; }

export SSHPASS="$pass"
ok=0
IFS=',' read -r -a hosts <<<"$HOSTS"
for host in "${hosts[@]}"; do
  host="$(echo "$host" | xargs)"
  [[ -n "$host" ]] || continue
  if sshpass -e ssh \
    -o StrictHostKeyChecking=no \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    -o ConnectTimeout=12 \
    "root@${host}" 'sh -s' <<'REMOTE'
set -e
uci set route_policy.@default[0].via='novpn'
uci set route_policy.@default[0].mark='0x8000'
# rule index for Tunnel 1 may vary; disable killswitch on any OVPN via rule
i=0
while uci -q get route_policy.@rule[$i] >/dev/null 2>&1; do
  via="$(uci -q get route_policy.@rule[$i].via || true)"
  if [ "$via" = "ovpnclient1" ] || [ "$(uci -q get route_policy.@rule[$i].via_type || true)" = "openvpn" ]; then
    uci set "route_policy.@rule[$i].killswitch=0"
  fi
  i=$((i + 1))
done
uci commit route_policy

[ -x /usr/bin/rtp2.sh ] && /usr/bin/rtp2.sh reload >/dev/null 2>&1 || true
[ -x /etc/init.d/route_policy ] && /etc/init.d/route_policy reload >/dev/null 2>&1 || true

mkdir -p /etc/firewall.user.d
cat >/etc/firewall.user.d/sm-lan-internet-via-wan.sh <<'EOF'
#!/bin/sh
# ServerManager: LAN clients use school WAN; OVPN stays site-to-site.
for chain in $(iptables -t mangle -S 2>/dev/null | awk '/^-N TUNNEL[0-9]+_ROUTE_POLICY/{print $2}'); do
  iptables -t mangle -F "$chain" 2>/dev/null || true
  iptables -t mangle -A "$chain" -d 74.208.76.213/32 -m mark --mark 0x0/0xf000 -j MARK --set-xmark 0xa000/0xf000 2>/dev/null || true
  iptables -t mangle -A "$chain" -d 10.11.0.1/32 -m mark --mark 0x0/0xf000 -j MARK --set-xmark 0xa000/0xf000 2>/dev/null || true
  iptables -t mangle -A "$chain" -d 10.42.42.0/24 -m mark --mark 0x0/0xf000 -j MARK --set-xmark 0xa000/0xf000 2>/dev/null || true
  iptables -t mangle -A "$chain" -m mark --mark 0x0/0xf000 -m comment --comment SM-LAN-WAN-DIRECT -j MARK --set-xmark 0x8000/0xf000 2>/dev/null || true
done
ip rule del pref 9910 2>/dev/null || true
ip rule del pref 9920 2>/dev/null || true
ip rule del pref 8900 2>/dev/null || true
ip rule add pref 8900 from 192.168.8.0/24 lookup main 2>/dev/null || true
EOF
chmod +x /etc/firewall.user.d/sm-lan-internet-via-wan.sh
grep -q sm-lan-internet-via-wan /etc/firewall.user 2>/dev/null || \
  echo '[ -f /etc/firewall.user.d/sm-lan-internet-via-wan.sh ] && . /etc/firewall.user.d/sm-lan-internet-via-wan.sh' >> /etc/firewall.user
. /etc/firewall.user.d/sm-lan-internet-via-wan.sh
conntrack -F >/dev/null 2>&1 || true
echo "lan-wan-internet: via=$(uci get route_policy.@default[0].via) mark=$(uci get route_policy.@default[0].mark) killswitch=$(uci -q get route_policy.@rule[0].killswitch)"
REMOTE
  then
    ok=1
    echo "applied on $host"
    break
  fi
done
[[ "$ok" -eq 1 ]] || { echo "failed to reach Flint via $HOSTS" >&2; exit 1; }
