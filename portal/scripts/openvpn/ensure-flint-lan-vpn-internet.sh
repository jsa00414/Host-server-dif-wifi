#!/usr/bin/env bash
# ServerManager — Flint LAN internet via OpenVPN only (VPS exit).
#
# Desired policy: phones/PCs on 192.168.8.0/24 must NOT use school WAN.
# All internet exits through ovpnclient1 → VPS MASQ (SM-OVPN-MASQ).
# Killswitch stays on so a tunnel drop does not leak to campus.
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
    -o ConnectTimeout=15 \
    "root@${host}" 'sh -s' <<'REMOTE'
set -e
uci set route_policy.@default[0].via='ovpnclient1'
uci set route_policy.@default[0].mark='0xa000'
i=0
while uci -q get route_policy.@rule[$i] >/dev/null 2>&1; do
  via="$(uci -q get route_policy.@rule[$i].via || true)"
  if [ "$via" = "ovpnclient1" ] || [ "$(uci -q get route_policy.@rule[$i].via_type || true)" = "openvpn" ]; then
    uci set "route_policy.@rule[$i].killswitch=1"
  fi
  i=$((i + 1))
done
uci commit route_policy

[ -x /usr/bin/rtp2.sh ] && /usr/bin/rtp2.sh reload >/dev/null 2>&1 || true
[ -x /etc/init.d/route_policy ] && /etc/init.d/route_policy reload >/dev/null 2>&1 || true

# Drop any prior "force LAN onto school WAN" safety net from the brief novpn experiment
ip rule del pref 8900 2>/dev/null || true

mkdir -p /etc/firewall.user.d
cat >/etc/firewall.user.d/sm-lan-internet-via-vpn.sh <<'EOF'
#!/bin/sh
# ServerManager: LAN internet via OVPN only (no school-WAN leak helper).
ip rule del pref 8900 2>/dev/null || true
EOF
chmod +x /etc/firewall.user.d/sm-lan-internet-via-vpn.sh
# neutralize old novpn helper if present
cat >/etc/firewall.user.d/sm-lan-internet-via-wan.sh <<'EOF'
#!/bin/sh
# Deprecated name — VPN-only policy. See sm-lan-internet-via-vpn.sh.
ip rule del pref 8900 2>/dev/null || true
EOF
chmod +x /etc/firewall.user.d/sm-lan-internet-via-wan.sh
grep -q sm-lan-internet-via-vpn /etc/firewall.user 2>/dev/null || \
  echo '[ -f /etc/firewall.user.d/sm-lan-internet-via-vpn.sh ] && . /etc/firewall.user.d/sm-lan-internet-via-vpn.sh' >> /etc/firewall.user

. /etc/firewall.user.d/sm-lan-internet-via-vpn.sh
conntrack -F >/dev/null 2>&1 || true

via="$(uci get route_policy.@default[0].via)"
mark="$(uci get route_policy.@default[0].mark)"
ks="$(uci -q get route_policy.@rule[0].killswitch || echo '?')"
echo "lan-vpn-internet: via=$via mark=$mark killswitch=$ks"
# Quick tunnel health
if ping -c1 -W3 -I ovpnclient1 8.8.8.8 >/dev/null 2>&1; then
  echo "lan-vpn-internet: ovpn exit OK"
else
  echo "lan-vpn-internet: WARN ovpn exit ping failed" >&2
  exit 2
fi
REMOTE
  then
    ok=1
    echo "applied on $host"
    break
  fi
done
[[ "$ok" -eq 1 ]] || { echo "failed to reach Flint via $HOSTS" >&2; exit 1; }
