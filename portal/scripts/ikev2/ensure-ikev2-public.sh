#!/usr/bin/env bash
# Restore public IKEv2 (UDP 500/4500 on WAN) while keeping portal fixes
# (split-DNS, hairpin RETURN, peer ACL, no HTTP/3, WAN-only bind, no nest).
set -euo pipefail

CHARON_MAIN="${CHARON_MAIN:-/etc/strongswan.d/charon.conf}"
WAN_IF="${IKEV2_WAN_IF:-$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')}"
WAN_IF="${WAN_IF:-ens6}"

echo "==> Restore public IKEv2 (WAN=${WAN_IF})"

# charon: listen on public WAN only (never advertise docker/tun ADD_4_ADDR to Windows MOBIKE)
if [[ -f "$CHARON_MAIN" ]]; then
  WAN_IF="$WAN_IF" CHARON_MAIN="$CHARON_MAIN" python3 - <<'PY'
from pathlib import Path
import os, re
p = Path(os.environ["CHARON_MAIN"])
t = p.read_text()
wan = os.environ["WAN_IF"]
if re.search(r"(?m)^\s*interfaces_use\s*=", t):
    t = re.sub(r"(?m)^\s*#?\s*interfaces_use\s*=.*$", f"    interfaces_use = {wan}", t, count=1)
else:
    t = t.replace("charon {\n", f"charon {{\n    interfaces_use = {wan}\n", 1)
p.write_text(t)
print(f"set interfaces_use = {wan} in {p}")
PY
fi

KN="/etc/strongswan.d/charon/kernel-netlink.conf"
if [[ -f "$KN" ]]; then
  python3 - <<'PY'
from pathlib import Path
import re
p = Path("/etc/strongswan.d/charon/kernel-netlink.conf")
t = p.read_text()
for key, val in (("roam_events", "no"), ("process_route", "no")):
    if re.search(rf"(?m)^\s*#?\s*{key}\s*=", t):
        t = re.sub(rf"(?m)^\s*#?\s*{key}\s*=\s*.*$", f"    {key} = {val}", t, count=1)
    else:
        t = t.replace("kernel-netlink {\n", f"kernel-netlink {{\n    {key} = {val}\n", 1)
p.write_text(t)
PY
fi

# Ensure mobike=no on the live conn definition
if [[ -f /etc/ipsec.conf ]] && ! grep -q 'mobike=no' /etc/ipsec.conf; then
  sed -i '/^conn %default/,/^conn /{ /rekey=no/a\    mobike=no
}' /etc/ipsec.conf || true
fi
if [[ -f /etc/ipsec.conf ]] && ! awk '/^conn ikev2-eap/{f=1} f&&/mobike=no/{found=1} f&&/^conn /&&!/ikev2-eap/{f=0} END{exit !found}' /etc/ipsec.conf; then
  sed -i '/^conn ikev2-eap/a\    mobike=no' /etc/ipsec.conf || true
fi

# Remove unused snippet marker
rm -f /etc/strongswan.d/charon/sm-ikev2-via-openvpn.conf

# UFW: allow public IKE again
if command -v ufw >/dev/null 2>&1; then
  ufw allow 500/udp comment 'IKEv2 IKE' >/dev/null 2>&1 || true
  ufw allow 4500/udp comment 'IKEv2 NAT-T' >/dev/null 2>&1 || true
  echo "ufw: 500/4500 ALLOW Anywhere"
fi

systemctl disable --now sm-ikev2-via-openvpn.service >/dev/null 2>&1 || true

if systemctl is-active --quiet strongswan-starter 2>/dev/null; then
  systemctl restart strongswan-starter
elif command -v ipsec >/dev/null 2>&1; then
  ipsec restart 2>/dev/null || true
fi
sleep 2

# Re-apply portal path fixes
[[ -x /opt/ikev2/ensure-ikev2-forward.sh ]] && bash /opt/ikev2/ensure-ikev2-forward.sh || true
[[ -x /opt/ikev2/ensure-vpn-split-dns.sh ]] && bash /opt/ikev2/ensure-vpn-split-dns.sh || true
[[ -x /opt/ikev2/ensure-ikev2-peer-acl.sh ]] && bash /opt/ikev2/ensure-ikev2-peer-acl.sh || true
[[ -x /opt/ikev2/ensure-caddy-no-h3.sh ]] && bash /opt/ikev2/ensure-caddy-no-h3.sh || true
[[ -x /opt/ikev2/ensure-ikev2-no-nest.sh ]] && bash /opt/ikev2/ensure-ikev2-no-nest.sh || true

echo "--- listen ---"
ipsec statusall 2>&1 | sed -n '/Listening IP/,/Connections/p' || true
ss -ulnp | grep -E ':500|:4500' || true
echo "--- ufw ---"
ufw status | grep -E '500/udp|4500/udp' || true
echo "OK: IKEv2 public on ${WAN_IF} only — reconnect ServerManager IKEv2"
