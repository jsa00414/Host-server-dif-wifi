#!/usr/bin/env bash
# Restore public IKEv2 (UDP 500/4500 on WAN) while keeping portal fixes
# (split-DNS, hairpin RETURN, peer ACL, no HTTP/3).
set -euo pipefail

CHARON_MAIN="${CHARON_MAIN:-/etc/strongswan.d/charon.conf}"

echo "==> Restore public IKEv2"

# charon: listen on all interfaces again
if [[ -f "$CHARON_MAIN" ]]; then
  python3 - <<'PY'
from pathlib import Path
import re
p = Path("/etc/strongswan.d/charon.conf")
t = p.read_text()
t2, n = re.subn(
    r"(?m)^\s*interfaces_use\s*=\s*.*$",
    "    # interfaces_use =",
    t,
    count=1,
)
if n:
    p.write_text(t2)
    print("cleared interfaces_use in charon.conf")
else:
    print("interfaces_use already unset")
PY
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

echo "--- listen ---"
ipsec statusall 2>&1 | sed -n '/Listening IP/,/Connections/p' || true
ss -ulnp | grep -E ':500|:4500' || true
echo "--- ufw ---"
ufw status | grep -E '500/udp|4500/udp' || true
echo "OK: IKEv2 public again — connect ServerManager IKEv2 to portal.vpstruelord.com"
