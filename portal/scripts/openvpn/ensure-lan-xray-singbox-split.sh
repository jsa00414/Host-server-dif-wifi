#!/usr/bin/env bash
# ServerManager — Flint LAN internet via Xray (circle) / sing-box (guest).
#
# Flow: LAN → OVPN (source IPs preserved) → VPS iptables REDIRECT
#   circle allowlisted 192.168.8.x  → Xray dokodemo :18080
#   everyone else on LAN           → sing-box redirect :18081
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

ALLOWLIST="${VPN_ALLOWLIST_FILE:-/opt/servermanager/panel/vpn-allowlist.json}"
XRAY_SETUP="${XRAY_SETUP_SCRIPT:-/opt/wireguard/port-forward-ui/scripts/xray/setup-xray.sh}"
SINGBOX_SETUP="${SINGBOX_SETUP_SCRIPT:-/opt/wireguard/port-forward-ui/scripts/singbox/setup-singbox.sh}"
XRAY_DOKODEMO_PORT="${XRAY_DOKODEMO_PORT:-18080}"
SINGBOX_REDIR_PORT="${SINGBOX_REDIR_PORT:-18081}"
LAN_CIDR="${LAN_CIDR:-192.168.8.0/24}"
VPS_IP="${VPS_PUBLIC_IP:-74.208.76.213}"
ADGUARD_DNS="${OVPN_DNS_ADGUARD:-10.42.42.44}"
GUEST_DNS="${VPN_GUEST_DNS:-10.42.42.45}"
CIRCLE_SET="sm-circle-lan"
GUEST_SET="sm-guest-lan"
COMMENT="SM-LAN-PROXY-SPLIT"

need_bin() { command -v "$1" >/dev/null 2>&1 || { echo "missing $1" >&2; exit 1; }; }
need_bin ipset
need_bin iptables
need_bin python3

ensure_proxies() {
  [[ -x "$XRAY_SETUP" ]] && bash "$XRAY_SETUP" >/tmp/sm-xray-setup.log 2>&1 || true
  [[ -x "$SINGBOX_SETUP" ]] && bash "$SINGBOX_SETUP" >/tmp/sm-singbox-setup.log 2>&1 || true
  systemctl is-active --quiet sm-xray || systemctl restart sm-xray || true
  systemctl is-active --quiet sm-singbox || systemctl restart sm-singbox || true
}

sync_ipsets() {
  ipset create "$CIRCLE_SET" hash:ip family inet timeout 0 -exist
  ipset create "$GUEST_SET" hash:ip family inet timeout 0 -exist
  ipset flush "$CIRCLE_SET"
  ipset flush "$GUEST_SET"
  ALLOWLIST="$ALLOWLIST" LAN_CIDR="$LAN_CIDR" CIRCLE_SET="$CIRCLE_SET" GUEST_SET="$GUEST_SET" python3 - <<'PY'
import ipaddress, json, os, subprocess
from pathlib import Path

allow = Path(os.environ["ALLOWLIST"])
lan = ipaddress.ip_network(os.environ["LAN_CIDR"], strict=False)
circle_set = os.environ["CIRCLE_SET"]
guest_set = os.environ["GUEST_SET"]
data = {"allowed": [], "pending": [], "denied": []}
if allow.is_file():
    try:
        data = json.loads(allow.read_text(encoding="utf-8"))
    except Exception:
        pass

def is_lan(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in lan
    except Exception:
        return False

circle = set()
for row in data.get("allowed") or []:
    if not isinstance(row, dict):
        continue
    ip = str(row.get("ip") or "").strip()
    if not is_lan(ip):
        continue
    sealed = bool(row.get("sealed")) or (
        str(row.get("source") or "") == "router"
        and "sealed" in str(row.get("note") or "").lower()
    )
    key_bound = bool(str(row.get("pubkey") or "").strip())
    if sealed or key_bound:
        circle.add(ip)

guest = set()
for bucket in ("pending", "denied"):
    for row in data.get(bucket) or []:
        if not isinstance(row, dict):
            continue
        ip = str(row.get("ip") or "").strip()
        if is_lan(ip) and ip not in circle:
            guest.add(ip)

# Known LAN leases that are not circle → guest (best-effort from pending already)
for ip in sorted(circle):
    subprocess.run(["ipset", "add", circle_set, ip, "-exist"], check=False)
for ip in sorted(guest):
    subprocess.run(["ipset", "add", guest_set, ip, "-exist"], check=False)
print(f"ipsets circle={len(circle)} guest={len(guest)}")
PY
}

flush_split_rules() {
  # Remove prior SM-LAN-PROXY-SPLIT rules from nat PREROUTING
  local tmp
  tmp="$(mktemp)"
  iptables -t nat -S PREROUTING | grep "comment --comment $COMMENT" | sed 's/^-A /-D /' >"$tmp" || true
  while read -r line; do
    [[ -n "$line" ]] || continue
    # shellcheck disable=SC2086
    iptables -t nat $line 2>/dev/null || true
  done <"$tmp"
  rm -f "$tmp"
}

install_split_rules() {
  flush_split_rules
  # Exclusions first (private / DNS / VPS / VPN pools)
  for cidr in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 "${VPS_IP}/32" "${ADGUARD_DNS}/32" "${GUEST_DNS}/32"; do
    iptables -t nat -A PREROUTING -i tun0 -s "$LAN_CIDR" -d "$cidr" -p tcp \
      -m comment --comment "$COMMENT" -j RETURN
  done
  # Circle → Xray dokodemo
  iptables -t nat -A PREROUTING -i tun0 -s "$LAN_CIDR" -p tcp \
    -m set --match-set "$CIRCLE_SET" src \
    -m comment --comment "$COMMENT" -j REDIRECT --to-ports "$XRAY_DOKODEMO_PORT"
  # Explicit guest set → sing-box
  iptables -t nat -A PREROUTING -i tun0 -s "$LAN_CIDR" -p tcp \
    -m set --match-set "$GUEST_SET" src \
    -m comment --comment "$COMMENT" -j REDIRECT --to-ports "$SINGBOX_REDIR_PORT"
  # Remaining LAN (unknown) → sing-box guest path
  iptables -t nat -A PREROUTING -i tun0 -s "$LAN_CIDR" -p tcp \
    -m comment --comment "$COMMENT" -j REDIRECT --to-ports "$SINGBOX_REDIR_PORT"

  # UDP/ICMP still need MASQ out ens6 (not redirected)
  iptables -t nat -C POSTROUTING -s "$LAN_CIDR" -o ens6 -m comment --comment SM-LAN-MASQ -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -s "$LAN_CIDR" -o ens6 -m comment --comment SM-LAN-MASQ -j MASQUERADE
  iptables -C FORWARD -s "$LAN_CIDR" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -s "$LAN_CIDR" -j ACCEPT
  iptables -C FORWARD -d "$LAN_CIDR" -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -d "$LAN_CIDR" -j ACCEPT
}

preserve_lan_src_on_flint() {
  # Best-effort: stop Flint from MASQing all LAN onto 10.9.0.2 so VPS sees real IPs.
  local envf=/opt/wireguard/port-forward-ui.env
  [[ -f "$envf" ]] || return 0
  local pass
  pass="$(python3 - <<PY
from pathlib import Path
import base64
text = Path("$envf").read_text(encoding="utf-8")
b64 = pass_ = ""
for line in text.splitlines():
    if line.startswith("ROUTER_PASS_B64="):
        b64 = line.split("=",1)[1].strip().strip('"').strip("'")
    if line.startswith("ROUTER_PASS=") and not line.startswith("ROUTER_PASS_B64"):
        pass_ = line.split("=",1)[1].strip().strip('"').strip("'")
if b64:
    print(base64.b64decode(b64).decode())
elif pass_:
    print(pass_)
PY
)"
  [[ -n "$pass" ]] || return 0
  command -v sshpass >/dev/null 2>&1 || return 0
  export SSHPASS="$pass"
  for host in 10.9.0.2 192.168.8.1; do
    if sshpass -e ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password \
      -o PubkeyAuthentication=no -o ConnectTimeout=12 "root@${host}" 'sh -s' <<'FLINT'
set -e
# Delete blanket LAN→ovpn MASQ (keep portal VIP /host-specific MASQ comments).
iptables -t nat -D POSTROUTING -s 192.168.8.0/24 -o ovpnclient1 -j MASQUERADE 2>/dev/null || true
# Drop unannotated catch-all MASQ out ovpnclient1 (duplicates).
while iptables -t nat -C POSTROUTING -o ovpnclient1 -j MASQUERADE 2>/dev/null; do
  iptables -t nat -D POSTROUTING -o ovpnclient1 -j MASQUERADE || break
done
# Persist
mkdir -p /etc/firewall.user.d
cat >/etc/firewall.user.d/sm-lan-preserve-src.sh <<'EOF'
#!/bin/sh
# Keep LAN source IPs across OVPN so VPS can split circle→Xray / guest→sing-box.
iptables -t nat -D POSTROUTING -s 192.168.8.0/24 -o ovpnclient1 -j MASQUERADE 2>/dev/null || true
while iptables -t nat -C POSTROUTING -o ovpnclient1 -j MASQUERADE 2>/dev/null; do
  iptables -t nat -D POSTROUTING -o ovpnclient1 -j MASQUERADE || break
done
EOF
chmod +x /etc/firewall.user.d/sm-lan-preserve-src.sh
grep -q sm-lan-preserve-src /etc/firewall.user 2>/dev/null || \
  echo '[ -f /etc/firewall.user.d/sm-lan-preserve-src.sh ] && . /etc/firewall.user.d/sm-lan-preserve-src.sh' >> /etc/firewall.user
echo "flint: LAN source preserve OK"
FLINT
    then
      return 0
    fi
  done
  echo "warn: could not update Flint MASQ (VPS rules still applied)" >&2
}

ensure_proxies
sync_ipsets
install_split_rules
preserve_lan_src_on_flint
echo "lan-proxy-split: xray_dokodemo=${XRAY_DOKODEMO_PORT} singbox_redir=${SINGBOX_REDIR_PORT}"
iptables -t nat -S PREROUTING | grep "$COMMENT" | head -20 || true
systemctl is-active sm-xray sm-singbox
