#!/bin/bash
# Per-device VPN internet exit: mark one client IPv4 toward Surfshark or Tailscale.
# Does NOT disable the other global exit — only overrides the listed /32s.
set -uo pipefail

STATE_JSON="${DEVICE_EXIT_STATE:-/opt/servermanager/panel/device-exit.json}"
SS_MANAGE="${SS_MANAGE:-/opt/surfshark/ss-manage.sh}"
SS_STATE="${SS_VPN_EXIT_STATE:-/opt/surfshark/ss-vpn-exit.state}"
TS_STATE="${TS_VPN_EXIT_STATE:-/opt/dns/ts-vpn-exit.state}"
TS_HOST_PROTECT="${TS_HOST_PROTECT:-/opt/dns/ts-host-protect.sh}"

CHAIN="SM-DEVICE-EXIT"
COMMENT="SM-DEV-EXIT"
TS_MARK="0x174"
SS_MARK="0x184"
DIRECT_MARK="0x170"
TS_TABLE="52"
SS_TABLE="53"
TS_IFACE="tailscale0"
# Flint site-to-site SNATs home LAN onto this OVPN VIP before packets hit the VPS.
# Per-LAN /32 marks alone never match Wi‑Fi Circle devices — also mark the VIP.
FLINT_OVPN_IP="${FLINT_OVPN_IP:-10.9.0.2}"
TS_EXIT_DNS="${TS_EXIT_DNS:-/opt/dns/ts-exit-dns.sh}"

ACTION="${1:-status}"
IP="${2:-}"
PROVIDER="${3:-}"
EXTRA="${4:-}"

PUBLIC_IP="$(ip -4 -o addr show dev ens6 2>/dev/null | awk '{print $4}' | head -1 | cut -d/ -f1)"
PUBLIC_IP="${PUBLIC_IP:-74.208.76.213}"

mkdir -p "$(dirname "$STATE_JSON")"
if [ ! -f "$STATE_JSON" ]; then
  printf '%s\n' '{"devices":{}}' >"$STATE_JSON"
fi

is_ipv4() {
  [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

read_json_devices() {
  python3 - <<'PY'
import json
from pathlib import Path
import os
p = Path(os.environ.get("STATE_JSON", "/opt/servermanager/panel/device-exit.json"))
try:
    data = json.loads(p.read_text(encoding="utf-8"))
except Exception:
    data = {"devices": {}}
devs = data.get("devices") if isinstance(data, dict) else {}
if not isinstance(devs, dict):
    devs = {}
for ip, row in sorted(devs.items()):
    if not isinstance(row, dict):
        continue
    prov = str(row.get("provider") or "").strip().lower()
    if prov not in ("surfshark", "tailscale", "direct"):
        continue
    extra = str(row.get("server") or row.get("exit_ip") or "").strip()
    print(f"{ip}|{prov}|{extra}")
PY
}

write_device() {
  local ip="$1" prov="$2" extra="$3"
  STATE_JSON="$STATE_JSON" IP="$ip" PROV="$prov" EXTRA="$extra" python3 - <<'PY'
import json, os, time
from pathlib import Path
p = Path(os.environ["STATE_JSON"])
ip = os.environ["IP"].strip()
prov = os.environ["PROV"].strip().lower()
extra = os.environ.get("EXTRA", "").strip()
try:
    data = json.loads(p.read_text(encoding="utf-8"))
except Exception:
    data = {"devices": {}}
if not isinstance(data, dict):
    data = {"devices": {}}
devs = data.setdefault("devices", {})
if not isinstance(devs, dict):
    devs = {}
    data["devices"] = devs
if prov in ("", "clear", "default", "off", "none"):
    devs.pop(ip, None)
else:
    row = {"provider": prov, "updated_at": int(time.time())}
    if prov == "surfshark" and extra:
        row["server"] = extra
    if prov == "tailscale" and extra:
        row["exit_ip"] = extra
    devs[ip] = row
data["updated_at"] = int(time.time())
tmp = p.with_suffix(".tmp")
tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
tmp.replace(p)
print(json.dumps({"ok": True, "ip": ip, "provider": prov or "clear", "devices": len(devs)}))
PY
}

ensure_skip_rules() {
  # If a packet already carries a device-exit mark, do not let global subnet
  # chains overwrite it. -D must match the full rule or duplicates pile up.
  for chain in SM-TS-VPN-EXIT SM-SS-VPN-EXIT; do
    iptables -t mangle -nL "$chain" >/dev/null 2>&1 || continue
    while iptables -t mangle -D "$chain" \
      -m mark ! --mark 0x0/0xffffffff \
      -m comment --comment "$COMMENT-SKIP" \
      -j RETURN 2>/dev/null; do :; done
    # Also scrub older incomplete -D matches that left orphan comments.
    while iptables -t mangle -D "$chain" \
      -m comment --comment "$COMMENT-SKIP" \
      -j RETURN 2>/dev/null; do :; done
    iptables -t mangle -I "$chain" 1 \
      -m mark ! --mark 0x0/0xffffffff \
      -m comment --comment "$COMMENT-SKIP" \
      -j RETURN 2>/dev/null || true
  done
}

del_device_chain() {
  while iptables -t mangle -D PREROUTING -j "$CHAIN" 2>/dev/null; do :; done
  iptables -t mangle -F "$CHAIN" 2>/dev/null || true
  iptables -t mangle -X "$CHAIN" 2>/dev/null || true
}

ensure_ss_backend() {
  local server="$1"
  local ifname=""
  if [ -z "$server" ]; then
    server="$(python3 - <<'PY'
from pathlib import Path
p=Path("/opt/surfshark/ss-vpn-exit.state")
srv=""
if p.is_file():
  for line in p.read_text().splitlines():
    if line.startswith("SERVER=") and line.split("=",1)[1].strip():
      srv=line.split("=",1)[1].strip()
print(srv or "us-nyc")
PY
)"
  fi
  ifname="ss-${server}"
  if ! ip link show "$ifname" >/dev/null 2>&1; then
    if [ -x "$SS_MANAGE" ]; then
      "$SS_MANAGE" connect "$server" 2>&1 || true
    fi
  fi
  if ! ip link show "$ifname" >/dev/null 2>&1; then
    echo "surfshark iface $ifname not up" >&2
    return 1
  fi
  ip route flush table "$SS_TABLE" 2>/dev/null || true
  ip route add default dev "$ifname" table "$SS_TABLE" 2>/dev/null || true
  # Host-protect style main lookups (idempotent priorities used by ss-vpn-exit).
  ip rule add priority 100 from "${PUBLIC_IP}/32" lookup main 2>/dev/null || true
  ip rule add priority 101 to "${PUBLIC_IP}/32" lookup main 2>/dev/null || true
  ip rule add priority 140 fwmark "$SS_MARK" lookup "$SS_TABLE" 2>/dev/null || true
  # SNAT device egress via Surfshark
  iptables -t nat -C POSTROUTING -o "$ifname" -m mark --mark "$SS_MARK" -m comment --comment "$COMMENT" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -I POSTROUTING 1 -o "$ifname" -m mark --mark "$SS_MARK" -m comment --comment "$COMMENT" -j MASQUERADE
  echo "ss-backend $ifname ok"
}

scrub_ts_hostwide_exit_rules() {
  # Best-effort: drop Tailscale's host-wide "from all lookup 52" (prio 5270).
  # tailscaled restores it quickly ("somebody deleted ip rules; restoring"), so
  # durable protection is ensure_ts_host_shadow() — prio 200 → main — which
  # wins over 5270 for unmarked traffic (same pattern as ts-vpn-exit.sh).
  #
  # IMPORTANT: do NOT use `ip rule del from all lookup 52` — iproute2 also
  # matches fwmark→52 rules with that selector and would break device exit.
  TS_TABLE="$TS_TABLE" python3 - <<'PY'
import os, re, subprocess
table = os.environ.get("TS_TABLE", "52")
try:
    out = subprocess.check_output(["ip", "rule", "list"], text=True)
except Exception:
    raise SystemExit(0)
for line in out.splitlines():
    if "fwmark" in line:
        continue
    m = re.match(r"^(\d+):\s+from all lookup (\S+)\s*$", line.strip())
    if m and m.group(2) == table:
        subprocess.run(["ip", "rule", "del", "priority", m.group(1)], check=False)
PY
}

ensure_ts_host_shadow() {
  # Unmarked traffic must hit main before Tailscale's prio 5270 exit table.
  ip rule add priority 200 from all lookup main 2>/dev/null || true
}

clear_ts_backend() {
  # Unset exit node so table 52 cannot blackhole the VPS even if 5270 remains.
  tailscale set --exit-node= --exit-node-allow-lan-access=false 2>/dev/null || true
  scrub_ts_hostwide_exit_rules
  while ip rule del priority 150 2>/dev/null; do :; done
  # Drop our main-shadow only when global ts-vpn-exit is not owning it.
  if ! grep -q '^ENABLED=1' "$TS_STATE" 2>/dev/null; then
    while ip rule del priority 200 2>/dev/null; do :; done
    if [ -x "$TS_EXIT_DNS" ]; then
      "$TS_EXIT_DNS" disable 2>/dev/null || true
    fi
  fi
  ip route flush table "$TS_TABLE" 2>/dev/null || true
  echo "ts-backend cleared"
}

ensure_ts_backend() {
  local exit_ip="$1"
  if [ -z "$exit_ip" ]; then
    exit_ip="$(python3 - <<'PY'
from pathlib import Path
p=Path("/opt/dns/ts-vpn-exit.state")
ip=""
if p.is_file():
  for line in p.read_text().splitlines():
    if line.startswith("EXIT_IP=") and line.split("=",1)[1].strip():
      ip=line.split("=",1)[1].strip()
print(ip or "100.94.32.63")
PY
)"
  fi
  if ! ip link show "$TS_IFACE" >/dev/null 2>&1; then
    echo "tailscale0 missing" >&2
    return 1
  fi
  # Never call `tailscale down` / logout. If the daemon was stopped, bring it
  # back with the known prefs, then set the exit node for mark-based routing.
  local backend
  backend="$(tailscale status --json 2>/dev/null | python3 -c 'import sys,json; print(json.load(sys.stdin).get("BackendState") or "")' 2>/dev/null || true)"
  if [ "$backend" != "Running" ]; then
    tailscale up --accept-dns=false --hostname=vpstruelord-vps 2>&1 || true
  fi
  # Exit node is required so marked packets can leave via tailscale0.
  # Host stays on main via prio 200 shadow (and best-effort 5270 scrub).
  tailscale set --exit-node="$exit_ip" --exit-node-allow-lan-access=true 2>&1 || true
  scrub_ts_hostwide_exit_rules
  if [ -x "$TS_HOST_PROTECT" ]; then
    "$TS_HOST_PROTECT" protect-only 2>/dev/null || true
  fi
  scrub_ts_hostwide_exit_rules
  ip route flush table "$TS_TABLE" 2>/dev/null || true
  ip route add default dev "$TS_IFACE" table "$TS_TABLE" 2>/dev/null || true
  ip rule add priority 150 fwmark "$TS_MARK" lookup "$TS_TABLE" 2>/dev/null || true
  ensure_ts_host_shadow
  iptables -t nat -C POSTROUTING -o "$TS_IFACE" -m mark --mark "$TS_MARK" -m comment --comment "$COMMENT" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -I POSTROUTING 1 -o "$TS_IFACE" -m mark --mark "$TS_MARK" -m comment --comment "$COMMENT" -j MASQUERADE
  scrub_ts_hostwide_exit_rules
  ensure_ts_host_shadow
  # Keep VPN/LAN DNS on AdGuard so lookups don't leak past the exit path.
  if [ -x "$TS_EXIT_DNS" ]; then
    "$TS_EXIT_DNS" enable "$TS_IFACE" 2>/dev/null || true
  fi
  # Nested OVPN→Tailscale exit needs explicit forward + MSS clamp or
  # speedtest/websockets stall after the first HTML load.
  iptables -C FORWARD -i tun0 -o "$TS_IFACE" -m comment --comment "$COMMENT" -j ACCEPT 2>/dev/null \
    || iptables -I FORWARD 1 -i tun0 -o "$TS_IFACE" -m comment --comment "$COMMENT" -j ACCEPT
  iptables -C FORWARD -i "$TS_IFACE" -o tun0 -m state --state RELATED,ESTABLISHED -m comment --comment "$COMMENT" -j ACCEPT 2>/dev/null \
    || iptables -I FORWARD 1 -i "$TS_IFACE" -o tun0 -m state --state RELATED,ESTABLISHED -m comment --comment "$COMMENT" -j ACCEPT
  iptables -t mangle -C FORWARD -o "$TS_IFACE" -p tcp --tcp-flags SYN,RST SYN -m comment --comment "$COMMENT-MSS" -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null \
    || iptables -t mangle -A FORWARD -o "$TS_IFACE" -p tcp --tcp-flags SYN,RST SYN -m comment --comment "$COMMENT-MSS" -j TCPMSS --clamp-mss-to-pmtu
  iptables -t mangle -C FORWARD -i "$TS_IFACE" -p tcp --tcp-flags SYN,RST SYN -m comment --comment "$COMMENT-MSS" -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null \
    || iptables -t mangle -A FORWARD -i "$TS_IFACE" -p tcp --tcp-flags SYN,RST SYN -m comment --comment "$COMMENT-MSS" -j TCPMSS --clamp-mss-to-pmtu
  echo "ts-backend $exit_ip ok (mark-only; host shadowed via prio 200)"
}

apply_rules() {
  export STATE_JSON
  local lines need_ss=0 need_ts=0
  lines="$(STATE_JSON="$STATE_JSON" read_json_devices)"
  del_device_chain
  iptables -t mangle -N "$CHAIN" 2>/dev/null || iptables -t mangle -F "$CHAIN"

  # Private / VPS destinations never take a VPN exit mark.
  iptables -t mangle -A "$CHAIN" -d 10.0.0.0/8 -j RETURN
  iptables -t mangle -A "$CHAIN" -d 172.16.0.0/12 -j RETURN
  iptables -t mangle -A "$CHAIN" -d 192.168.0.0/16 -j RETURN
  iptables -t mangle -A "$CHAIN" -d "${PUBLIC_IP}/32" -j RETURN
  iptables -t mangle -A "$CHAIN" -d 100.64.0.0/10 -j RETURN
  iptables -t mangle -A "$CHAIN" -d 10.11.0.1/32 -j RETURN

  while IFS='|' read -r ip prov extra; do
    [ -n "$ip" ] || continue
    is_ipv4 "$ip" || continue
    case "$prov" in
      surfshark)
        need_ss=1
        iptables -t mangle -A "$CHAIN" -s "${ip}/32" -m comment --comment "$COMMENT" -j MARK --set-mark "$SS_MARK"
        ;;
      tailscale)
        need_ts=1
        iptables -t mangle -A "$CHAIN" -s "${ip}/32" -m comment --comment "$COMMENT" -j MARK --set-mark "$TS_MARK"
        ;;
      direct)
        iptables -t mangle -A "$CHAIN" -s "${ip}/32" -m comment --comment "$COMMENT" -j MARK --set-mark "$DIRECT_MARK"
        ;;
    esac
  done <<<"$lines"

  # Home Wi‑Fi Circle devices are SNATed by Flint to FLINT_OVPN_IP on tun0.
  # Without marking that VIP, Exit only works for direct CCD clients (e.g. 10.9.0.3).
  if [ "$need_ts" -eq 1 ] && is_ipv4 "$FLINT_OVPN_IP"; then
    iptables -t mangle -A "$CHAIN" -s "${FLINT_OVPN_IP}/32" -m comment --comment "$COMMENT-FLINT" -j MARK --set-mark "$TS_MARK"
  elif [ "$need_ss" -eq 1 ] && is_ipv4 "$FLINT_OVPN_IP"; then
    iptables -t mangle -A "$CHAIN" -s "${FLINT_OVPN_IP}/32" -m comment --comment "$COMMENT-FLINT" -j MARK --set-mark "$SS_MARK"
  fi

  # Jump first so device marks win over global SM-TS / SM-SS subnet marks.
  iptables -t mangle -I PREROUTING 1 -j "$CHAIN"
  ensure_skip_rules

  if [ "$need_ss" -eq 1 ]; then
    # Prefer explicit server from first surfshark device, else default.
    local ss_server=""
    while IFS='|' read -r ip prov extra; do
      if [ "$prov" = "surfshark" ] && [ -n "$extra" ]; then
        ss_server="$extra"
        break
      fi
    done <<<"$lines"
    ensure_ss_backend "$ss_server" || true
  fi
  if [ "$need_ts" -eq 1 ]; then
    local ts_exit=""
    while IFS='|' read -r ip prov extra; do
      if [ "$prov" = "tailscale" ] && [ -n "$extra" ]; then
        ts_exit="$extra"
        break
      fi
    done <<<"$lines"
    ensure_ts_backend "$ts_exit" || true
  else
    clear_ts_backend || true
  fi

  echo "applied device-exit ($(echo "$lines" | grep -c . || true) device(s)); need_ss=$need_ss need_ts=$need_ts"
}

status_out() {
  echo "=== state $STATE_JSON ==="
  cat "$STATE_JSON" 2>/dev/null || true
  echo "=== mangle $CHAIN ==="
  iptables -t mangle -S "$CHAIN" 2>/dev/null || echo "(missing)"
  echo "=== prerouting jump ==="
  iptables -t mangle -S PREROUTING 2>/dev/null | grep -E "$CHAIN|$COMMENT" || true
  echo "=== marks/rules ==="
  ip rule | grep -E "0x174|0x184|lookup 52|lookup 53" || true
}

case "$ACTION" in
  set)
    if ! is_ipv4 "$IP"; then
      echo "usage: $0 set <ipv4> <surfshark|tailscale|direct|clear> [server|exit-ip]" >&2
      exit 2
    fi
    case "$PROVIDER" in
      surfshark|tailscale|direct|clear|default|off|none|"") ;;
      *) echo "provider must be surfshark|tailscale|direct|clear" >&2; exit 2 ;;
    esac
    write_device "$IP" "$PROVIDER" "$EXTRA"
    apply_rules
    ;;
  apply|reload)
    apply_rules
    ;;
  clear)
    if ! is_ipv4 "$IP"; then
      echo "usage: $0 clear <ipv4>" >&2
      exit 2
    fi
    write_device "$IP" "clear" ""
    apply_rules
    ;;
  status)
    status_out
    ;;
  *)
    echo "usage: $0 set <ip> <surfshark|tailscale|direct|clear> [extra]|apply|clear <ip>|status" >&2
    exit 2
    ;;
esac
