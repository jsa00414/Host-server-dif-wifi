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
  # chains overwrite it.
  for chain in SM-TS-VPN-EXIT SM-SS-VPN-EXIT; do
    iptables -t mangle -nL "$chain" >/dev/null 2>&1 || continue
    # Remove prior skip rules then re-insert at top.
    while iptables -t mangle -D "$chain" -m comment --comment "$COMMENT-SKIP" -j RETURN 2>/dev/null; do :; done
    iptables -t mangle -I "$chain" 1 -m mark ! --mark 0x0/0xffffffff -m comment --comment "$COMMENT-SKIP" -j RETURN 2>/dev/null || true
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
  tailscale set --exit-node="$exit_ip" --exit-node-allow-lan-access=true 2>&1 || true
  if [ -x "$TS_HOST_PROTECT" ]; then
    "$TS_HOST_PROTECT" protect-only 2>/dev/null || true
  fi
  ip route flush table "$TS_TABLE" 2>/dev/null || true
  ip route add default dev "$TS_IFACE" table "$TS_TABLE" 2>/dev/null || true
  ip rule add priority 150 fwmark "$TS_MARK" lookup "$TS_TABLE" 2>/dev/null || true
  iptables -t nat -C POSTROUTING -o "$TS_IFACE" -m mark --mark "$TS_MARK" -m comment --comment "$COMMENT" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -I POSTROUTING 1 -o "$TS_IFACE" -m mark --mark "$TS_MARK" -m comment --comment "$COMMENT" -j MASQUERADE
  echo "ts-backend $exit_ip ok"
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
