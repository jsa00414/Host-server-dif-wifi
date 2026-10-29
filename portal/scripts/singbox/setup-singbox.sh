#!/usr/bin/env bash
# ServerManager — sing-box (VLESS + REALITY) for guest-DNS users.
# Internet-only exit; DNS forced to guest AdGuard/Unbound VIP (10.42.42.45).
# Private LAN is blocked. Client UUIDs are issued via portal login.
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

SINGBOX_DIR="${SINGBOX_DIR:-/opt/singbox}"
SINGBOX_BIN="${SINGBOX_BIN:-/usr/local/bin/sing-box}"
SINGBOX_PORT="${SINGBOX_PORT:-8445}"
SINGBOX_HOST="${SINGBOX_HOST:-vpn.vpstruelord.com}"
SINGBOX_SNI="${SINGBOX_SNI:-www.microsoft.com}"
SINGBOX_DEST_HOST="${SINGBOX_DEST_HOST:-${SINGBOX_SNI}}"
SINGBOX_DEST_PORT="${SINGBOX_DEST_PORT:-443}"
# Transparent redirect for Flint LAN guest users (iptables REDIRECT).
SINGBOX_REDIR_PORT="${SINGBOX_REDIR_PORT:-18081}"
GUEST_DNS="${VPN_GUEST_DNS:-${SINGBOX_GUEST_DNS:-10.42.42.45}}"
CLIENTS_FILE="${SINGBOX_CLIENTS_FILE:-$SINGBOX_DIR/clients.json}"
KEYS_FILE="${SINGBOX_KEYS_FILE:-$SINGBOX_DIR/reality.keys}"
CONFIG_FILE="${SINGBOX_CONFIG_FILE:-$SINGBOX_DIR/config.json}"
ENV_FILE="${PORTAL_ENV_FILE:-/opt/wireguard/port-forward-ui.env}"

mkdir -p "$SINGBOX_DIR" "$SINGBOX_DIR/logs"
chmod 750 "$SINGBOX_DIR"

install_singbox_binary() {
  if [[ -x "$SINGBOX_BIN" ]]; then
    ver="$("$SINGBOX_BIN" version 2>/dev/null | head -1 || true)"
    echo "sing-box binary present: ${ver:-unknown}"
    return 0
  fi
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) asset_arch="amd64" ;;
    aarch64|arm64) asset_arch="arm64" ;;
    *) echo "unsupported arch: $arch" >&2; return 1 ;;
  esac
  tag="$(curl -fsSL https://api.github.com/repos/SagerNet/sing-box/releases/latest \
    | python3 -c 'import sys,json; print(json.load(sys.stdin).get("tag_name",""))')"
  [[ -n "$tag" ]] || { echo "failed to resolve sing-box release" >&2; return 1; }
  ver="${tag#v}"
  url="https://github.com/SagerNet/sing-box/releases/download/${tag}/sing-box-${ver}-linux-${asset_arch}.tar.gz"
  echo "downloading $url"
  curl -fsSL -o "$tmp/sing-box.tgz" "$url"
  tar -xzf "$tmp/sing-box.tgz" -C "$tmp"
  bin="$(find "$tmp" -type f -name sing-box | head -1)"
  [[ -n "$bin" && -x "$bin" ]] || { echo "sing-box binary missing from archive" >&2; return 1; }
  install -m 0755 "$bin" "$SINGBOX_BIN"
  echo "installed $("$SINGBOX_BIN" version | head -1)"
}

ensure_keys() {
  if [[ -f "$KEYS_FILE" ]] && grep -q '^private:' "$KEYS_FILE" && grep -q '^public:' "$KEYS_FILE"; then
    return 0
  fi
  out="$("$SINGBOX_BIN" generate reality-keypair)"
  priv="$(printf '%s\n' "$out" | awk -F': ' '/[Pp]rivate/{print $2; exit}')"
  pub="$(printf '%s\n' "$out" | awk -F': ' '/[Pp]ublic/{print $2; exit}')"
  short="$("$SINGBOX_BIN" generate rand --hex 8 2>/dev/null || openssl rand -hex 4)"
  [[ -n "$priv" && -n "$pub" && -n "$short" ]] || { echo "failed to generate REALITY keys" >&2; return 1; }
  cat >"$KEYS_FILE" <<EOF
private:$priv
public:$pub
short_id:$short
EOF
  chmod 600 "$KEYS_FILE"
  echo "wrote $KEYS_FILE"
}

ensure_clients_seed() {
  if [[ -f "$CLIENTS_FILE" ]]; then
    return 0
  fi
  uuid="$("$SINGBOX_BIN" generate uuid)"
  python3 - <<PY
import json, time
from pathlib import Path
now = int(time.time())
data = {
  "clients": [
    {
      "name": "guest-default",
      "uuid": "$uuid",
      "created_at": now,
      "note": "seed client for guest-DNS users",
      "guest": True,
    }
  ]
}
Path("$CLIENTS_FILE").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
PY
  chmod 600 "$CLIENTS_FILE"
  echo "seeded $CLIENTS_FILE"
}

write_config() {
  export SINGBOX_DIR SINGBOX_PORT SINGBOX_HOST SINGBOX_SNI SINGBOX_DEST_HOST SINGBOX_DEST_PORT
  export SINGBOX_REDIR_PORT GUEST_DNS CLIENTS_FILE KEYS_FILE CONFIG_FILE SINGBOX_BIN
  python3 - <<'PY'
import json
import os
import re
from pathlib import Path

keys = {}
for line in Path(os.environ["KEYS_FILE"]).read_text(encoding="utf-8").splitlines():
    if ":" not in line:
        continue
    k, v = line.split(":", 1)
    keys[k.strip()] = v.strip()
priv = keys.get("private", "")
short_id = keys.get("short_id", "")
if not priv or not short_id:
    raise SystemExit("missing reality private/short_id")

clients_raw = json.loads(Path(os.environ["CLIENTS_FILE"]).read_text(encoding="utf-8"))
users = []
for row in clients_raw.get("clients") or []:
    if not isinstance(row, dict):
        continue
    uuid = str(row.get("uuid") or "").strip()
    name = re.sub(r"[^a-zA-Z0-9._-]+", "-", str(row.get("name") or "guest").strip())[:64] or "guest"
    if not uuid:
        continue
    users.append({"name": name, "uuid": uuid})

port = int(os.environ.get("SINGBOX_PORT", "8445"))
redir_port = int(os.environ.get("SINGBOX_REDIR_PORT", "18081"))
sni = os.environ.get("SINGBOX_SNI", "www.microsoft.com")
dest_host = os.environ.get("SINGBOX_DEST_HOST", sni)
dest_port = int(os.environ.get("SINGBOX_DEST_PORT", "443") or "443")
guest_dns = os.environ.get("GUEST_DNS", "10.42.42.45")
log_dir = Path(os.environ["SINGBOX_DIR"]) / "logs"

cfg = {
    "log": {
        "level": "warn",
        "timestamp": True,
        "output": str(log_dir / "sing-box.log"),
    },
    # sing-box 1.12+ DNS server objects (type/server); legacy "address" removed in 1.14.
    "dns": {
        "servers": [
            {
                "type": "udp",
                "tag": "guest",
                "server": guest_dns,
                "server_port": 53,
            }
        ],
        "final": "guest",
        "strategy": "prefer_ipv4",
    },
    "inbounds": [
        {
            "type": "vless",
            "tag": "vless-reality-guest",
            "listen": "0.0.0.0",
            "listen_port": port,
            "users": users,
            "tls": {
                "enabled": True,
                "server_name": sni,
                "reality": {
                    "enabled": True,
                    "handshake": {
                        "server": dest_host,
                        "server_port": dest_port,
                    },
                    "private_key": priv,
                    "short_id": [short_id],
                },
            },
        },
        {
            "type": "redirect",
            "tag": "redir-lan-guest",
            "listen": "127.0.0.1",
            "listen_port": redir_port,
        },
    ],
    "outbounds": [
        {"type": "direct", "tag": "direct"},
        {"type": "block", "tag": "block"},
    ],
    "route": {
        "rules": [
            {"action": "sniff"},
            {"protocol": "dns", "action": "hijack-dns"},
            {"inbound": ["redir-lan-guest"], "outbound": "direct"},
            {"ip_is_private": True, "outbound": "block"},
        ],
        "final": "direct",
        "auto_detect_interface": True,
    },
}
Path(os.environ["CONFIG_FILE"]).write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
os.chmod(os.environ["CONFIG_FILE"], 0o600)
# Validate before systemd picks it up.
import subprocess
subprocess.run(
    [os.environ["SINGBOX_BIN"], "check", "-c", os.environ["CONFIG_FILE"]],
    check=True,
)
print(
    f"wrote {os.environ['CONFIG_FILE']} users={len(users)} "
    f"guest_dns={guest_dns} redir={redir_port}"
)
PY
}

write_systemd() {
  cat >/etc/systemd/system/sm-singbox.service <<EOF
[Unit]
Description=ServerManager sing-box (VLESS REALITY guest DNS)
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=$SINGBOX_BIN run -c $CONFIG_FILE
Restart=on-failure
RestartSec=2
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable sm-singbox.service >/dev/null
}

write_env_hints() {
  [[ -f "$ENV_FILE" ]] || return 0
  python3 - <<PY
from pathlib import Path
p = Path("$ENV_FILE")
text = p.read_text(encoding="utf-8")
lines = text.splitlines()
wanted = {
    "SINGBOX_DIR": "$SINGBOX_DIR",
    "SINGBOX_PORT": "$SINGBOX_PORT",
    "SINGBOX_HOST": "$SINGBOX_HOST",
    "SINGBOX_SNI": "$SINGBOX_SNI",
    "SINGBOX_GUEST_DNS": "$GUEST_DNS",
    "SINGBOX_PUBLIC_KEY": "",
}
for line in Path("$KEYS_FILE").read_text().splitlines():
    if line.startswith("public:"):
        wanted["SINGBOX_PUBLIC_KEY"] = line.split(":", 1)[1].strip()
out = []
seen = set()
for line in lines:
    if "=" in line and not line.strip().startswith("#"):
        k = line.split("=", 1)[0].strip()
        if k in wanted:
            out.append(f'{k}="{wanted[k]}"')
            seen.add(k)
            continue
    out.append(line)
for k, v in wanted.items():
    if k not in seen and v != "":
        out.append(f'{k}="{v}"')
p.write_text("\n".join(out) + "\n", encoding="utf-8")
print(f"updated {p}")
PY
}

open_firewall() {
  if command -v ufw >/dev/null 2>&1; then
    ufw allow "${SINGBOX_PORT}/tcp" comment "sing-box VLESS REALITY guest" >/dev/null 2>&1 || true
  fi
  iptables -C INPUT -p tcp --dport "$SINGBOX_PORT" -m comment --comment SM-SINGBOX -j ACCEPT 2>/dev/null \
    || iptables -I INPUT 1 -p tcp --dport "$SINGBOX_PORT" -m comment --comment SM-SINGBOX -j ACCEPT
}

install_singbox_binary
ensure_keys
ensure_clients_seed
write_config
write_systemd
write_env_hints
open_firewall
systemctl restart sm-singbox.service
systemctl --no-pager --full status sm-singbox.service | head -20
echo "sing-box guest ready on ${SINGBOX_HOST}:${SINGBOX_PORT} dns=${GUEST_DNS}"
