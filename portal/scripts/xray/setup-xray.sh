#!/usr/bin/env bash
# ServerManager — Xray-core (VLESS + REALITY) for trust-circle users.
# Public inbound (UUID auth). Client links are issued only via portal login.
set -euo pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

XRAY_DIR="${XRAY_DIR:-/opt/xray}"
XRAY_BIN="${XRAY_BIN:-/usr/local/bin/xray}"
XRAY_PORT="${XRAY_PORT:-8444}"
XRAY_HOST="${XRAY_HOST:-vpn.vpstruelord.com}"
XRAY_SNI="${XRAY_SNI:-www.microsoft.com}"
XRAY_DEST="${XRAY_DEST:-www.microsoft.com:443}"
CLIENTS_FILE="${XRAY_CLIENTS_FILE:-$XRAY_DIR/clients.json}"
KEYS_FILE="${XRAY_KEYS_FILE:-$XRAY_DIR/reality.keys}"
CONFIG_FILE="${XRAY_CONFIG_FILE:-$XRAY_DIR/config.json}"
ENV_FILE="${PORTAL_ENV_FILE:-/opt/wireguard/port-forward-ui.env}"

mkdir -p "$XRAY_DIR" "$XRAY_DIR/logs"
chmod 750 "$XRAY_DIR"

install_xray_binary() {
  if [[ -x "$XRAY_BIN" ]]; then
    ver="$("$XRAY_BIN" version 2>/dev/null | head -1 || true)"
    echo "xray binary present: ${ver:-unknown}"
    return 0
  fi
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) asset="Xray-linux-64.zip" ;;
    aarch64|arm64) asset="Xray-linux-arm64-v8a.zip" ;;
    *) echo "unsupported arch: $arch" >&2; return 1 ;;
  esac
  tag="$(curl -fsSL https://api.github.com/repos/XTLS/Xray-core/releases/latest \
    | python3 -c 'import sys,json; print(json.load(sys.stdin).get("tag_name",""))')"
  [[ -n "$tag" ]] || { echo "failed to resolve Xray release" >&2; return 1; }
  url="https://github.com/XTLS/Xray-core/releases/download/${tag}/${asset}"
  echo "downloading $url"
  curl -fsSL -o "$tmp/xray.zip" "$url"
  python3 - <<PY
import zipfile
from pathlib import Path
z = zipfile.ZipFile("$tmp/xray.zip")
z.extractall("$tmp/out")
PY
  install -m 0755 "$tmp/out/xray" "$XRAY_BIN"
  mkdir -p /usr/local/share/xray
  [[ -f "$tmp/out/geoip.dat" ]] && install -m 0644 "$tmp/out/geoip.dat" /usr/local/share/xray/geoip.dat
  [[ -f "$tmp/out/geosite.dat" ]] && install -m 0644 "$tmp/out/geosite.dat" /usr/local/share/xray/geosite.dat
  echo "installed $("$XRAY_BIN" version | head -1)"
}

ensure_keys() {
  if [[ -f "$KEYS_FILE" ]] && grep -q '^private:' "$KEYS_FILE" && grep -q '^public:' "$KEYS_FILE"; then
    return 0
  fi
  # xray x25519 prints: Private key: ... / Public key: ...
  out="$("$XRAY_BIN" x25519)"
  priv="$(printf '%s\n' "$out" | awk -F': ' '/[Pp]rivate/{print $2; exit}')"
  pub="$(printf '%s\n' "$out" | awk -F': ' '/[Pp]ublic/{print $2; exit}')"
  short="$(openssl rand -hex 4)"
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
  uuid="$("$XRAY_BIN" uuid)"
  python3 - <<PY
import json, time
from pathlib import Path
now = int(time.time())
data = {
  "clients": [
    {
      "name": "circle-default",
      "uuid": "$uuid",
      "created_at": now,
      "note": "seed client for trust-circle users",
      "circle": True,
    }
  ]
}
Path("$CLIENTS_FILE").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
PY
  chmod 600 "$CLIENTS_FILE"
  echo "seeded $CLIENTS_FILE"
}

write_config() {
  export XRAY_DIR XRAY_PORT XRAY_HOST XRAY_SNI XRAY_DEST CLIENTS_FILE KEYS_FILE CONFIG_FILE XRAY_BIN
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
clients = []
for row in clients_raw.get("clients") or []:
    if not isinstance(row, dict):
        continue
    uuid = str(row.get("uuid") or "").strip()
    name = re.sub(r"[^a-zA-Z0-9._-]+", "-", str(row.get("name") or "client").strip())[:64] or "client"
    if not uuid:
        continue
    clients.append({"id": uuid, "email": name, "flow": ""})

port = int(os.environ.get("XRAY_PORT", "8444"))
sni = os.environ.get("XRAY_SNI", "www.microsoft.com")
dest = os.environ.get("XRAY_DEST", "www.microsoft.com:443")
cfg = {
    "log": {
        "loglevel": "warning",
        "access": str(Path(os.environ["XRAY_DIR"]) / "logs" / "access.log"),
        "error": str(Path(os.environ["XRAY_DIR"]) / "logs" / "error.log"),
    },
    "inbounds": [
        {
            "tag": "vless-reality",
            "listen": "0.0.0.0",
            "port": port,
            "protocol": "vless",
            "settings": {
                "clients": clients,
                "decryption": "none",
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": False,
                    "dest": dest,
                    "xver": 0,
                    "serverNames": [sni],
                    "privateKey": priv,
                    "shortIds": [short_id],
                },
            },
            "sniffing": {
                "enabled": True,
                "destOverride": ["http", "tls", "quic"],
            },
        }
    ],
    "outbounds": [
        {"protocol": "freedom", "tag": "direct"},
        {"protocol": "blackhole", "tag": "block"},
    ],
    "routing": {
        "domainStrategy": "AsIs",
        "rules": [
            {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
        ],
    },
}
Path(os.environ["CONFIG_FILE"]).write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
os.chmod(os.environ["CONFIG_FILE"], 0o600)
print(f"wrote {os.environ['CONFIG_FILE']} clients={len(clients)}")
PY
}

write_systemd() {
  cat >/etc/systemd/system/sm-xray.service <<EOF
[Unit]
Description=ServerManager Xray (VLESS REALITY)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$XRAY_BIN run -config $CONFIG_FILE
Restart=on-failure
RestartSec=2
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable sm-xray.service >/dev/null
}

write_env_hints() {
  [[ -f "$ENV_FILE" ]] || return 0
  python3 - <<PY
from pathlib import Path
p = Path("$ENV_FILE")
text = p.read_text(encoding="utf-8")
lines = text.splitlines()
wanted = {
    "XRAY_DIR": "$XRAY_DIR",
    "XRAY_PORT": "$XRAY_PORT",
    "XRAY_HOST": "$XRAY_HOST",
    "XRAY_SNI": "$XRAY_SNI",
    "XRAY_PUBLIC_KEY": "",
}
# fill public key from keys file
for line in Path("$KEYS_FILE").read_text().splitlines():
    if line.startswith("public:"):
        wanted["XRAY_PUBLIC_KEY"] = line.split(":", 1)[1].strip()
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
    ufw allow "${XRAY_PORT}/tcp" comment "Xray VLESS REALITY circle" >/dev/null 2>&1 || true
  fi
  # iptables fallback idempotent accept
  iptables -C INPUT -p tcp --dport "$XRAY_PORT" -m comment --comment SM-XRAY -j ACCEPT 2>/dev/null \
    || iptables -I INPUT 1 -p tcp --dport "$XRAY_PORT" -m comment --comment SM-XRAY -j ACCEPT
}

install_xray_binary
ensure_keys
ensure_clients_seed
write_config
write_systemd
write_env_hints
open_firewall
systemctl restart sm-xray.service
systemctl --no-pager --full status sm-xray.service | head -20
echo "xray ready on :${XRAY_PORT} (VLESS REALITY SNI=${XRAY_SNI})"
