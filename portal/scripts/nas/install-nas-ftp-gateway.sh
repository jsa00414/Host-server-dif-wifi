#!/bin/bash
# Public FTP gateway on VPS for RaiDrive / Windows Explorer.
# Proxies to Buffalo FTP and advertises the VPS public IP for PASV.
set -euo pipefail

ROOT="/opt/wireguard/nas-ftp-gateway"
ENV_FILE="/opt/wireguard/port-forward-ui.env"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Missing $ENV_FILE" >&2
  exit 1
fi

# shellcheck disable=SC1090
set -a
# shellcheck source=/dev/null
source "$ENV_FILE"
set +a

NAS_HOST="${NAS_SMB_HOST:-${FTP_HOST:-192.168.8.159}}"
# Backend login to Buffalo FTP
NAS_BACKEND_USER="${FTP_USER:-${BUFFALO_USER:-admin}}"
# Public login shown in RaiDrive / Explorer
NAS_PUBLIC_USER="${NAS_FTP_PUBLIC_USER:-admin}"
PUBLIC_IP="${NAS_SMB_PUBLIC_IP:-${VPS_PUBLIC_IP:-74.208.76.213}}"
PUBLIC_PORT="${NAS_FTP_PUBLIC_PORT:-2121}"
PASV_START="${NAS_FTP_PASV_START:-50100}"
PASV_END="${NAS_FTP_PASV_END:-50200}"

NAS_PASS="${BUFFALO_PASS:-}"
if [[ -z "$NAS_PASS" && -n "${BUFFALO_PASS_B64:-}" ]]; then
  NAS_PASS="$(BUFFALO_PASS_B64="$BUFFALO_PASS_B64" python3 -c 'import os,base64; print(base64.b64decode(os.environ["BUFFALO_PASS_B64"]).decode())')"
fi
if [[ -z "$NAS_PASS" && -n "${FTP_PASS_B64:-}" ]]; then
  NAS_PASS="$(FTP_PASS_B64="$FTP_PASS_B64" python3 -c 'import os,base64; print(base64.b64decode(os.environ["FTP_PASS_B64"]).decode())')"
fi
if [[ -z "$NAS_PASS" ]]; then
  echo "NAS password not configured" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq unzip curl

# Ubuntu's rclone package is too old for `serve ftp` — install official binary.
if ! /usr/local/bin/rclone serve ftp --help >/dev/null 2>&1; then
  tmp="$(mktemp -d)"
  curl -fsSL https://downloads.rclone.org/rclone-current-linux-amd64.zip -o "$tmp/rclone.zip"
  unzip -qo "$tmp/rclone.zip" -d "$tmp/out"
  BIN="$(find "$tmp/out" -type f -name rclone | head -1)"
  install -m 0755 "$BIN" /usr/local/bin/rclone
  rm -rf "$tmp"
fi
RCLONE=/usr/local/bin/rclone
"$RCLONE" version | head -1

mkdir -p "$ROOT"
chmod 700 "$ROOT"

OBSCURED="$("$RCLONE" obscure "$NAS_PASS")"
cat >"$ROOT/rclone.conf" <<EOF
[buffalo]
type = ftp
host = ${NAS_HOST}
user = ${NAS_BACKEND_USER}
pass = ${OBSCURED}
explicit_tls = false
EOF
chmod 600 "$ROOT/rclone.conf"

cat >"$ROOT/run.sh" <<EOF
#!/bin/bash
set -euo pipefail
ROOT=/opt/wireguard/nas-ftp-gateway
RCLONE=/usr/local/bin/rclone
set -a
# shellcheck disable=SC1091
source /opt/wireguard/port-forward-ui.env
set +a
NAS_BACKEND_USER="\${FTP_USER:-\${BUFFALO_USER:-admin}}"
NAS_PUBLIC_USER="\${NAS_FTP_PUBLIC_USER:-admin}"
NAS_PASS="\${BUFFALO_PASS:-}"
if [[ -z "\$NAS_PASS" && -n "\${BUFFALO_PASS_B64:-}" ]]; then
  NAS_PASS="\$(BUFFALO_PASS_B64="\$BUFFALO_PASS_B64" python3 -c 'import os,base64; print(base64.b64decode(os.environ["BUFFALO_PASS_B64"]).decode())')"
fi
PUBLIC_IP="\${NAS_SMB_PUBLIC_IP:-\${VPS_PUBLIC_IP:-74.208.76.213}}"
PUBLIC_PORT="\${NAS_FTP_PUBLIC_PORT:-2121}"
PASV_START="\${NAS_FTP_PASV_START:-50100}"
PASV_END="\${NAS_FTP_PASV_END:-50200}"
exec "\$RCLONE" serve ftp buffalo: \\
  --config "\$ROOT/rclone.conf" \\
  --addr "0.0.0.0:\${PUBLIC_PORT}" \\
  --user "\$NAS_PUBLIC_USER" \\
  --pass "\$NAS_PASS" \\
  --passive-port "\${PASV_START}-\${PASV_END}" \\
  --public-ip "\$PUBLIC_IP" \\
  --vfs-cache-mode writes \\
  --dir-cache-time 30s
EOF
chmod 700 "$ROOT/run.sh"

install -m 0644 "$SCRIPT_DIR/nas-ftp-gateway.service" /etc/systemd/system/nas-ftp-gateway.service

if command -v ufw >/dev/null 2>&1; then
  ufw allow "${PUBLIC_PORT}/tcp" comment "nas-ftp-gateway" >/dev/null || true
  ufw allow "${PASV_START}:${PASV_END}/tcp" comment "nas-ftp-pasv" >/dev/null || true
fi

systemctl daemon-reload
systemctl enable nas-ftp-gateway.service
systemctl restart nas-ftp-gateway.service
sleep 2

if ! systemctl is-active --quiet nas-ftp-gateway.service; then
  journalctl -u nas-ftp-gateway.service -n 40 --no-pager || true
  exit 1
fi

export NAS_PUBLIC_USER NAS_PASS PUBLIC_PORT
python3 - <<'PY'
import ftplib, os
port = int(os.environ["PUBLIC_PORT"])
user = os.environ["NAS_PUBLIC_USER"]
pw = os.environ["NAS_PASS"]
ftp = ftplib.FTP()
ftp.connect("127.0.0.1", port, timeout=20)
ftp.login(user, pw)
ftp.set_pasv(True)
print("gateway pwd", ftp.pwd())
names = []
ftp.retrlines("NLST", names.append)
print("entries", len(names), names[:8])
ftp.quit()
print(f"NAS FTP gateway OK on 0.0.0.0:{port} user={user}")
PY
