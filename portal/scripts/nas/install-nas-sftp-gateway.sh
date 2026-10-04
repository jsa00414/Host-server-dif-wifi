#!/bin/bash
# VPN/LAN SFTP gateway on the VPS for WinSCP / FileZilla / macOS / rclone.
# Proxies to Buffalo FTP backend via rclone (same backend as FTP/WebDAV gateways).
set -euo pipefail

ROOT="/opt/wireguard/nas-sftp-gateway"
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
NAS_BACKEND_USER="${FTP_USER:-${BUFFALO_USER:-admin}}"
NAS_PUBLIC_USER="${NAS_SFTP_PUBLIC_USER:-${NAS_FTP_PUBLIC_USER:-admin}}"
PUBLIC_PORT="${NAS_SFTP_PUBLIC_PORT:-2123}"

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
if ! /usr/local/bin/rclone serve sftp --help >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y -qq unzip curl
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

# Stable host key so clients don't get fingerprint churn on every restart.
if [[ ! -f "$ROOT/ssh_host_ed25519_key" ]]; then
  ssh-keygen -t ed25519 -f "$ROOT/ssh_host_ed25519_key" -N "" -C "nas-sftp-gateway" >/dev/null
  chmod 600 "$ROOT/ssh_host_ed25519_key"
fi

OBSCURED="$("$RCLONE" obscure "$NAS_PASS")"
if [[ -f /opt/wireguard/nas-ftp-gateway/rclone.conf ]]; then
  cp /opt/wireguard/nas-ftp-gateway/rclone.conf "$ROOT/rclone.conf"
else
  cat >"$ROOT/rclone.conf" <<EOF
[buffalo]
type = ftp
host = ${NAS_HOST}
user = ${NAS_BACKEND_USER}
pass = ${OBSCURED}
explicit_tls = false
EOF
fi
chmod 600 "$ROOT/rclone.conf"

cat >"$ROOT/run.sh" <<EOF
#!/bin/bash
set -euo pipefail
ROOT=/opt/wireguard/nas-sftp-gateway
RCLONE=/usr/local/bin/rclone
set -a
# shellcheck disable=SC1091
source /opt/wireguard/port-forward-ui.env
set +a
NAS_PUBLIC_USER="\${NAS_SFTP_PUBLIC_USER:-\${NAS_FTP_PUBLIC_USER:-admin}}"
NAS_PASS="\${BUFFALO_PASS:-}"
if [[ -z "\$NAS_PASS" && -n "\${BUFFALO_PASS_B64:-}" ]]; then
  NAS_PASS="\$(BUFFALO_PASS_B64="\$BUFFALO_PASS_B64" python3 -c 'import os,base64; print(base64.b64decode(os.environ["BUFFALO_PASS_B64"]).decode())')"
fi
PUBLIC_PORT="\${NAS_SFTP_PUBLIC_PORT:-2123}"
# Disable host authorized_keys so password auth is used (rclone defaults to ~/.ssh/authorized_keys).
: > "\$ROOT/authorized_keys.empty"
exec "\$RCLONE" serve sftp buffalo: \\
  --config "\$ROOT/rclone.conf" \\
  --addr "0.0.0.0:\${PUBLIC_PORT}" \\
  --user "\$NAS_PUBLIC_USER" \\
  --pass "\$NAS_PASS" \\
  --key "\$ROOT/ssh_host_ed25519_key" \\
  --authorized-keys "\$ROOT/authorized_keys.empty" \\
  --vfs-cache-mode writes \\
  --dir-cache-time 30s
EOF
chmod 700 "$ROOT/run.sh"

install -m 0644 "$SCRIPT_DIR/nas-sftp-gateway.service" /etc/systemd/system/nas-sftp-gateway.service

# Prefer shared VPN-only hardener when present.
HARDEN_NAS="${SCRIPT_DIR}/../security/harden-nas-gateways-vpn-only.sh"
if [[ -x "$HARDEN_NAS" ]]; then
  NAS_SFTP_PUBLIC_PORT="$PUBLIC_PORT" bash "$HARDEN_NAS" || true
elif command -v ufw >/dev/null 2>&1; then
  while ufw status numbered 2>/dev/null | grep -E "\[.*\] ${PUBLIC_PORT}/tcp.*Anywhere" >/dev/null; do
    num="$(ufw status numbered | sed -n "s/^\[ *\([0-9][0-9]*\)\] ${PUBLIC_PORT}\/tcp.*Anywhere.*/\1/p" | tail -1)"
    [[ -z "$num" ]] && break
    ufw --force delete "$num" >/dev/null || break
  done
  for src in 10.8.0.0/24 10.9.0.0/24 100.64.0.0/10 192.168.8.0/24 10.42.42.0/24 172.16.0.0/12; do
    ufw allow from "$src" to any port "${PUBLIC_PORT}" proto tcp comment "nas-sftp-vpn" >/dev/null || true
  done
fi

systemctl daemon-reload
systemctl enable nas-sftp-gateway.service
systemctl restart nas-sftp-gateway.service
sleep 2

if ! systemctl is-active --quiet nas-sftp-gateway.service; then
  journalctl -u nas-sftp-gateway.service -n 40 --no-pager || true
  exit 1
fi

export NAS_PUBLIC_USER NAS_PASS PUBLIC_PORT
ok=0
if command -v python3 >/dev/null 2>&1; then
  if ! dpkg -s python3-paramiko >/dev/null 2>&1; then
    apt-get install -y -qq python3-paramiko >/dev/null 2>&1 || true
  fi
  if dpkg -s python3-paramiko >/dev/null 2>&1; then
    if NAS_PUBLIC_USER="$NAS_PUBLIC_USER" NAS_PASS="$NAS_PASS" PUBLIC_PORT="$PUBLIC_PORT" python3 - <<'PY'
import os, paramiko
port=int(os.environ["PUBLIC_PORT"]); user=os.environ["NAS_PUBLIC_USER"]; pw=os.environ["NAS_PASS"]
t=paramiko.Transport(("127.0.0.1", port)); t.connect(username=user, password=pw)
s=paramiko.SFTPClient.from_transport(t); print("entries", s.listdir(".")[:8]); s.close(); t.close()
PY
    then
      ok=1
    fi
  fi
fi
if [[ "$ok" -ne 1 ]]; then
  if timeout 3 bash -c "echo >/dev/tcp/127.0.0.1/${PUBLIC_PORT}"; then
    echo "NAS SFTP gateway listening on 0.0.0.0:${PUBLIC_PORT} user=${NAS_PUBLIC_USER} (list probe skipped)"
  else
    journalctl -u nas-sftp-gateway.service -n 40 --no-pager || true
    exit 1
  fi
else
  echo "NAS SFTP gateway OK on 0.0.0.0:${PUBLIC_PORT} user=${NAS_PUBLIC_USER}"
fi
