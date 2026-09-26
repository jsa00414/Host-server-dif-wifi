#!/bin/bash
# Install Samba gateway on the VPS for Windows SMB (portal public route :1445).
set -euo pipefail

ROOT="/opt/wireguard/nas-smb-gateway"
MOUNT="/mnt/nas-gateway"
ENV_FILE="/opt/wireguard/port-forward-ui.env"
FORWARDS="/opt/wireguard/scripts/forwards.conf"
APPLY="/opt/wireguard/scripts/apply-lan-forwards.sh"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Missing $ENV_FILE" >&2
  exit 1
fi

# shellcheck disable=SC1090
set -a
source "$ENV_FILE"
set +a

NAS_HOST="${NAS_SMB_HOST:-${FTP_HOST:-192.168.8.159}}"
NAS_SHARE="${NAS_SMB_SHARE:-share}"
NAS_USER="${FTP_USER:-${BUFFALO_USER:-admin}}"
NAS_PASS="${BUFFALO_PASS:-}"
if [[ -n "${BUFFALO_PASS_B64:-}" ]]; then
  NAS_PASS="$(python3 - <<'PY'
import os, base64
print(base64.b64decode(os.environ["BUFFALO_PASS_B64"]).decode())
PY
)"
fi
if [[ -z "$NAS_PASS" && -n "${NAS_SMB_PASS_B64:-}" ]]; then
  NAS_PASS="$(python3 - <<'PY'
import os, base64
print(base64.b64decode(os.environ["NAS_SMB_PASS_B64"]).decode())
PY
)"
fi
if [[ -z "$NAS_PASS" ]]; then
  echo "NAS password not configured in $ENV_FILE" >&2
  exit 1
fi

PUBLIC_PORT="${NAS_SMB_PUBLIC_PORT:-1445}"
GATEWAY_PORT="${NAS_SMB_GATEWAY_PORT:-14450}"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq samba cifs-utils keyutils

mkdir -p "$ROOT" "$MOUNT"
chmod 755 "$ROOT" "$MOUNT"

if ! id "$NAS_USER" &>/dev/null; then
  if getent group "$NAS_USER" >/dev/null; then
    useradd -M -s /usr/sbin/nologin -g "$NAS_USER" "$NAS_USER"
  else
    useradd -M -s /usr/sbin/nologin "$NAS_USER"
  fi
fi

export NAS_USER NAS_PASS
python3 - <<'PY'
import os
from pathlib import Path
root = Path("/opt/wireguard/nas-smb-gateway")
user = os.environ["NAS_USER"]
password = os.environ["NAS_PASS"]
root.joinpath("credentials").write_text(
    f"username={user}\npassword={password}\ndomain=WORKGROUP\n",
    encoding="utf-8",
)
PY
chmod 600 "$ROOT/credentials"

install -m 0644 "$SCRIPT_DIR/smb-gateway.smb.conf" "$ROOT/smb.conf"
sed -i "s|//192.168.8.159/share|//${NAS_HOST}/${NAS_SHARE}|g" "$ROOT/smb.conf"

FSTAB_LINE="//${NAS_HOST}/${NAS_SHARE} ${MOUNT} cifs credentials=${ROOT}/credentials,file_mode=0660,dir_mode=0770,_netdev,nofail 0 0"
modprobe cifs 2>/dev/null || true
modprobe nls_utf8 2>/dev/null || true
if ! grep -qF "$MOUNT" /etc/fstab; then
  echo "$FSTAB_LINE" >> /etc/fstab
fi
for _try in 1 2 3 4 5; do
  if mountpoint -q "$MOUNT"; then
    break
  fi
  mount "$MOUNT" && break
  sleep 3
done
if ! mountpoint -q "$MOUNT"; then
  echo "WARNING: NAS CIFS mount failed; gateway may not serve files yet" >&2
fi

install -m 0644 "$SCRIPT_DIR/nas-smb-gateway.service" /etc/systemd/system/nas-smb-gateway.service

# Samba user for Windows clients (same admin password as Buffalo).
export NAS_USER NAS_PASS PUBLIC_PORT="$PUBLIC_PORT" GATEWAY_PORT="$GATEWAY_PORT" FORWARDS
python3 - <<'PY'
import os, subprocess
user = os.environ["NAS_USER"]
pw = os.environ["NAS_PASS"]
subprocess.run(["smbpasswd", "-s", "-a", user], input=f"{pw}\n{pw}\n".encode(), check=True)
subprocess.run(["smbpasswd", "-e", user], check=True)
PY

systemctl daemon-reload
systemctl enable nas-smb-gateway.service
systemctl restart nas-smb-gateway.service

# Point public :1445 DNAT at local gateway instead of raw NAS forward.
if [[ -f "$FORWARDS" ]]; then
  python3 - <<'PY'
from pathlib import Path
import os
forwards = Path(os.environ["FORWARDS"])
text = forwards.read_text(encoding="utf-8")
pub = os.environ.get("PUBLIC_PORT", "1445")
gw_port = os.environ.get("GATEWAY_PORT", "14450")
lines = []
replaced = False
for line in text.splitlines():
    if line.strip().startswith("#") or not line.strip():
        lines.append(line)
        continue
    parts = line.split()
    if len(parts) >= 5 and parts[0] == pub and parts[1].lower() == "tcp" and parts[4] == "nas-smb":
        lines.append(f"{pub}  tcp 127.0.0.1  {gw_port}  nas-smb")
        replaced = True
    else:
        lines.append(line)
if not replaced:
    lines.append(f"{pub}  tcp 127.0.0.1  {gw_port}  nas-smb")
forwards.write_text("\n".join(lines) + "\n", encoding="utf-8")
print("updated", forwards)
PY
  if [[ -x "$APPLY" ]]; then
    bash "$APPLY"
  fi
fi

sleep 2
if smbclient "//127.0.0.1/${NAS_SHARE}" -p "$GATEWAY_PORT" -U "${NAS_USER}%${NAS_PASS}" -c 'ls' >/dev/null 2>&1; then
  echo "NAS SMB gateway OK on 127.0.0.1:${GATEWAY_PORT} (public ${PUBLIC_PORT})"
else
  echo "WARNING: local gateway test failed — check mount and smbd logs" >&2
  journalctl -u nas-smb-gateway.service -n 20 --no-pager || true
  exit 1
fi
