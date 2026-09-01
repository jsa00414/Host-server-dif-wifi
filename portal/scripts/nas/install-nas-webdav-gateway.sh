#!/bin/bash
# HTTPS WebDAV gateway (via Caddy) so Windows Explorer can open files.
set -euo pipefail

ROOT="/opt/wireguard/nas-webdav-gateway"
ENV_FILE="/opt/wireguard/port-forward-ui.env"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CADDYFILE="/opt/truemail/Caddyfile"
LISTEN_PORT="${NAS_WEBDAV_PORT:-2122}"
DAV_HOST="${NAS_WEBDAV_HOST:-dav.vpstruelord.com}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Missing $ENV_FILE" >&2
  exit 1
fi

set -a
# shellcheck source=/dev/null
source "$ENV_FILE"
set +a

NAS_HOST="${NAS_SMB_HOST:-${FTP_HOST:-192.168.8.159}}"
NAS_BACKEND_USER="${FTP_USER:-${BUFFALO_USER:-admin}}"
NAS_PUBLIC_USER="${NAS_FTP_PUBLIC_USER:-admin}"
NAS_PASS="${BUFFALO_PASS:-}"
if [[ -z "$NAS_PASS" && -n "${BUFFALO_PASS_B64:-}" ]]; then
  NAS_PASS="$(BUFFALO_PASS_B64="$BUFFALO_PASS_B64" python3 -c 'import os,base64; print(base64.b64decode(os.environ["BUFFALO_PASS_B64"]).decode())')"
fi
if [[ -z "$NAS_PASS" ]]; then
  echo "NAS password not configured" >&2
  exit 1
fi

RCLONE=/usr/local/bin/rclone
if ! "$RCLONE" serve webdav --help >/dev/null 2>&1; then
  echo "rclone missing or too old" >&2
  exit 1
fi

mkdir -p "$ROOT"
chmod 700 "$ROOT"

OBSCURED="$("$RCLONE" obscure "$NAS_PASS")"
# Reuse FTP rclone backend config if present
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
ROOT=/opt/wireguard/nas-webdav-gateway
RCLONE=/usr/local/bin/rclone
set -a
# shellcheck disable=SC1091
source /opt/wireguard/port-forward-ui.env
set +a
NAS_PUBLIC_USER="\${NAS_FTP_PUBLIC_USER:-admin}"
NAS_PASS="\${BUFFALO_PASS:-}"
if [[ -z "\$NAS_PASS" && -n "\${BUFFALO_PASS_B64:-}" ]]; then
  NAS_PASS="\$(BUFFALO_PASS_B64="\$BUFFALO_PASS_B64" python3 -c 'import os,base64; print(base64.b64decode(os.environ["BUFFALO_PASS_B64"]).decode())')"
fi
LISTEN_PORT="\${NAS_WEBDAV_PORT:-2122}"
exec "\$RCLONE" serve webdav buffalo:disk1 \\
  --config "\$ROOT/rclone.conf" \\
  --addr "0.0.0.0:\${LISTEN_PORT}" \\
  --user "\$NAS_PUBLIC_USER" \\
  --pass "\$NAS_PASS" \\
  --vfs-cache-mode writes \\
  --dir-cache-time 30s
EOF
chmod 700 "$ROOT/run.sh"

install -m 0644 "$SCRIPT_DIR/nas-webdav-gateway.service" /etc/systemd/system/nas-webdav-gateway.service
systemctl daemon-reload
systemctl enable nas-webdav-gateway.service
systemctl restart nas-webdav-gateway.service
sleep 2
systemctl is-active nas-webdav-gateway.service

# Prefer path on portal host (no extra DNS). Keep legacy marker empty.
if [[ -f "$CADDYFILE" ]]; then
  python3 - <<'PY'
from pathlib import Path
path = Path("/opt/truemail/Caddyfile")
text = path.read_text(encoding="utf-8")
begin, end = "# BEGIN NAS-WEBDAV-GATEWAY", "# END NAS-WEBDAV-GATEWAY"
if begin in text and end in text:
    pre, rest = text.split(begin, 1)
    _, post = rest.split(end, 1)
    text = pre.rstrip() + "\n" + post.lstrip()

if "@nasdav path" not in text:
    marker = "\t@nasmedia path /nas-files/rpc/cat* /nas-files/rpc/download* /nas-files/rpc/thumbnail*\n"
    insert = (
        "\t@nasdav path /dav /dav/*\n"
        "\thandle @nasdav {\n"
        "\t\turi strip_prefix /dav\n"
        "\t\treverse_proxy 172.18.0.1:2122 {\n"
        "\t\t\theader_up Host {host}\n"
        "\t\t\theader_up X-Forwarded-Host {host}\n"
        "\t\t\theader_up X-Forwarded-Proto {scheme}\n"
        "\t\t}\n"
        "\t}\n"
    )
    if marker not in text:
        raise SystemExit("portal @nasmedia marker not found")
    text = text.replace(marker, insert + marker, 1)
path.write_text(text, encoding="utf-8")
print("updated", path)
PY
  docker exec truemail-caddy-1 caddy reload --config /etc/caddy/Caddyfile 2>/dev/null \
    || docker kill -s HUP truemail-caddy-1 2>/dev/null \
    || true
fi

# Do not expose 2122 publicly via UFW if possible; Caddy reaches host docker bridge.
if command -v ufw >/dev/null 2>&1; then
  ufw deny 2122/tcp >/dev/null 2>&1 || true
fi

export NAS_PUBLIC_USER NAS_PASS
code="$(curl -s -o /tmp/dav-root.xml -w '%{http_code}' -u "${NAS_PUBLIC_USER}:${NAS_PASS}" -X PROPFIND -H 'Depth: 1' "http://127.0.0.1:${LISTEN_PORT}/" || true)"
echo "webdav local PROPFIND HTTP $code"
if [[ "$code" != "207" && "$code" != "200" ]]; then
  journalctl -u nas-webdav-gateway -n 30 --no-pager || true
  exit 1
fi
echo "NAS WebDAV gateway OK — use https://portal.vpstruelord.com/dav/"
