#!/usr/bin/env bash
# Configure CT 101 as Plex Media Server (not a player) with reverse-proxy prefs
# and optional Buffalo NAS media bind-mount. Run on the Proxmox host.
set -euo pipefail

CTID="${CTID:-101}"
CT_IP="${CT_IP:-192.168.8.161}"
PUBLIC_HOST="${PUBLIC_HOST:-plex.vpstruelord.com}"
NAS_HOST="${NAS_HOST:-192.168.8.159}"
NAS_SHARE="${NAS_SHARE:-}"
NAS_CRED="${NAS_CRED:-/root/.plex-nas.cred}"
HOST_MEDIA="${HOST_MEDIA:-/mnt/plex-nas}"
CT_MEDIA="${CT_MEDIA:-/mnt/media}"

if ! command -v pct >/dev/null 2>&1; then
  echo "pct not found — run on the Proxmox host" >&2
  exit 1
fi

if ! pct status "$CTID" >/dev/null 2>&1; then
  echo "CT ${CTID} missing — run install-plex-lxc.sh first" >&2
  exit 1
fi

pct set "$CTID" --hostname plex-server \
  --description "Plex Media Server LXC (${PUBLIC_HOST})" >/dev/null

if ! pct status "$CTID" 2>/dev/null | grep -qi running; then
  pct start "$CTID"
  sleep 4
fi

echo "==> Ensuring plexmediaserver (remove any Plex player/desktop packages)"
pct exec "$CTID" -- bash -s <<'INNER'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
# Player / HTPC clients — not Media Server
apt-get remove -y --purge plex-desktop plex-htpc plexmediaplayer 2>/dev/null || true
apt-get install -y -qq curl gnupg ca-certificates apt-transport-https cifs-utils python3 >/dev/null
install -d -m 0755 /usr/share/keyrings
if [[ ! -f /usr/share/keyrings/plex.gpg ]]; then
  curl -fsSL https://downloads.plex.tv/plex-keys/PlexSign.key | gpg --dearmor -o /usr/share/keyrings/plex.gpg
fi
echo "deb [signed-by=/usr/share/keyrings/plex.gpg] https://downloads.plex.tv/repo/deb public main" \
  > /etc/apt/sources.list.d/plexmediaserver.list
apt-get update -qq
apt-get install -y -qq plexmediaserver
systemctl enable plexmediaserver
INNER

if [[ -f "$NAS_CRED" ]]; then
  echo "==> Mounting NAS media on host → CT ${CT_MEDIA}"
  mkdir -p "$HOST_MEDIA"
  if ! mountpoint -q "$HOST_MEDIA"; then
    shares=()
    if [[ -n "$NAS_SHARE" ]]; then
      shares+=("$NAS_SHARE")
    fi
    shares+=(share disk1 Disk1 media Media public Public)
    mounted=""
    for s in "${shares[@]}"; do
      [[ -z "$s" ]] && continue
      for ver in 3.0 2.1 2.0; do
        if mount -t cifs "//${NAS_HOST}/${s}" "$HOST_MEDIA" \
          -o "credentials=${NAS_CRED},iocharset=utf8,vers=${ver},uid=0,gid=0,file_mode=0775,dir_mode=0775" 2>/dev/null; then
          mounted="$s"
          echo "    mounted //${NAS_HOST}/${s} (vers=${ver})"
          break 2
        fi
      done
    done
    if [[ -z "$mounted" ]]; then
      echo "WARNING: could not mount NAS share (continuing without media mount)" >&2
    else
      # Persist across Proxmox reboots
      if [[ -f "$NAS_CRED" ]] && ! grep -q " ${HOST_MEDIA} " /etc/fstab 2>/dev/null; then
        echo "//${NAS_HOST}/${mounted} ${HOST_MEDIA} cifs credentials=${NAS_CRED},iocharset=utf8,vers=2.0,uid=0,gid=0,file_mode=0775,dir_mode=0775,_netdev,x-systemd.automount 0 0" >> /etc/fstab
      fi
    fi
  fi
  if mountpoint -q "$HOST_MEDIA"; then
    pct set "$CTID" -mp0 "${HOST_MEDIA},mp=${CT_MEDIA}" >/dev/null || true
    if ! pct exec "$CTID" -- test -d "$CT_MEDIA" 2>/dev/null; then
      pct stop "$CTID" || true
      pct start "$CTID"
      sleep 5
    fi
    # Ensure mp is live even if CT was already running when mp0 was set
    if ! pct exec "$CTID" -- mountpoint -q "$CT_MEDIA" 2>/dev/null; then
      pct stop "$CTID" || true
      pct start "$CTID"
      sleep 5
    fi
    pct exec "$CTID" -- bash -lc "mkdir -p '${CT_MEDIA}'; ls -la '${CT_MEDIA}' | head -20; df -h '${CT_MEDIA}'" || true
  fi
else
  echo "==> No ${NAS_CRED} — skip NAS media mount"
fi

echo "==> Writing Plex Media Server reverse-proxy preferences"
# Push a small Python helper into the CT (avoids nested-heredoc escaping issues).
cat > /tmp/plex-write-prefs.py <<PY
from pathlib import Path
import re
import sys

public = sys.argv[1]
ct_ip = sys.argv[2]
p = Path("/var/lib/plexmediaserver/Library/Application Support/Plex Media Server/Preferences.xml")
text = p.read_text(encoding="utf-8") if p.exists() else '<?xml version="1.0" encoding="utf-8"?>\n<Preferences/>\n'
m = re.search(r"<Preferences\\b([^>]*)/?>", text)
if not m:
    raise SystemExit("Preferences.xml missing Preferences tag")
body = m.group(1).rstrip().rstrip("/")
existing = dict(re.findall(r'(\\w+)="([^"]*)"', body))
existing.update({
    "FriendlyName": "Plex Media Server",
    # Allow first-time claim via https://plex.vpstruelord.com (LAN IP is not
    # reachable off-home). Turn off after claiming for tighter security.
    "DisableRemoteSecurity": "1",
    "customConnections": f"https://{public}:443,http://{ct_ip}:32400",
    "allowedNetworks": "192.168.8.0/255.255.255.0,10.9.0.0/255.255.255.0,172.16.0.0/255.240.0.0,10.0.0.0/255.0.0.0",
    "LanNetworksBandwidth": "192.168.8.0/255.255.255.0,10.9.0.0/255.255.255.0",
    "PublishServerOnPlexOnlineKey": "1",
    "ManualPortMappingMode": "1",
    "ManualPortMappingPort": "443",
    "secureConnections": "0",
    "AcceptedEULA": "1",
})
attr_str = " ".join(f'{k}="{v}"' for k, v in existing.items())
p.parent.mkdir(parents=True, exist_ok=True)
p.write_text(f'<?xml version="1.0" encoding="utf-8"?>\n<Preferences {attr_str}/>\n', encoding="utf-8")
print(p.read_text(encoding="utf-8"))
PY
pct push "$CTID" /tmp/plex-write-prefs.py /tmp/plex-write-prefs.py
pct exec "$CTID" -- bash -s <<INNER
set -euo pipefail
systemctl stop plexmediaserver
python3 /tmp/plex-write-prefs.py '${PUBLIC_HOST}' '${CT_IP}'
PREF="/var/lib/plexmediaserver/Library/Application Support/Plex Media Server/Preferences.xml"
chown plex:plex "\$PREF"
chmod 600 "\$PREF"
mkdir -p /mnt/media
systemctl start plexmediaserver
for i in \$(seq 1 30); do
  if ss -ltn 2>/dev/null | grep -q ':32400'; then
    break
  fi
  sleep 1
done
systemctl is-active plexmediaserver
dpkg -l plexmediaserver | tail -1
curl -s http://127.0.0.1:32400/identity || true
echo
INNER

echo
echo "Plex Media Server configured on CT ${CTID}"
echo "  Claim/setup from LAN/VPN: http://${CT_IP}:32400/web"
echo "  Public: https://${PUBLIC_HOST}/web"
echo "  Media path (if mounted): ${CT_MEDIA}"
pct status "$CTID" || true
