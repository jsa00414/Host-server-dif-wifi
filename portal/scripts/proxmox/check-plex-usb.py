#!/usr/bin/env python3
"""Quick check: USB mount + Plex library sizes via VPS→Proxmox."""
from __future__ import annotations

import base64
import io
import os
import sys

import paramiko

PROXMOX = "192.168.8.160"
INNER = r"""
set -euo pipefail
echo "==> host mount"
df -h /mnt/plex-usb | tail -1
echo "==> ct mount"
pct exec 101 -- df -h /mnt/usb | tail -1
pct exec 101 -- bash -lc '
TOKEN=$(python3 - <<'"'"'PY'"'"'
import re, pathlib
t = pathlib.Path("/var/lib/plexmediaserver/Library/Application Support/Plex Media Server/Preferences.xml").read_text()
m = re.search(r"PlexOnlineToken=\"([^\"]+)\"", t)
print(m.group(1) if m else "")
PY
)
echo "==> sections"
curl -sk "http://127.0.0.1:32400/library/sections?X-Plex-Token=$TOKEN" | python3 -c "
import sys,re
xml=sys.stdin.read()
for m in re.finditer(r\"<Directory\\b([^>]*)>\", xml):
    a=m.group(1)
    def g(k):
        mm=re.search(rf\"{k}=\\\"([^\\\"]*)\\\"\", a)
        return mm.group(1) if mm else \"\"
    print(f\"  {g(\"key\")}: {g(\"title\")} ({g(\"type\")})\")
for m in re.finditer(r\"<Location\\b([^>]*)>\", xml):
    a=m.group(1)
    def g(k):
        mm=re.search(rf\"{k}=\\\"([^\\\"]*)\\\"\", a)
        return mm.group(1) if mm else \"\"
    print(f\"    path={g(\"path\")}\")
"
echo "==> library sizes"
for k in 1 2; do
  curl -sk "http://127.0.0.1:32400/library/sections/$k/all?X-Plex-Token=$TOKEN&X-Plex-Container-Start=0&X-Plex-Container-Size=0" \
    | python3 -c "import sys,re; t=sys.stdin.read(); m=re.search(r\"totalSize=\\\"(\\d+)\\\"\", t) or re.search(r\"size=\\\"(\\d+)\\\"\", t); print(f\"  section $k size={m.group(1) if m else \"?\"}\")"
done
echo "==> activities"
curl -sk "http://127.0.0.1:32400/activities?X-Plex-Token=$TOKEN" | head -c 800; echo
'
"""


def main() -> int:
    password = os.environ.get("VPS_SSH_PASSWORD", "").strip()
    key_text = os.environ.get("VPS_SSH_PRIVATE_KEY", "").strip()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kw = dict(hostname=os.environ.get("VPS_HOST", "74.208.76.213"), username="root", port=22, timeout=45, allow_agent=False, look_for_keys=False)
    if key_text:
        kw["pkey"] = paramiko.RSAKey.from_private_key(io.StringIO(key_text))
    else:
        kw["password"] = password
    client.connect(**kw)
    try:
        b64 = base64.b64encode(INNER.encode()).decode()
        _, stdout, stderr = client.exec_command(
            "ip route replace 192.168.8.0/24 via 10.9.0.2 dev tun0 metric 5 2>/dev/null || true; "
            f"python3 -c \"import base64,pathlib; pathlib.Path('/tmp/plex-usb-check.sh').write_bytes(base64.b64decode('{b64}'))\"; "
            f"scp -o StrictHostKeyChecking=no /tmp/plex-usb-check.sh root@{PROXMOX}:/tmp/; "
            f"ssh -o StrictHostKeyChecking=no root@{PROXMOX} bash /tmp/plex-usb-check.sh",
            timeout=120,
        )
        code = stdout.channel.recv_exit_status()
        print(stdout.read().decode("utf-8", errors="replace"))
        err = stderr.read().decode("utf-8", errors="replace")
        if err:
            print(err, file=sys.stderr)
        return code
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
