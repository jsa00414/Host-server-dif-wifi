#!/usr/bin/env python3
"""Widen Plex allowedNetworks so reverse-proxy setup can claim the server."""
from __future__ import annotations

import io
import os
import sys

import paramiko

PREFS = r'''
from pathlib import Path
import re
p = Path("/var/lib/plexmediaserver/Library/Application Support/Plex Media Server/Preferences.xml")
text = p.read_text(encoding="utf-8")
m = re.search(r"<Preferences\b([^>]*)/?>", text)
body = m.group(1).rstrip().rstrip("/")
existing = dict(re.findall(r'(\w+)="([^"]*)"', body))
existing.update({
    "FriendlyName": "Plex Media Server",
    "DisableRemoteSecurity": "1",
    # Treat all clients as local during first claim via reverse proxy.
    "allowedNetworks": "0.0.0.0/0.0.0.0",
    "LanNetworksBandwidth": "0.0.0.0/0.0.0.0",
    "customConnections": "https://plex.vpstruelord.com:443,http://192.168.8.161:32400",
    "PublishServerOnPlexOnlineKey": "1",
    "ManualPortMappingMode": "1",
    "ManualPortMappingPort": "443",
    "secureConnections": "0",
    "AcceptedEULA": "1",
})
attr = " ".join(f'{k}="{v}"' for k, v in existing.items())
p.write_text(f'<?xml version="1.0" encoding="utf-8"?>\n<Preferences {attr}/>\n', encoding="utf-8")
print(p.read_text(encoding="utf-8"))
'''


def main() -> int:
    host = os.environ.get("VPS_HOST", "74.208.76.213").strip()
    user = os.environ.get("VPS_USER", "root").strip() or "root"
    port = int(os.environ.get("VPS_PORT", "22"))
    key_text = os.environ.get("VPS_SSH_PRIVATE_KEY", "").strip()
    password = os.environ.get("VPS_SSH_PASSWORD", "").strip()
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kw = {
        "hostname": host,
        "username": user,
        "port": port,
        "timeout": 30,
        "allow_agent": False,
        "look_for_keys": False,
    }
    if key_text:
        kw["pkey"] = paramiko.RSAKey.from_private_key(io.StringIO(key_text))
    else:
        kw["password"] = password
    c.connect(**kw)
    try:
        _, out, err = c.exec_command(
            "ip route replace 192.168.8.0/24 via 10.9.0.2 dev tun0 metric 5 2>/dev/null || true",
            timeout=30,
        )
        out.channel.recv_exit_status()
        sftp = c.open_sftp()
        with sftp.file("/tmp/plex-widen-local.py", "w") as f:
            f.write(PREFS)
        sftp.close()
        cmd = r"""
scp -o StrictHostKeyChecking=no /tmp/plex-widen-local.py root@192.168.8.160:/tmp/
ssh -o StrictHostKeyChecking=no root@192.168.8.160 'pct push 101 /tmp/plex-widen-local.py /tmp/plex-widen-local.py; pct exec 101 -- bash -lc "
systemctl stop plexmediaserver
python3 /tmp/plex-widen-local.py
chown plex:plex \"/var/lib/plexmediaserver/Library/Application Support/Plex Media Server/Preferences.xml\"
chmod 600 \"/var/lib/plexmediaserver/Library/Application Support/Plex Media Server/Preferences.xml\"
systemctl start plexmediaserver
sleep 5
systemctl is-active plexmediaserver
curl -s http://127.0.0.1:32400/identity
echo
# LocalAdminToken
python3 -c \"from pathlib import Path; p=Path(\\\"/var/lib/plexmediaserver/Library/Application Support/Plex Media Server/.LocalAdminToken\\\"); print(\\\"admin_token_len\\\", len(p.read_text().strip()) if p.exists() else 0)\"
"'
"""
        _, out, err = c.exec_command(cmd, timeout=120)
        code = out.channel.recv_exit_status()
        sys.stdout.write(out.read().decode())
        sys.stderr.write(err.read().decode())
        if code != 0:
            return code
        # Verify public providers still 200
        _, out, err = c.exec_command(
            "curl -sk -o /dev/null -w 'providers=%{http_code}\\n' https://plex.vpstruelord.com/media/providers; "
            "curl -sI https://plex.vpstruelord.com/ | head -6",
            timeout=30,
        )
        out.channel.recv_exit_status()
        sys.stdout.write(out.read().decode())
    finally:
        c.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
