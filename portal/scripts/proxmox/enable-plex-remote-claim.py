#!/usr/bin/env python3
"""Enable remote claim for Plex Media Server via DisableRemoteSecurity."""
from __future__ import annotations

import io
import os
import sys

import paramiko

PREFS = r"""
from pathlib import Path
import re
p = Path("/var/lib/plexmediaserver/Library/Application Support/Plex Media Server/Preferences.xml")
text = p.read_text(encoding="utf-8") if p.exists() else '<?xml version="1.0" encoding="utf-8"?>\n<Preferences/>\n'
m = re.search(r"<Preferences\b([^>]*)/?>", text)
if not m:
    raise SystemExit("no Preferences")
body = m.group(1).rstrip().rstrip("/")
existing = dict(re.findall(r'(\w+)="([^"]*)"', body))
existing.update({
    "FriendlyName": "Plex Media Server",
    "DisableRemoteSecurity": "1",
    "customConnections": "https://plex.vpstruelord.com:443,http://192.168.8.161:32400",
    "allowedNetworks": "192.168.8.0/255.255.255.0,10.9.0.0/255.255.255.0,172.16.0.0/255.240.0.0,10.0.0.0/255.0.0.0",
    "LanNetworksBandwidth": "192.168.8.0/255.255.255.0,10.9.0.0/255.255.255.0",
    "PublishServerOnPlexOnlineKey": "1",
    "ManualPortMappingMode": "1",
    "ManualPortMappingPort": "443",
    "secureConnections": "0",
    "AcceptedEULA": "1",
})
attr = " ".join(f'{k}="{v}"' for k, v in existing.items())
p.parent.mkdir(parents=True, exist_ok=True)
p.write_text(f'<?xml version="1.0" encoding="utf-8"?>\n<Preferences {attr}/>\n', encoding="utf-8")
print(p.read_text(encoding="utf-8"))
"""


def client() -> paramiko.SSHClient:
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
    return c


def run(c: paramiko.SSHClient, cmd: str, timeout: int = 120) -> None:
    print(f">>> {cmd[:160]}", flush=True)
    _, out, err = c.exec_command(cmd, timeout=timeout)
    code = out.channel.recv_exit_status()
    sys.stdout.write(out.read().decode())
    e = err.read().decode()
    if e:
        sys.stderr.write(e)
    print(f"<<< {code}", flush=True)
    if code != 0:
        raise SystemExit(code)


def main() -> int:
    c = client()
    try:
        run(c, "ip route replace 192.168.8.0/24 via 10.9.0.2 dev tun0 metric 5 2>/dev/null || true")
        sftp = c.open_sftp()
        with sftp.file("/tmp/plex-disable-remote-sec.py", "w") as f:
            f.write(PREFS)
        sftp.close()
        run(
            c,
            "scp -o StrictHostKeyChecking=no /tmp/plex-disable-remote-sec.py root@192.168.8.160:/tmp/",
            timeout=60,
        )
        run(
            c,
            """ssh -o StrictHostKeyChecking=no root@192.168.8.160 '
pct push 101 /tmp/plex-disable-remote-sec.py /tmp/plex-disable-remote-sec.py
pct exec 101 -- bash -lc "
systemctl stop plexmediaserver
python3 /tmp/plex-disable-remote-sec.py
PREF=\\\"/var/lib/plexmediaserver/Library/Application Support/Plex Media Server/Preferences.xml\\\"
chown plex:plex \\\"$PREF\\\"
chmod 600 \\\"$PREF\\\"
systemctl start plexmediaserver
sleep 4
systemctl is-active plexmediaserver
curl -s http://127.0.0.1:32400/identity; echo
"
'""",
            timeout=90,
        )
        run(
            c,
            "curl -sI https://plex.vpstruelord.com/web | head -12; "
            "curl -sk https://plex.vpstruelord.com/identity; echo; "
            "curl -sk -o /dev/null -w 'index=%{http_code}\\n' https://plex.vpstruelord.com/web/index.html",
        )
        # Also confirm LAN still works from VPS
        run(
            c,
            "curl -sI --connect-timeout 5 http://192.168.8.161:32400/web | head -8",
        )
    finally:
        c.close()
    print(
        "\nUse https://plex.vpstruelord.com/web (not the LAN IP unless on home WiFi/VPN).\n"
        "DisableRemoteSecurity=1 is on until you claim the server.\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
