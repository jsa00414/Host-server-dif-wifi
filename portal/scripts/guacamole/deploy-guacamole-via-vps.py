#!/usr/bin/env python3
"""Deploy Guacamole+MySQL on VPS and create Windows RDP connection."""
from __future__ import annotations

import base64
import io
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

import paramiko

ROOT = Path(__file__).resolve().parent
WIN_IP = os.environ.get("WINDOWS_VM_IP", "192.168.8.181").strip() or "192.168.8.181"


def client() -> paramiko.SSHClient:
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kw = dict(
        hostname=os.environ.get("VPS_HOST", "74.208.76.213"),
        username="root",
        port=22,
        timeout=45,
        allow_agent=False,
        look_for_keys=False,
    )
    key = os.environ.get("VPS_SSH_PRIVATE_KEY", "").strip()
    if key:
        kw["pkey"] = paramiko.RSAKey.from_private_key(io.StringIO(key))
    else:
        kw["password"] = os.environ.get("VPS_SSH_PASSWORD", "").strip()
    c.connect(**kw)
    return c


def run(c: paramiko.SSHClient, cmd: str, timeout: int = 600) -> str:
    _, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    code = stdout.channel.recv_exit_status()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    if out:
        print(out, end="" if out.endswith("\n") else "\n")
    if err.strip():
        print(err[-2000:], file=sys.stderr)
    if code != 0:
        raise RuntimeError(f"exit {code}: {cmd[:160]}")
    return out


def put(c: paramiko.SSHClient, remote: str, data: bytes) -> None:
    b64 = base64.b64encode(data).decode("ascii")
    run(
        c,
        f"python3 -c \"import base64,pathlib; pathlib.Path({remote!r}).write_bytes(base64.b64decode({b64!r}))\"",
        timeout=60,
    )


def main() -> int:
    c = client()
    try:
        run(c, "ip route replace 192.168.8.0/24 via 10.9.0.2 dev tun0 metric 5 2>/dev/null || true")
        run(c, "mkdir -p /opt/guacamole")
        put(c, "/opt/guacamole/docker-compose.yml", (ROOT / "docker-compose.yml").read_bytes())

        # Generate schema
        run(
            c,
            "docker pull guacamole/guacamole:1.5.5 >/dev/null && "
            "docker run --rm guacamole/guacamole:1.5.5 "
            "/opt/guacamole/bin/initdb.sh --mysql > /opt/guacamole/initdb.sql && "
            "wc -l /opt/guacamole/initdb.sql",
            timeout=300,
        )

        # Reset stack (fresh DB for first bring-up if schema volume empty)
        run(
            c,
            "cd /opt/guacamole && docker compose down 2>/dev/null || true; "
            "docker rm -f guacamole guacd guac-mysql 2>/dev/null || true; "
            "docker compose up -d",
            timeout=300,
        )

        # Wait for HTTP
        for i in range(40):
            code, out, _ = 0, "", ""
            _, stdout, stderr = c.exec_command(
                "curl -sk -o /dev/null -w '%{http_code}' http://127.0.0.1:8088/guacamole/",
                timeout=30,
            )
            code = stdout.channel.recv_exit_status()
            body = stdout.read().decode().strip()
            print(f"wait http={body}")
            if body in ("200", "302", "401"):
                break
            time.sleep(3)
        else:
            run(c, "docker logs guacamole 2>&1 | tail -40")
            raise RuntimeError("guacamole not healthy")

        # Create RDP connection via Guacamole REST API (guacadmin/guacadmin)
        setup = f"""
python3 - <<'PY'
import json, urllib.parse, urllib.request, ssl
ctx = ssl.create_default_context()
base = "http://127.0.0.1:8088/guacamole"
# token
data = urllib.parse.urlencode({{"username":"guacadmin","password":"guacadmin"}}).encode()
req = urllib.request.Request(base + "/api/tokens", data=data, method="POST")
with urllib.request.urlopen(req, timeout=30) as r:
    tok = json.load(r)["authToken"]
print("token_ok")
auth = tok
# list connections
req = urllib.request.Request(base + f"/api/session/data/mysql/connections?token={{auth}}")
with urllib.request.urlopen(req, timeout=30) as r:
    conns = json.load(r)
print("existing", list(conns.keys()) if isinstance(conns, dict) else conns)
# find/create Windows VM
name = "Windows VM"
found = None
if isinstance(conns, dict):
    for cid, meta in conns.items():
        if meta.get("name") == name:
            found = cid
            break
payload = {{
  "name": name,
  "parentIdentifier": "ROOT",
  "protocol": "rdp",
  "parameters": {{
    "hostname": "{WIN_IP}",
    "port": "3389",
    "ignore-cert": "true",
    "security": "any",
    "resize-method": "display-update",
    "enable-wallpaper": "true",
    "color-depth": "32",
  }},
  "attributes": {{
    "max-connections": "",
    "max-connections-per-user": "",
    "weight": "",
    "failover-only": "",
    "guacd-port": "",
    "guacd-encryption": "",
    "guacd-hostname": "",
  }},
}}
body = json.dumps(payload).encode()
if found:
    req = urllib.request.Request(
        base + f"/api/session/data/mysql/connections/{{found}}?token={{auth}}",
        data=body, method="PUT",
        headers={{"Content-Type":"application/json"}},
    )
else:
    req = urllib.request.Request(
        base + f"/api/session/data/mysql/connections?token={{auth}}",
        data=body, method="POST",
        headers={{"Content-Type":"application/json"}},
    )
with urllib.request.urlopen(req, timeout=30) as r:
    print(r.read().decode()[:500])
print("connection_ok")
PY
"""
        run(c, setup, timeout=60)
        print(f"Guacamole ready → RDP {WIN_IP}:3389")
    finally:
        c.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
