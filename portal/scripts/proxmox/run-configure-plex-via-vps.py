#!/usr/bin/env python3
"""Push and run configure-plex-server.sh on Proxmox via the VPS."""
from __future__ import annotations

import base64
import io
import os
import sys
from pathlib import Path

import paramiko

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "proxmox" / "configure-plex-server.sh"
DEFAULT_HOST = "74.208.76.213"
PROXMOX = "192.168.8.160"


def _client() -> paramiko.SSHClient:
    host = os.environ.get("VPS_HOST", DEFAULT_HOST).strip()
    user = os.environ.get("VPS_USER", "root").strip() or "root"
    port = int(os.environ.get("VPS_PORT", "22"))
    key_text = os.environ.get("VPS_SSH_PRIVATE_KEY", "").strip()
    password = os.environ.get("VPS_SSH_PASSWORD", "").strip()
    if not key_text and not password:
        raise SystemExit("Set VPS_SSH_PRIVATE_KEY or VPS_SSH_PASSWORD")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kw: dict = {
        "hostname": host,
        "username": user,
        "port": port,
        "timeout": 45,
        "allow_agent": False,
        "look_for_keys": False,
    }
    if key_text:
        kw["pkey"] = paramiko.RSAKey.from_private_key(io.StringIO(key_text))
    else:
        kw["password"] = password
    client.connect(**kw)
    return client


def _run(client: paramiko.SSHClient, cmd: str, timeout: int = 300) -> str:
    _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    code = stdout.channel.recv_exit_status()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    if out:
        print(out, end="" if out.endswith("\n") else "\n")
    if err:
        print(err, end="" if err.endswith("\n") else "\n", file=sys.stderr)
    if code != 0:
        raise RuntimeError(f"exit {code}: {cmd[:120]}")
    return out


def main() -> int:
    if not SCRIPT.is_file():
        raise SystemExit(f"missing {SCRIPT}")
    script_b64 = base64.b64encode(SCRIPT.read_bytes()).decode("ascii")
    client = _client()
    try:
        _run(client, "ip route replace 192.168.8.0/24 via 10.9.0.2 dev tun0 metric 5 2>/dev/null || true")
        # Build NAS cred from portal env on VPS
        _run(
            client,
            r"""
set -euo pipefail
set -a
. /opt/wireguard/port-forward-ui.env
set +a
python3 - <<'PY'
import os, base64
from pathlib import Path
user = os.environ.get("BUFFALO_USER") or "admin"
pb = os.environ.get("BUFFALO_PASS_B64") or ""
pr = os.environ.get("BUFFALO_PASS") or ""
pw = base64.b64decode(pb).decode() if pb else pr
if not pw:
    raise SystemExit("BUFFALO_PASS_B64/BUFFALO_PASS missing in port-forward-ui.env")
Path("/tmp/plex-nas.cred").write_text(
    f"username={user}\npassword={pw}\ndomain=WORKGROUP\n", encoding="utf-8"
)
print(f"nas user={user} pass_len={len(pw)}")
# list shares
import subprocess
r = subprocess.run(
    ["smbclient", "-L", "//192.168.8.159", "-U", f"{user}%{pw}", "-m", "SMB3"],
    capture_output=True, text=True
)
print(r.stdout or r.stderr)
PY
chmod 600 /tmp/plex-nas.cred
""",
            timeout=90,
        )
        _run(
            client,
            f"echo '{script_b64}' | base64 -d > /tmp/configure-plex-server.sh && chmod +x /tmp/configure-plex-server.sh",
        )
        _run(
            client,
            f"""
set -euo pipefail
scp -o StrictHostKeyChecking=no /tmp/configure-plex-server.sh /tmp/plex-nas.cred root@{PROXMOX}:/tmp/
ssh -o StrictHostKeyChecking=no root@{PROXMOX} 'install -m 600 /tmp/plex-nas.cred /root/.plex-nas.cred; bash /tmp/configure-plex-server.sh'
""",
            timeout=360,
        )
        # Quick public check
        _run(
            client,
            "curl -sI https://plex.vpstruelord.com/web | head -15; echo ---; curl -sk https://plex.vpstruelord.com/identity; echo",
        )
    finally:
        client.close()
    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
