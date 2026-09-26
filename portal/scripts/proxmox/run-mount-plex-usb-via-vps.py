#!/usr/bin/env python3
"""Detach WD USB from Windows VM, mount on Proxmox, bind into Plex CT, add libraries."""
from __future__ import annotations

import base64
import io
import os
import sys
from pathlib import Path

import paramiko

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "proxmox" / "mount-plex-usb.sh"
ADD_LIBS = ROOT / "scripts" / "proxmox" / "add-plex-usb-libraries.sh"
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


def _run(client: paramiko.SSHClient, cmd: str, timeout: int = 600) -> str:
    _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    code = stdout.channel.recv_exit_status()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    if out:
        print(out, end="" if out.endswith("\n") else "\n")
    if err:
        print(err, end="" if err.endswith("\n") else "\n", file=sys.stderr)
    if code != 0:
        raise RuntimeError(f"exit {code}: {cmd[:160]}")
    return out


def _push_and_run(client: paramiko.SSHClient, local: Path, remote: str, timeout: int = 600) -> str:
    b64 = base64.b64encode(local.read_bytes()).decode("ascii")
    _run(
        client,
        f"python3 -c \"import base64,pathlib; pathlib.Path('{remote}').write_bytes(base64.b64decode('{b64}'))\"",
        timeout=60,
    )
    return _run(
        client,
        f"scp -o StrictHostKeyChecking=no {remote} root@{PROXMOX}:{remote} && "
        f"ssh -o StrictHostKeyChecking=no root@{PROXMOX} 'chmod +x {remote} && bash {remote}'",
        timeout=timeout,
    )


def main() -> int:
    if not SCRIPT.is_file():
        raise SystemExit(f"missing {SCRIPT}")
    if not ADD_LIBS.is_file():
        raise SystemExit(f"missing {ADD_LIBS}")
    client = _client()
    try:
        _run(client, "ip route replace 192.168.8.0/24 via 10.9.0.2 dev tun0 metric 5 2>/dev/null || true")
        print("=== Mount USB ===")
        _push_and_run(client, SCRIPT, "/tmp/mount-plex-usb.sh", timeout=900)
        print("=== Add Plex libraries ===")
        _push_and_run(client, ADD_LIBS, "/tmp/add-plex-usb-libraries.sh", timeout=300)
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
