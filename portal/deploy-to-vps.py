#!/usr/bin/env python3
"""Deploy portal files to the VPS over SSH (key or password)."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import paramiko

ROOT = Path(__file__).resolve().parent
REMOTE_UI = "/opt/wireguard/port-forward-ui"
DEFAULT_HOST = "74.208.76.213"
DEFAULT_USER = "root"

UPLOADS: list[tuple[Path, str]] = [
    (ROOT / "server.py", f"{REMOTE_UI}/server.py"),
    (ROOT / "static/index.html", f"{REMOTE_UI}/static/index.html"),
    (ROOT / "static/files.html", f"{REMOTE_UI}/static/files.html"),
    (ROOT / "static/nas-windows.html", f"{REMOTE_UI}/static/nas-windows.html"),
    (ROOT / "static/windows-vpn.html", f"{REMOTE_UI}/static/windows-vpn.html"),
    (
        ROOT / "scripts/nas/Setup-ServerManagerNas.ps1",
        f"{REMOTE_UI}/scripts/nas/Setup-ServerManagerNas.ps1",
    ),
    (
        ROOT / "scripts/openvpn/server.conf",
        "/opt/openvpn/server.conf",
    ),
    (
        ROOT / "scripts/openvpn/client-connect.sh",
        "/opt/openvpn/scripts/client-connect.sh",
    ),
    (
        ROOT / "scripts/openvpn/client-disconnect.sh",
        "/opt/openvpn/scripts/client-disconnect.sh",
    ),
    (
        ROOT / "scripts/openvpn/flint-allow-vpn-ssh.sh",
        "/opt/openvpn/scripts/flint-allow-vpn-ssh.sh",
    ),
    (
        ROOT / "scripts/nas/install-nas-smb-gateway.sh",
        f"{REMOTE_UI}/scripts/nas/install-nas-smb-gateway.sh",
    ),
    (
        ROOT / "scripts/nas/smb-gateway.smb.conf",
        f"{REMOTE_UI}/scripts/nas/smb-gateway.smb.conf",
    ),
    (
        ROOT / "scripts/nas/nas-smb-gateway.service",
        f"{REMOTE_UI}/scripts/nas/nas-smb-gateway.service",
    ),
    (
        ROOT / "scripts/nas/install-nas-ftp-gateway.sh",
        f"{REMOTE_UI}/scripts/nas/install-nas-ftp-gateway.sh",
    ),
    (
        ROOT / "scripts/nas/nas-ftp-gateway.service",
        f"{REMOTE_UI}/scripts/nas/nas-ftp-gateway.service",
    ),
    (
        ROOT / "scripts/nas/install-nas-webdav-gateway.sh",
        f"{REMOTE_UI}/scripts/nas/install-nas-webdav-gateway.sh",
    ),
    (
        ROOT / "scripts/nas/nas-webdav-gateway.service",
        f"{REMOTE_UI}/scripts/nas/nas-webdav-gateway.service",
    ),
]


def _client() -> paramiko.SSHClient:
    host = os.environ.get("VPS_HOST", DEFAULT_HOST).strip()
    user = os.environ.get("VPS_USER", DEFAULT_USER).strip() or DEFAULT_USER
    port = int(os.environ.get("VPS_PORT", "22"))
    key_text = os.environ.get("VPS_SSH_PRIVATE_KEY", "").strip()
    password = os.environ.get("VPS_SSH_PASSWORD", "").strip()

    if not key_text and not password:
        raise SystemExit(
            "Missing VPS credentials. Set VPS_SSH_PRIVATE_KEY or VPS_SSH_PASSWORD."
        )

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    connect_kwargs: dict = {
        "hostname": host,
        "username": user,
        "port": port,
        "timeout": 30,
        "allow_agent": False,
        "look_for_keys": False,
    }
    if key_text:
        connect_kwargs["pkey"] = paramiko.RSAKey.from_private_key(
            __import__("io").StringIO(key_text)
        )
    else:
        connect_kwargs["password"] = password
    client.connect(**connect_kwargs)
    return client


def _run(client: paramiko.SSHClient, cmd: str) -> None:
    _, stdout, stderr = client.exec_command(cmd)
    exit_code = stdout.channel.recv_exit_status()
    out = stdout.read().decode("utf-8", errors="replace").strip()
    err = stderr.read().decode("utf-8", errors="replace").strip()
    if exit_code != 0:
        raise RuntimeError(f"Command failed ({exit_code}): {cmd}\n{err or out}")
    if out:
        print(out)


def main() -> int:
    host = os.environ.get("VPS_HOST", DEFAULT_HOST).strip()
    print(f"Deploying portal to {host}:{REMOTE_UI} …")
    client = _client()
    try:
        sftp = client.open_sftp()
        try:
            _run(
                client,
                f"mkdir -p {REMOTE_UI}/static {REMOTE_UI}/scripts/nas",
            )
            for local, remote in UPLOADS:
                if not local.is_file():
                    raise FileNotFoundError(f"Missing local file: {local}")
                print(f"  upload {local.name} -> {remote}")
                sftp.put(str(local), remote)
        finally:
            sftp.close()

        if host == DEFAULT_HOST:
            _run(
                client,
                f"sed -i 's/74\\.208\\.54\\.132/74.208.76.213/g' {REMOTE_UI}/server.py || true",
            )
        _run(client, "systemctl restart port-forward-ui && systemctl is-active port-forward-ui")
        _run(
            client,
            "chmod +x /opt/openvpn/scripts/client-connect.sh /opt/openvpn/scripts/client-disconnect.sh /opt/openvpn/scripts/flint-allow-vpn-ssh.sh",
        )
        _run(
            client,
            "cd /opt/wireguard/port-forward-ui && python3 -c \"import server; s=server.read_hookups_state(); print(server.write_hookups_state([r for r in s.get('rules', []) if not r.get('external')]))\"",
        )
        gateway = f"{REMOTE_UI}/scripts/nas/install-nas-ftp-gateway.sh"
        _run(client, f"chmod +x {gateway} && bash {gateway}")
        dav = f"{REMOTE_UI}/scripts/nas/install-nas-webdav-gateway.sh"
        _run(client, f"chmod +x {dav} && bash {dav}")
        _run(client, "systemctl restart openvpn-server-sm 2>/dev/null || systemctl restart openvpn@server 2>/dev/null || true")
    finally:
        client.close()

    hint = (
        "http://74.208.76.213/"
        if host == DEFAULT_HOST
        else "https://portal.vpstruelord.com/"
    )
    print(f"Done. Hard-refresh {hint} (Ctrl+Shift+R).")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"Deploy failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
