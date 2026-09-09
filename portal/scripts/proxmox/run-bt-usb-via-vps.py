#!/usr/bin/env python3
"""Install bt-usb-owner on Proxmox and hand Bluetooth to Windows VM 100."""
from __future__ import annotations

import base64
import io
import os
import sys
from pathlib import Path

import paramiko

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "proxmox" / "bt-usb-owner"
LED_OWNER = ROOT / "scripts" / "proxmox" / "aw-elc-usb-owner"
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
        raise RuntimeError(f"exit {code}: {cmd[:160]}")
    return out


def _push(client: paramiko.SSHClient, local: Path, remote: str) -> None:
    b64 = base64.b64encode(local.read_bytes()).decode("ascii")
    _run(
        client,
        f"python3 -c \"import base64,pathlib; pathlib.Path('{remote}').write_bytes(base64.b64decode('{b64}'))\"",
        timeout=60,
    )


def main() -> int:
    if not SCRIPT.is_file():
        raise SystemExit(f"missing {SCRIPT}")
    action = (sys.argv[1] if len(sys.argv) > 1 else "to-windows").strip() or "to-windows"
    client = _client()
    try:
        _run(client, "ip route replace 192.168.8.0/24 via 10.9.0.2 dev tun0 metric 5 2>/dev/null || true")
        print("=== Install bt-usb-owner ===")
        _push(client, SCRIPT, "/tmp/bt-usb-owner")
        if LED_OWNER.is_file():
            _push(client, LED_OWNER, "/tmp/aw-elc-usb-owner")
        _run(
            client,
            f"scp -o StrictHostKeyChecking=no /tmp/bt-usb-owner root@{PROXMOX}:/usr/local/sbin/bt-usb-owner && "
            f"ssh -o StrictHostKeyChecking=no root@{PROXMOX} 'chmod 755 /usr/local/sbin/bt-usb-owner'",
        )
        if LED_OWNER.is_file():
            _run(
                client,
                f"scp -o StrictHostKeyChecking=no /tmp/aw-elc-usb-owner root@{PROXMOX}:/usr/local/sbin/aw-elc-usb-owner && "
                f"ssh -o StrictHostKeyChecking=no root@{PROXMOX} 'chmod 755 /usr/local/sbin/aw-elc-usb-owner'",
            )
        # Drop dead usb2 host=2-3 if present (optional cleanup)
        _run(
            client,
            f"ssh -o StrictHostKeyChecking=no root@{PROXMOX} "
            f"\"qm config 100 | grep -q '^usb2:.*host=2-3' && qm set 100 --delete usb2 || true\"",
        )
        print(f"=== bt-usb-owner {action} ===")
        _run(
            client,
            f"ssh -o StrictHostKeyChecking=no root@{PROXMOX} '/usr/local/sbin/bt-usb-owner {action}'",
            timeout=120,
        )
        print("=== status ===")
        _run(
            client,
            f"ssh -o StrictHostKeyChecking=no root@{PROXMOX} "
            f"'/usr/local/sbin/bt-usb-owner status; echo ----; qm config 100 | grep -i ^usb'",
        )
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
