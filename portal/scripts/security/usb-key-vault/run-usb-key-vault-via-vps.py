#!/usr/bin/env python3
"""Create/mount the ServerManager LUKS USB key vault on Proxmox via the VPS hop."""
from __future__ import annotations

import argparse
import base64
import io
import os
import shlex
import sys
from pathlib import Path

import paramiko

SCRIPTS = Path(__file__).resolve().parent
DEFAULT_HOST = "74.208.76.213"
PROXMOX = "192.168.8.160"
# ~128GB Norelsys flash drive (not WD Elements)
DEFAULT_USB_BY_ID = "/dev/disk/by-id/usb-NORELSYS_1081_F9CB2147CF3A-0:0"


def _client() -> paramiko.SSHClient:
    host = os.environ.get("VPS_HOST", DEFAULT_HOST).strip()
    user = os.environ.get("VPS_USER", "truekingofthekill").strip() or "truekingofthekill"
    port = int(os.environ.get("VPS_PORT", "22"))
    key_path = os.environ.get("VPS_SSH_KEY", "").strip()
    key_text = os.environ.get("VPS_SSH_PRIVATE_KEY", "").strip()
    password = os.environ.get("VPS_SSH_PASSWORD", "").strip()
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
    if key_path and Path(key_path).is_file():
        kw["pkey"] = paramiko.Ed25519Key.from_private_key_file(key_path)
    elif key_text:
        try:
            kw["pkey"] = paramiko.Ed25519Key.from_private_key(io.StringIO(key_text))
        except Exception:
            kw["pkey"] = paramiko.RSAKey.from_private_key(io.StringIO(key_text))
    elif password:
        kw["password"] = password
    else:
        fallback = Path.home() / ".ssh" / "id_ed25519_truekingofthekill"
        if fallback.is_file():
            kw["pkey"] = paramiko.Ed25519Key.from_private_key_file(str(fallback))
        else:
            raise SystemExit("Set VPS_SSH_KEY, VPS_SSH_PRIVATE_KEY, or VPS_SSH_PASSWORD")
    client.connect(**kw)
    return client


def _shell_quote(s: str) -> str:
    return shlex.quote(s)


def _run(client: paramiko.SSHClient, cmd: str, timeout: int = 600) -> str:
    full = f"sudo bash -lc {_shell_quote(cmd)}"
    _, stdout, stderr = client.exec_command(full, timeout=timeout)
    code = stdout.channel.recv_exit_status()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    if out:
        print(out, end="" if out.endswith("\n") else "\n")
    if err:
        for line in err.splitlines():
            if "unable to resolve host" in line:
                continue
            print(line, file=sys.stderr)
    if code != 0:
        raise RuntimeError(f"exit {code}: {cmd[:200]}")
    return out


def _push_scripts(client: paramiko.SSHClient, names: list[str]) -> None:
    remote_dir = "/tmp/sm-usb-key-vault"
    _run(client, f"mkdir -p {remote_dir}", timeout=30)
    for name in names:
        local = SCRIPTS / name
        if not local.is_file():
            raise SystemExit(f"missing {local}")
        b64 = base64.b64encode(local.read_bytes()).decode("ascii")
        remote = f"{remote_dir}/{name}"
        _run(
            client,
            "python3 -c "
            + _shell_quote(
                "import base64,pathlib; "
                f"pathlib.Path('{remote}').write_bytes(base64.b64decode('{b64}'))"
            ),
            timeout=60,
        )
    _run(
        client,
        f"ip route replace 192.168.8.0/24 via 10.9.0.2 dev tun0 metric 5 2>/dev/null || true; "
        f"scp -o StrictHostKeyChecking=no -r {remote_dir} root@{PROXMOX}:/tmp/ && "
        f"ssh -o StrictHostKeyChecking=no root@{PROXMOX} 'chmod +x /tmp/sm-usb-key-vault/*.sh'",
        timeout=120,
    )


def _pve(client: paramiko.SSHClient, remote_cmd: str, timeout: int = 600) -> str:
    return _run(
        client,
        f"ip route replace 192.168.8.0/24 via 10.9.0.2 dev tun0 metric 5 2>/dev/null || true; "
        f"ssh -o StrictHostKeyChecking=no root@{PROXMOX} {_shell_quote(remote_cmd)}",
        timeout=timeout,
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="USB LUKS key vault on Proxmox via VPS")
    ap.add_argument(
        "action",
        choices=["create", "keygen", "mount", "dismount", "status", "setup"],
        help="setup = create + keygen + dismount",
    )
    ap.add_argument("--size-mb", type=int, default=256)
    ap.add_argument("--usb-by-id", default=DEFAULT_USB_BY_ID)
    ap.add_argument("--comment", default="servermanager-usb-vault@proxmox")
    ap.add_argument("--passphrase", default=os.environ.get("LUKS_PASSPHRASE", ""))
    args = ap.parse_args()

    scripts = [
        "new-sm-usb-key-vault.sh",
        "mount-sm-usb-key-vault.sh",
        "dismount-sm-usb-key-vault.sh",
        "new-sm-usb-ssh-key.sh",
    ]
    client = _client()
    try:
        _push_scripts(client, scripts)

        def env_prefix(extra: str = "") -> str:
            parts = [
                f"USB_BY_ID={_shell_quote(args.usb_by_id)}",
                f"SIZE_MB={args.size_mb}",
                f"COMMENT={_shell_quote(args.comment)}",
            ]
            if args.passphrase:
                parts.append(f"PASSPHRASE={_shell_quote(args.passphrase)}")
            if extra:
                parts.append(extra)
            return " ".join(parts)

        if args.action in ("create", "setup"):
            print("=== Create LUKS vault on ~128GB Norelsys USB ===")
            _pve(
                client,
                f"cd /tmp/sm-usb-key-vault && {env_prefix()} bash ./new-sm-usb-key-vault.sh",
                timeout=900,
            )
        if args.action in ("keygen", "setup"):
            print("=== Generate SSH key inside vault ===")
            if args.action == "keygen":
                if not args.passphrase:
                    raise SystemExit("keygen alone needs --passphrase or LUKS_PASSPHRASE")
                _pve(
                    client,
                    f"cd /tmp/sm-usb-key-vault && {env_prefix()} bash ./mount-sm-usb-key-vault.sh",
                    timeout=300,
                )
            _pve(
                client,
                f"cd /tmp/sm-usb-key-vault && {env_prefix()} bash ./new-sm-usb-ssh-key.sh",
                timeout=120,
            )
        if args.action == "mount":
            if not args.passphrase:
                raise SystemExit("mount needs --passphrase or LUKS_PASSPHRASE")
            _pve(
                client,
                f"cd /tmp/sm-usb-key-vault && {env_prefix('ADD_TO_SSH_AGENT=1')} "
                f"bash ./mount-sm-usb-key-vault.sh",
            )
        if args.action == "dismount":
            _pve(client, "cd /tmp/sm-usb-key-vault && bash ./dismount-sm-usb-key-vault.sh")
        if args.action == "setup":
            print("=== Dismount vault ===")
            _pve(client, "cd /tmp/sm-usb-key-vault && bash ./dismount-sm-usb-key-vault.sh")
        if args.action == "status":
            _pve(
                client,
                "echo '=== USB ==='; lsblk -o NAME,SIZE,TRAN,RM,MODEL,FSTYPE,LABEL,MOUNTPOINT; "
                "echo; echo '=== mapper ==='; ls -la /dev/mapper/sm-key-vault 2>/dev/null || echo '(closed)'; "
                "echo; echo '=== mounts ==='; findmnt /mnt/sm-key-vault /mnt/sm-usb-stick 2>/dev/null || true; "
                "echo; echo '=== by-id ==='; ls -la /dev/disk/by-id/usb-NORELSYS* 2>/dev/null || true",
            )
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
