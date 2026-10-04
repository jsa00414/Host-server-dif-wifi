#!/usr/bin/env python3
"""Deploy portal files to the VPS over SSH (key or password)."""
from __future__ import annotations

import os
import shlex
import sys
from pathlib import Path

import paramiko

ROOT = Path(__file__).resolve().parent
REMOTE_UI = "/opt/wireguard/port-forward-ui"
DEFAULT_HOST = "74.208.76.213"
# Root SSH is keys-only / restricted; deploy as the sudo-capable operator account.
DEFAULT_USER = "truekingofthekill"
FALLBACK_KEY = Path.home() / ".ssh" / "id_ed25519_truekingofthekill"

UPLOADS: list[tuple[Path, str]] = [
    (ROOT / "server.py", f"{REMOTE_UI}/server.py"),
    (ROOT / "static/index.html", f"{REMOTE_UI}/static/index.html"),
    (ROOT / "static/login.html", f"{REMOTE_UI}/static/login.html"),
    (ROOT / "static/files.html", f"{REMOTE_UI}/static/files.html"),
    (ROOT / "static/nas-windows.html", f"{REMOTE_UI}/static/nas-windows.html"),
    (ROOT / "static/windows-vpn.html", f"{REMOTE_UI}/static/windows-vpn.html"),
    (ROOT / "static/email-code-test.html", f"{REMOTE_UI}/static/email-code-test.html"),
    (ROOT / "static/auth-app.html", f"{REMOTE_UI}/static/auth-app.html"),
    (ROOT / "static/auth-app.webmanifest", f"{REMOTE_UI}/static/auth-app.webmanifest"),
    (ROOT / "static/auth-app-sw.js", f"{REMOTE_UI}/static/auth-app-sw.js"),
    (ROOT / "static/auth-app-iphone.html", f"{REMOTE_UI}/static/auth-app-iphone.html"),
    (ROOT / "static/auth-app-iphone.webmanifest", f"{REMOTE_UI}/static/auth-app-iphone.webmanifest"),
    (ROOT / "static/auth-app-iphone-sw.js", f"{REMOTE_UI}/static/auth-app-iphone-sw.js"),
    (ROOT / "static/auth-app-icon-180.png", f"{REMOTE_UI}/static/auth-app-icon-180.png"),
    (ROOT / "static/auth-app-icon-192.png", f"{REMOTE_UI}/static/auth-app-icon-192.png"),
    (ROOT / "static/auth-app-icon-512.png", f"{REMOTE_UI}/static/auth-app-icon-512.png"),
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
    (
        ROOT / "scripts/nas/install-nas-sftp-gateway.sh",
        f"{REMOTE_UI}/scripts/nas/install-nas-sftp-gateway.sh",
    ),
    (
        ROOT / "scripts/nas/nas-sftp-gateway.service",
        f"{REMOTE_UI}/scripts/nas/nas-sftp-gateway.service",
    ),
    (
        ROOT / "scripts/backup/sm-backup.sh",
        "/opt/servermanager-backup/sm-backup.sh",
    ),
    (
        ROOT / "scripts/backup/secrets.env.example",
        "/opt/servermanager-backup/secrets.env.example",
    ),
    (
        ROOT / "scripts/backup/sm-backup.service",
        "/etc/systemd/system/sm-backup.service",
    ),
    (
        ROOT / "scripts/backup/sm-backup.timer",
        "/etc/systemd/system/sm-backup.timer",
    ),
    (
        ROOT / "scripts/security/harden-secret-perms.sh",
        f"{REMOTE_UI}/scripts/security/harden-secret-perms.sh",
    ),
    (
        ROOT / "scripts/security/harden-smb-vpn-only.sh",
        f"{REMOTE_UI}/scripts/security/harden-smb-vpn-only.sh",
    ),
    (
        ROOT / "scripts/security/harden-portal-5002-vpn-only.sh",
        f"{REMOTE_UI}/scripts/security/harden-portal-5002-vpn-only.sh",
    ),
    (
        ROOT / "scripts/security/harden-nas-gateways-vpn-only.sh",
        f"{REMOTE_UI}/scripts/security/harden-nas-gateways-vpn-only.sh",
    ),
    (
        ROOT / "scripts/security/harden-wg-easy-ui-vpn-only.sh",
        f"{REMOTE_UI}/scripts/security/harden-wg-easy-ui-vpn-only.sh",
    ),
    (
        ROOT / "scripts/security/harden-remote-desktop-bind.sh",
        f"{REMOTE_UI}/scripts/security/harden-remote-desktop-bind.sh",
    ),
    (
        ROOT / "scripts/security/harden-flint-forwards-vpn-only.sh",
        f"{REMOTE_UI}/scripts/security/harden-flint-forwards-vpn-only.sh",
    ),
    (
        ROOT / "scripts/security/retire-old-vps-ip.sh",
        f"{REMOTE_UI}/scripts/security/retire-old-vps-ip.sh",
    ),
    (
        ROOT / "scripts/security/check-circle-drift.sh",
        f"{REMOTE_UI}/scripts/security/check-circle-drift.sh",
    ),
    (
        ROOT / "scripts/security/sm-circle-drift.service",
        "/etc/systemd/system/sm-circle-drift.service",
    ),
    (
        ROOT / "scripts/security/sm-circle-drift.timer",
        "/etc/systemd/system/sm-circle-drift.timer",
    ),
    (
        ROOT / "scripts/backup/sm-backup-restore-drill.sh",
        "/opt/servermanager-backup/sm-backup-restore-drill.sh",
    ),
    (
        ROOT / "scripts/ikev2/ensure-lan-circle-flint-gate.sh",
        "/opt/ikev2/ensure-lan-circle-flint-gate.sh",
    ),
    (
        ROOT / "scripts/ikev2/ensure-ikev2-forward.sh",
        "/opt/ikev2/ensure-ikev2-forward.sh",
    ),
    (
        ROOT / "scripts/ikev2/ensure-vpn-client-gate.sh",
        "/opt/ikev2/ensure-vpn-client-gate.sh",
    ),
    (
        ROOT / "scripts/mail/ensure-portal-send-mailbox.sh",
        f"{REMOTE_UI}/scripts/mail/ensure-portal-send-mailbox.sh",
    ),
    (
        ROOT / "scripts/forwards/apply-lan-forwards.sh",
        "/opt/wireguard/scripts/apply-lan-forwards.sh",
    ),
]


def _client() -> paramiko.SSHClient:
    host = os.environ.get("VPS_HOST", DEFAULT_HOST).strip()
    user = os.environ.get("VPS_USER", DEFAULT_USER).strip() or DEFAULT_USER
    port = int(os.environ.get("VPS_PORT", "22"))
    key_path = os.environ.get("VPS_SSH_KEY", "").strip()
    key_text = os.environ.get("VPS_SSH_PRIVATE_KEY", "").strip()
    password = os.environ.get("VPS_SSH_PASSWORD", "").strip()

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
    if key_path and Path(key_path).is_file():
        connect_kwargs["pkey"] = paramiko.Ed25519Key.from_private_key_file(key_path)
    elif key_text:
        import io as _io

        key_file = _io.StringIO(key_text if key_text.endswith("\n") else key_text + "\n")
        last_exc: Exception | None = None
        pkey = None
        for loader in (
            paramiko.Ed25519Key.from_private_key,
            paramiko.ECDSAKey.from_private_key,
            paramiko.RSAKey.from_private_key,
        ):
            try:
                key_file.seek(0)
                pkey = loader(key_file)
                break
            except Exception as exc:  # noqa: BLE001 — try next key type
                last_exc = exc
        if pkey is None:
            raise RuntimeError(f"Unsupported SSH private key format: {last_exc}")
        connect_kwargs["pkey"] = pkey
    elif password:
        connect_kwargs["password"] = password
    elif FALLBACK_KEY.is_file():
        connect_kwargs["pkey"] = paramiko.Ed25519Key.from_private_key_file(str(FALLBACK_KEY))
    else:
        raise SystemExit(
            "Missing VPS credentials. Set VPS_SSH_KEY, VPS_SSH_PRIVATE_KEY, or VPS_SSH_PASSWORD."
        )
    client.connect(**connect_kwargs)
    return client


def _run(client: paramiko.SSHClient, cmd: str) -> None:
    """Run as root via sudo when connected as a non-root operator."""
    user = os.environ.get("VPS_USER", DEFAULT_USER).strip() or DEFAULT_USER
    full = cmd if user == "root" else f"sudo bash -lc {shlex.quote(cmd)}"
    _, stdout, stderr = client.exec_command(full)
    exit_code = stdout.channel.recv_exit_status()
    out = stdout.read().decode("utf-8", errors="replace").strip()
    err = stderr.read().decode("utf-8", errors="replace").strip()
    # Ignore transient sudo hostname resolution noise.
    err_lines = [
        line
        for line in err.splitlines()
        if "unable to resolve host" not in line
    ]
    err = "\n".join(err_lines).strip()
    if exit_code != 0:
        raise RuntimeError(f"Command failed ({exit_code}): {cmd}\n{err or out}")
    if out:
        print(out)


def _sftp_put(client: paramiko.SSHClient, local: Path, remote: str) -> None:
    """Upload via /tmp then sudo install (operator may lack write on /opt)."""
    user = os.environ.get("VPS_USER", DEFAULT_USER).strip() or DEFAULT_USER
    if user == "root":
        sftp = client.open_sftp()
        try:
            sftp.put(str(local), remote)
        finally:
            sftp.close()
        return
    remote_tmp = f"/tmp/sm-deploy-{Path(remote).name}.{os.getpid()}"
    sftp = client.open_sftp()
    try:
        sftp.put(str(local), remote_tmp)
    finally:
        sftp.close()
    _run(
        client,
        f"install -D -m 0644 {shlex.quote(remote_tmp)} {shlex.quote(remote)} && "
        f"rm -f {shlex.quote(remote_tmp)}",
    )


def main() -> int:
    host = os.environ.get("VPS_HOST", DEFAULT_HOST).strip()
    print(f"Deploying portal to {host}:{REMOTE_UI} …")
    client = _client()
    try:
        _run(
            client,
            f"mkdir -p {REMOTE_UI}/static {REMOTE_UI}/scripts/nas",
        )
        for local, remote in UPLOADS:
            if not local.is_file():
                raise FileNotFoundError(f"Missing local file: {local}")
            print(f"  upload {local.name} -> {remote}")
            _sftp_put(client, local, remote)

        if host == DEFAULT_HOST:
            _run(
                client,
                f"chmod +x {REMOTE_UI}/scripts/security/retire-old-vps-ip.sh "
                f"{REMOTE_UI}/scripts/mail/ensure-portal-send-mailbox.sh && "
                f"bash {REMOTE_UI}/scripts/security/retire-old-vps-ip.sh || true; "
                f"bash {REMOTE_UI}/scripts/mail/ensure-portal-send-mailbox.sh || true",
            )
        _run(
            client,
            f"mkdir -p {REMOTE_UI}/sm /var/lib/node_exporter/textfile_collector && "
            "export DEBIAN_FRONTEND=noninteractive; "
            "apt-get install -y -qq python3.12-venv >/dev/null 2>&1 || apt-get install -y -qq python3-venv >/dev/null 2>&1 || true; "
            f"python3 -m venv {REMOTE_UI}/.venv; "
            f"{REMOTE_UI}/.venv/bin/pip install -q --upgrade pip; "
            f"{REMOTE_UI}/.venv/bin/pip install -q 'webauthn>=2.0'; "
            "python3 - <<'PY'\n"
            "from pathlib import Path\n"
            "import re\n"
            "u=Path('/etc/systemd/system/port-forward-ui.service')\n"
            "t=u.read_text()\n"
            "t2=re.sub(r'^ExecStart=.*$', "
            f"'ExecStart={REMOTE_UI}/.venv/bin/python {REMOTE_UI}/server.py', t, count=1, flags=re.M)\n"
            "u.write_text(t2)\n"
            "PY",
        )
        for local in (ROOT / "sm").rglob("*"):
            if not local.is_file() or "__pycache__" in local.parts:
                continue
            rel = local.relative_to(ROOT).as_posix()
            remote = f"{REMOTE_UI}/{rel}"
            _run(client, f"mkdir -p {Path(remote).parent.as_posix()}")
            print(f"  upload {rel} -> {remote}")
            _sftp_put(client, local, remote)
        _run(client, "systemctl daemon-reload && systemctl restart port-forward-ui && systemctl is-active port-forward-ui")
        _run(
            client,
            "chmod +x /opt/wireguard/port-forward-ui/scripts/security/check-circle-drift.sh "
            "/opt/servermanager-backup/sm-backup-restore-drill.sh 2>/dev/null || true; "
            "systemctl enable --now sm-circle-drift.timer 2>/dev/null || true; "
            "bash /opt/wireguard/port-forward-ui/scripts/security/check-circle-drift.sh || true; "
            "bash /opt/servermanager-backup/sm-backup-restore-drill.sh || true",
        )
        _run(
            client,
            "chmod +x /opt/openvpn/scripts/client-connect.sh /opt/openvpn/scripts/client-disconnect.sh /opt/openvpn/scripts/flint-allow-vpn-ssh.sh "
            "/opt/servermanager-backup/sm-backup.sh 2>/dev/null || true",
        )
        _run(
            client,
            "systemctl daemon-reload && "
            "systemctl enable --now sm-backup.timer 2>/dev/null || true && "
            "systemctl is-enabled sm-backup.timer 2>/dev/null || true",
        )
        # Grafana: localhost bind + Caddy docker network + unique admin password
        _run(
            client,
            f"mkdir -p {REMOTE_UI}/scripts/grafana "
            f"{REMOTE_UI}/scripts/grafana/dashboards "
            f"{REMOTE_UI}/scripts/grafana/prometheus "
            f"{REMOTE_UI}/scripts/grafana/provisioning/dashboards "
            f"{REMOTE_UI}/scripts/grafana/provisioning/datasources "
            "/opt/grafana",
        )
        groot = ROOT / "scripts" / "grafana"
        for local in groot.rglob("*"):
            if not local.is_file():
                continue
            rel = local.relative_to(groot).as_posix()
            remote = f"{REMOTE_UI}/scripts/grafana/{rel}"
            remote_dir = str(Path(remote).parent)
            _run(client, f"mkdir -p {remote_dir}")
            print(f"  upload grafana/{rel} -> {remote}")
            _sftp_put(client, local, remote)
        _run(
            client,
            f"chmod +x {REMOTE_UI}/scripts/grafana/install-grafana.sh && "
            f"bash {REMOTE_UI}/scripts/grafana/install-grafana.sh",
        )
        _run(
            client,
            "cd /opt/wireguard/port-forward-ui && set -a && . /opt/wireguard/port-forward-ui.env && set +a && python3 -c \""
            "import server; "
            "s=server.read_hookups_state(); "
            "rules=[r for r in s.get('rules', []) if not r.get('external')]; "
            "print(server.write_hookups_state(rules))"
            "\"",
        )
        # FTP gateway retired by default (NAS_FTP_RETIRED=1).
        _run(
            client,
            "set -a; . /opt/wireguard/port-forward-ui.env; set +a; "
            "if [ \"${NAS_FTP_RETIRED:-1}\" = \"0\" ]; then "
            f"chmod +x {REMOTE_UI}/scripts/nas/install-nas-ftp-gateway.sh && "
            f"bash {REMOTE_UI}/scripts/nas/install-nas-ftp-gateway.sh; "
            "else systemctl disable --now nas-ftp-gateway.service 2>/dev/null || true; "
            "echo FTP retired; fi",
        )
        dav = f"{REMOTE_UI}/scripts/nas/install-nas-webdav-gateway.sh"
        _run(client, f"chmod +x {dav} && bash {dav}")
        sftp_gw = f"{REMOTE_UI}/scripts/nas/install-nas-sftp-gateway.sh"
        _run(client, f"chmod +x {sftp_gw} && bash {sftp_gw}")
        _run(
            client,
            f"chmod +x {REMOTE_UI}/scripts/security/harden-nas-gateways-vpn-only.sh "
            f"/opt/ikev2/ensure-ikev2-forward.sh "
            f"/opt/ikev2/ensure-vpn-client-gate.sh "
            f"/opt/ikev2/ensure-lan-circle-flint-gate.sh && "
            f"bash {REMOTE_UI}/scripts/security/harden-nas-gateways-vpn-only.sh && "
            f"bash /opt/ikev2/ensure-ikev2-forward.sh",
        )
        _run(
            client,
            f"chmod +x {REMOTE_UI}/scripts/security/harden-remote-desktop-bind.sh "
            f"{REMOTE_UI}/scripts/security/harden-flint-forwards-vpn-only.sh "
            f"/opt/wireguard/scripts/apply-lan-forwards.sh && "
            f"bash {REMOTE_UI}/scripts/security/harden-remote-desktop-bind.sh && "
            f"bash {REMOTE_UI}/scripts/security/harden-flint-forwards-vpn-only.sh",
        )
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
