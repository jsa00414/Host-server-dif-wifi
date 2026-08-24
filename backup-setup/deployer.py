"""SSH install of ServerManager backup agent + GitHub connectivity."""

from __future__ import annotations

import io
import json
import os
import sys
import tarfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import paramiko

LogFn = Callable[[str], None]
INSTALL_DIR = "/opt/servermanager-backup"


def _bundle_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS) / "scripts"
    return Path(__file__).resolve().parent / "scripts"


SCRIPTS_DIR = _bundle_dir()


@dataclass
class BackupConfig:
    vps_host: str
    vps_port: int
    ssh_user: str
    ssh_password: str | None
    ssh_key_path: str | None
    github_token: str
    github_owner: str
    github_repo: str
    github_branch: str = "main"
    backup_hour: int = 3
    create_repo_if_missing: bool = True


def _connect(cfg: BackupConfig) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs: dict = {
        "hostname": cfg.vps_host,
        "port": cfg.vps_port,
        "username": cfg.ssh_user,
        "timeout": 30,
        "allow_agent": False,
        "look_for_keys": False,
    }
    if cfg.ssh_key_path and os.path.isfile(cfg.ssh_key_path):
        kwargs["key_filename"] = cfg.ssh_key_path
    elif cfg.ssh_password:
        kwargs["password"] = cfg.ssh_password
    else:
        raise ValueError("Provide an SSH private key path or password.")
    client.connect(**kwargs)
    return client


def _run(client: paramiko.SSHClient, cmd: str, log: LogFn, timeout: int = 600) -> tuple[int, str]:
    log(f"$ {cmd}")
    _, stdout, stderr = client.exec_command(cmd, get_pty=True, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    code = stdout.channel.recv_exit_status()
    text = (out + ("\n" + err if err and code else "")).strip()
    if text:
        for line in text.splitlines()[-80:]:
            log(line)
    return code, text


def test_ssh_connection(cfg: BackupConfig, log: LogFn) -> None:
    client = _connect(cfg)
    try:
        code, _ = _run(client, "uname -a && hostname && whoami", log)
        if code != 0:
            raise RuntimeError("SSH connected but remote command failed.")
        log("SSH OK")
    finally:
        client.close()


def ensure_github_repo(cfg: BackupConfig, log: LogFn) -> None:
    token = cfg.github_token.strip()
    owner = cfg.github_owner.strip()
    repo = cfg.github_repo.strip()
    api = f"https://api.github.com/repos/{owner}/{repo}"
    req = urllib.request.Request(
        api,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "ServerManager-Backup-Setup",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
            log(f"GitHub repo exists: {data.get('html_url')} (private={data.get('private')})")
            return
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"GitHub API error {exc.code}: {body[:300]}") from exc

    if not cfg.create_repo_if_missing:
        raise RuntimeError(
            f"Repo {owner}/{repo} not found. Create it at "
            f"https://github.com/new or enable auto-create."
        )

    log(f"Creating private repo {owner}/{repo}…")
    payload = json.dumps(
        {
            "name": repo,
            "private": True,
            "description": "ServerManager VPS config backups",
            "auto_init": True,
        }
    ).encode()
    # Try user repo create first
    create_urls = [
        "https://api.github.com/user/repos",
        f"https://api.github.com/orgs/{owner}/repos",
    ]
    last_err = ""
    for url in create_urls:
        req = urllib.request.Request(
            url,
            data=payload,
            method="POST",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "User-Agent": "ServerManager-Backup-Setup",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())
                log(f"Created: {data.get('html_url')}")
                return
        except urllib.error.HTTPError as exc:
            last_err = exc.read().decode("utf-8", errors="replace")[:400]
            continue
    raise RuntimeError(
        "Could not create GitHub repo automatically.\n"
        f"Create https://github.com/{owner}/{repo} as a private empty repo, then retry.\n"
        f"API said: {last_err}"
    )


def _upload_scripts(client: paramiko.SSHClient, log: LogFn) -> None:
    log("Uploading backup scripts…")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name in ("sm-backup.sh", "install-on-vps.sh"):
            path = SCRIPTS_DIR / name
            if not path.is_file():
                raise FileNotFoundError(f"Missing bundled script: {path}")
            tar.add(path, arcname=name)
    buf.seek(0)
    sftp = client.open_sftp()
    try:
        _run(client, "mkdir -p /tmp/sm-backup-install", log)
        remote = "/tmp/sm-backup-install/bundle.tgz"
        with sftp.file(remote, "wb") as rf:
            rf.write(buf.read())
    finally:
        sftp.close()
    code, _ = _run(
        client,
        "mkdir -p /tmp/sm-backup-install && tar -xzf /tmp/sm-backup-install/bundle.tgz -C /tmp/sm-backup-install && chmod +x /tmp/sm-backup-install/*.sh",
        log,
    )
    if code != 0:
        raise RuntimeError("Failed to unpack scripts on VPS")


def install_backup(cfg: BackupConfig, log: LogFn) -> None:
    ensure_github_repo(cfg, log)
    client = _connect(cfg)
    try:
        _upload_scripts(client, log)
        env_exports = " ".join(
            [
                f"GITHUB_OWNER={_shell_quote(cfg.github_owner.strip())}",
                f"GITHUB_REPO={_shell_quote(cfg.github_repo.strip())}",
                f"GITHUB_TOKEN={_shell_quote(cfg.github_token.strip())}",
                f"GITHUB_BRANCH={_shell_quote(cfg.github_branch.strip() or 'main')}",
                f"BACKUP_HOUR={int(cfg.backup_hour)}",
                "BACKUP_NAME=vps",
            ]
        )
        code, _ = _run(
            client,
            f"cd /tmp/sm-backup-install && {env_exports} bash ./install-on-vps.sh",
            log,
            timeout=900,
        )
        if code != 0:
            raise RuntimeError("install-on-vps.sh failed — see log above")
        log("")
        log("Backup agent installed.")
        log(f"Daily timer enabled. Repo: https://github.com/{cfg.github_owner}/{cfg.github_repo}")
        log(f"On VPS: {INSTALL_DIR}/backup.log")
    finally:
        client.close()


def _shell_quote(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"
