"""SSH deployment logic for VPS WireGuard Setup."""

from __future__ import annotations

import io
import os
import secrets
import sys
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import paramiko

from cloudflare import CloudflareConfig, CloudflareError, setup_deployment_dns, verify_token

LogFn = Callable[[str], None]
WG_EASY_VERSION = "15.3.0"
INSTALL_DIR = "/opt/vps-wireguard"


def _server_dir() -> Path:
    """Resolve server bundle path (supports PyInstaller frozen exe)."""
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS) / "server"
    return Path(__file__).resolve().parent.parent / "server"


SERVER_DIR = _server_dir()


@dataclass
class DeployConfig:
    vps_host: str
    vps_port: int
    ssh_user: str
    ssh_password: str | None
    ssh_key_path: str | None
    wg_tunnel_port: int
    wg_ui_port: int
    wg_domain: str
    caddy_email: str
    domain_manager_host: str
    vpn_subnet: str
    cloudflare_api_token: str = ""
    cloudflare_zone_name: str = ""
    cloudflare_zone_id: str = ""
    cloudflare_proxied: bool = True
    cloudflare_auto_dns: bool = True
    cloudflare_dns_tls: bool = True


def _connect(cfg: DeployConfig) -> paramiko.SSHClient:
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


def _run(client: paramiko.SSHClient, cmd: str, log: LogFn) -> tuple[int, str, str]:
    log(f"$ {cmd}")
    _, stdout, stderr = client.exec_command(cmd, get_pty=True)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    exit_code = stdout.channel.recv_exit_status()
    if out.strip():
        for line in out.strip().splitlines():
            log(line)
    if err.strip() and exit_code != 0:
        for line in err.strip().splitlines():
            log(f"[stderr] {line}")
    return exit_code, out, err


def _build_env(cfg: DeployConfig, admin_token: str) -> str:
    wg_domain = cfg.wg_domain.strip() or "localhost"
    domain_manager_host = cfg.domain_manager_host.strip() or f"domains.{cfg.vps_host}"

    template_path = SERVER_DIR / ".env.template"
    template = template_path.read_text()
    return template.format(
        vps_host=cfg.vps_host,
        wg_tunnel_port=cfg.wg_tunnel_port,
        wg_ui_port=cfg.wg_ui_port,
        wg_domain=wg_domain,
        caddy_email=cfg.caddy_email or f"admin@{wg_domain}",
        domain_manager_host=domain_manager_host,
        domain_admin_token=admin_token,
        vpn_subnet=cfg.vpn_subnet,
        cloudflare_api_token=cfg.cloudflare_api_token,
        cloudflare_zone_name=cfg.cloudflare_zone_name,
        cloudflare_zone_id=cfg.cloudflare_zone_id,
        cloudflare_proxied=str(cfg.cloudflare_proxied).lower(),
        cloudflare_dns_tls=str(cfg.cloudflare_dns_tls).lower(),
    )


def _build_caddyfile(cfg: DeployConfig) -> str:
    wg_domain = cfg.wg_domain.strip()
    domain_manager_host = cfg.domain_manager_host.strip() or f"domains.{cfg.vps_host}"
    caddy_email = cfg.caddy_email or "admin@localhost"
    use_cf_tls = bool(cfg.cloudflare_api_token and cfg.cloudflare_dns_tls)

    global_block = [
        "{",
        f"\temail {caddy_email}",
        "\tadmin off",
    ]
    if use_cf_tls:
        global_block.append("\tacme_dns cloudflare {env.CLOUDFLARE_API_TOKEN}")
    global_block.extend(["}", ""])

    lines = global_block

    if wg_domain and wg_domain.lower() not in ("localhost", "127.0.0.1"):
        wg_lines = [
            f"# WireGuard Easy v{WG_EASY_VERSION} UI over HTTPS",
            f"{wg_domain} {{",
        ]
        if use_cf_tls:
            wg_lines.append("\ttls {\n\t\tdns cloudflare {env.CLOUDFLARE_API_TOKEN}\n\t}")
        wg_lines.extend([
            f"\treverse_proxy wg-easy:{cfg.wg_ui_port}",
            "}",
            "",
        ])
        lines.extend(wg_lines)

    dm_lines = [
        "# Caddy Domain Manager — VPN clients only",
        f"{domain_manager_host} {{",
    ]
    if use_cf_tls:
        dm_lines.append("\ttls {\n\t\tdns cloudflare {env.CLOUDFLARE_API_TOKEN}\n\t}")
    dm_lines.extend([
        f"\t@vpn remote_ip {cfg.vpn_subnet} 127.0.0.1/32 172.28.0.0/24",
        "\thandle @vpn {",
        "\t\treverse_proxy domain-manager:8080",
        "\t}",
        '\trespond "Access denied — connect via WireGuard VPN" 403',
        "}",
        "",
        "# Dynamically managed reverse-proxy sites",
        "import /etc/caddy/domains/*.caddy",
        "",
    ])
    lines.extend(dm_lines)
    return "\n".join(lines)


def _create_tarball(cfg: DeployConfig, admin_token: str) -> bytes:
    buf = io.BytesIO()
    env_content = _build_env(cfg, admin_token)
    caddy_content = _build_caddyfile(cfg)

    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        def add_text(name: str, data: str, mode: int = 0o644):
            encoded = data.encode("utf-8")
            info = tarfile.TarInfo(name=name)
            info.size = len(encoded)
            info.mode = mode
            tar.addfile(info, io.BytesIO(encoded))

        add_text(".env", env_content)
        add_text("Caddyfile", caddy_content)
        add_text("install.sh", (SERVER_DIR / "install.sh").read_text(), mode=0o755)

        compose = (SERVER_DIR / "docker-compose.yml").read_text()
        add_text("docker-compose.yml", compose)

        domains_keep = SERVER_DIR / "domains" / ".gitkeep"
        add_text("domains/.gitkeep", domains_keep.read_text() if domains_keep.exists() else "")

        for rel in ["domain-manager/Dockerfile", "domain-manager/requirements.txt", "domain-manager/app.py", "domain-manager/cloudflare.py"]:
            full = SERVER_DIR / rel
            add_text(rel, full.read_text())

        caddy_dockerfile = SERVER_DIR / "caddy" / "Dockerfile"
        if caddy_dockerfile.exists():
            add_text("caddy/Dockerfile", caddy_dockerfile.read_text())

    buf.seek(0)
    return buf.read()


def deploy(cfg: DeployConfig, log: LogFn) -> dict:
    """Deploy the full stack to the VPS. Returns connection info dict."""
    if not SERVER_DIR.is_dir():
        raise FileNotFoundError(f"Server bundle not found at {SERVER_DIR}")

    if cfg.cloudflare_api_token:
        cf_cfg = CloudflareConfig(
            api_token=cfg.cloudflare_api_token,
            zone_name=cfg.cloudflare_zone_name,
            zone_id=cfg.cloudflare_zone_id,
            proxied=cfg.cloudflare_proxied,
        )
        log("Verifying Cloudflare API token...")
        ok, msg = verify_token(cf_cfg)
        if not ok:
            raise CloudflareError(msg)
        log(msg)

        if cfg.cloudflare_auto_dns:
            hostnames = [cfg.wg_domain, cfg.domain_manager_host]
            log("Creating Cloudflare DNS records...")
            setup_deployment_dns(cf_cfg, cfg.vps_host, hostnames, log)

    admin_token = secrets.token_urlsafe(24)
    tarball = _create_tarball(cfg, admin_token)

    log(f"Connecting to {cfg.ssh_user}@{cfg.vps_host}:{cfg.vps_port}...")
    client = _connect(cfg)
    sftp = client.open_sftp()

    try:
        log("Creating install directory...")
        _run(client, f"mkdir -p {INSTALL_DIR}", log)

        remote_tar = f"/tmp/vps-wireguard-{secrets.token_hex(4)}.tar.gz"
        log("Uploading server bundle...")
        with sftp.file(remote_tar, "wb") as remote:
            remote.write(tarball)

        log("Extracting files...")
        _run(client, f"tar -xzf {remote_tar} -C {INSTALL_DIR}", log)
        _run(client, f"rm -f {remote_tar}", log)
        _run(client, f"chmod +x {INSTALL_DIR}/install.sh", log)

        log("Running install script (Docker + WireGuard Easy + Caddy)...")
        code, _, err = _run(client, f"cd {INSTALL_DIR} && bash install.sh", log)
        if code != 0:
            raise RuntimeError(err or f"Install script failed with exit code {code}")

        domain_manager_host = cfg.domain_manager_host.strip() or f"domains.{cfg.vps_host}"
        wg_domain = cfg.wg_domain.strip()

        return {
            "vps_host": cfg.vps_host,
            "wg_ui_port": cfg.wg_ui_port,
            "wg_tunnel_port": cfg.wg_tunnel_port,
            "wg_easy_url": f"http://{cfg.vps_host}:{cfg.wg_ui_port}",
            "wg_domain": wg_domain,
            "wg_domain_url": f"https://{wg_domain}" if wg_domain and wg_domain != "localhost" else None,
            "domain_manager_host": domain_manager_host,
            "domain_manager_url": f"https://{domain_manager_host}?token={admin_token}",
            "admin_token": admin_token,
            "install_dir": INSTALL_DIR,
        }
    finally:
        sftp.close()
        client.close()


def test_cloudflare_connection(cfg: DeployConfig) -> tuple[bool, str]:
    if not cfg.cloudflare_api_token:
        return False, "Cloudflare API token is empty."
    cf_cfg = CloudflareConfig(
        api_token=cfg.cloudflare_api_token,
        zone_name=cfg.cloudflare_zone_name,
        zone_id=cfg.cloudflare_zone_id,
        proxied=cfg.cloudflare_proxied,
    )
    ok, msg = verify_token(cf_cfg)
    if not ok:
        return False, msg
    try:
        from cloudflare import resolve_zone_id
        zone_id = resolve_zone_id(cf_cfg)
        return True, f"{msg} Zone ID: {zone_id}"
    except CloudflareError as exc:
        return False, str(exc)


def test_ssh_connection(cfg: DeployConfig) -> tuple[bool, str]:
    try:
        client = _connect(cfg)
        code, out, err = 0, "", ""
        _, stdout, stderr = client.exec_command("echo ok", timeout=10)
        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()
        code = stdout.channel.recv_exit_status()
        client.close()
        if code == 0 and out == "ok":
            return True, "SSH connection successful."
        return False, err or "Unexpected SSH response."
    except Exception as exc:
        return False, str(exc)
