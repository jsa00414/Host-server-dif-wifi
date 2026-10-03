#!/usr/bin/env python3
"""ServerManager panel — VPS forwards, GL.iNet router, domains, firewall."""

from __future__ import annotations

import ftplib
import gzip
import http.client
import io
import mimetypes
import base64
import crypt
import hashlib
import hmac
import json
import os
import re
import secrets
import shlex
import shutil
import subprocess
import syslog
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse, urljoin
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

CONF_PATH = Path(os.environ.get("FORWARDS_CONF", "/opt/servermanager/scripts/forwards.conf"))
APPLY_SCRIPT = Path(
    os.environ.get("APPLY_SCRIPT", "/opt/servermanager/scripts/apply-lan-forwards.sh")
)
STATIC_DIR = Path(__file__).resolve().parent / "static"
ROUTER_KNOWN_HOSTS = Path(
    os.environ.get(
        "ROUTER_KNOWN_HOSTS",
        str(Path(__file__).resolve().parent / "router_known_hosts"),
    )
)
HOST = os.environ.get("PF_HOST", "0.0.0.0")
PORT = int(os.environ.get("PF_PORT", "5002"))
AUTH_USER = os.environ.get("PF_USER", "admin")
AUTH_PASS = os.environ.get("PF_PASS", "")
PANEL_TITLE = os.environ.get("PANEL_TITLE", "ServerManager")
PORTAL_HOST = os.environ.get("PORTAL_HOST", "portal.vpstruelord.com").strip()
BUFFALO_UPSTREAM = os.environ.get("BUFFALO_UPSTREAM", "http://192.168.8.159").rstrip("/")
BUFFALO_PREFIX = "/buffalo-frame"
# Buffalo WebAccess file manager (LinkStation :9000)
NAS_FILES_UPSTREAM = os.environ.get("NAS_FILES_UPSTREAM", "http://192.168.8.159:9000").rstrip("/")
NAS_FILES_PREFIX = "/nas-files"
# wg-easy UI (themed same-origin embed under /wg-ui/)
WG_UI_UPSTREAM = os.environ.get("WG_UI_UPSTREAM", "http://127.0.0.1:5001").rstrip("/")
WG_UI_PREFIX = os.environ.get("WG_UI_PREFIX", "/wg-ui").rstrip("/") or "/wg-ui"
WG_UI_PUBLIC_HOSTS = tuple(
    h.strip().lower()
    for h in os.environ.get(
        "WG_UI_PUBLIC_HOSTS",
        "vpn.vpstruelord.com,https://vpn.vpstruelord.com,http://vpn.vpstruelord.com",
    ).split(",")
    if h.strip()
)
WG_EASY_COOKIE = "wg-easy"
WG_EASY_SSO_USER = os.environ.get("WG_EASY_USER", "").strip()
WG_EASY_SSO_PASS = ""  # filled after helpers below / docker fallback
# Flint / school WireGuard client profile (Endpoint :443, MTU 1280).
WG_CLIENT_CONF = Path(
    os.environ.get("WG_CLIENT_CONF", "/opt/wireguard/GL-MT6000.conf")
)
WG_CLIENT_DOWNLOAD_NAME = os.environ.get(
    "WG_CLIENT_DOWNLOAD_NAME", "GL-MT6000-school.conf"
)
WG_CLIENT_NAME = os.environ.get("WG_CLIENT_NAME", "GL-MT6000")
WG_EASY_DB_CONTAINER = os.environ.get("WG_EASY_DB_CONTAINER", "wg-easy")
WG_EASY_DB_PATH = os.environ.get("WG_EASY_DB_PATH", "/etc/wireguard/wg-easy.db")


def _load_wg_easy_pass() -> str:
    b64 = os.environ.get("WG_EASY_PASS_B64", "").strip()
    raw = os.environ.get("WG_EASY_PASS", "")
    if b64:
        try:
            return base64.b64decode(b64).decode("utf-8")
        except Exception:
            pass
    return raw


def _wg_easy_docker_init_creds() -> tuple[str, str]:
    """Fall back to wg-easy container INIT_USERNAME / INIT_PASSWORD when unset."""
    user = ""
    password = ""
    try:
        proc = subprocess.run(
            [
                "docker",
                "inspect",
                "-f",
                "{{range .Config.Env}}{{println .}}{{end}}",
                WG_EASY_DB_CONTAINER,
            ],
            capture_output=True,
            text=True,
            timeout=8,
        )
        for line in (proc.stdout or "").splitlines():
            if line.startswith("INIT_USERNAME="):
                user = line.split("=", 1)[1].strip()
            elif line.startswith("INIT_PASSWORD="):
                password = line.split("=", 1)[1]
    except Exception:
        pass
    return user, password


WG_EASY_SSO_PASS = _load_wg_easy_pass()
if not WG_EASY_SSO_USER or not WG_EASY_SSO_PASS:
    _du, _dp = _wg_easy_docker_init_creds()
    if not WG_EASY_SSO_USER:
        WG_EASY_SSO_USER = (_du or "admin").strip() or "admin"
    if not WG_EASY_SSO_PASS:
        WG_EASY_SSO_PASS = _dp
OVPN_CLIENT_DIR = Path(os.environ.get("OVPN_CLIENT_DIR", "/opt/openvpn/clients"))
OVPN_FLINT_NAME = os.environ.get("OVPN_FLINT_NAME", "flint.ovpn")
OVPN_PHONE_NAME = os.environ.get("OVPN_PHONE_NAME", "james-iphone.ovpn")
OVPN_WINDOWS_NAME = os.environ.get("OVPN_WINDOWS_NAME", "windows.ovpn")
# Optional shared-secret download link (works without portal login / for Caddy
# public path allow). Empty = token downloads disabled.
OVPN_WINDOWS_DL_TOKEN = os.environ.get("OVPN_WINDOWS_DL_TOKEN", "").strip()
OVPN_SCRIPTS_DIR = Path(os.environ.get("OVPN_SCRIPTS_DIR", "/opt/openvpn/scripts"))
OVPN_ALLOW_SSH_SCRIPT = os.environ.get(
    "OVPN_ALLOW_SSH_SCRIPT", "flint-allow-vpn-ssh.sh"
)
OVPN_CREATE_SCRIPT = Path(
    os.environ.get("OVPN_CREATE_SCRIPT", "/opt/openvpn/scripts/create-client.sh")
)
OVPN_BUILD_SCRIPT = Path(
    os.environ.get("OVPN_BUILD_SCRIPT", "/opt/openvpn/scripts/build-client.sh")
)
OVPN_REVOKE_SCRIPT = Path(
    os.environ.get("OVPN_REVOKE_SCRIPT", "/opt/openvpn/scripts/revoke-client.sh")
)
OVPN_PROTECTED_CLIENTS = {
    x.strip().lower()
    for x in os.environ.get("OVPN_PROTECTED_CLIENTS", "flint,server,ca").split(",")
    if x.strip()
}
_OVPN_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")


def _ovpn_validate_name(name: str) -> str:
    name = str(name or "").strip()
    if not _OVPN_NAME_RE.match(name):
        raise ValueError("invalid client name (use letters, numbers, . _ -)")
    if name.lower() in {"server", "ca"}:
        raise ValueError("reserved client name")
    return name


def list_openvpn_clients() -> list[dict]:
    """List issued OpenVPN clients with online + download state."""
    status = parse_openvpn_status(
        OVPN_STATUS_LOG.read_text(encoding="utf-8", errors="replace")
        if OVPN_STATUS_LOG.is_file()
        else ""
    )
    online = {
        str(c.get("name") or "").strip().lower(): c for c in (status.get("clients") or [])
    }
    issued_dir = Path(os.environ.get("OVPN_PKI", "/opt/openvpn/easy-rsa/pki")) / "issued"
    clients: list[dict] = []
    names: set[str] = set()
    if issued_dir.is_dir():
        for crt in sorted(issued_dir.glob("*.crt")):
            name = crt.stem
            if name.lower() == "server":
                continue
            names.add(name)
    # Also include any leftover .ovpn without crt (unlikely)
    if OVPN_CLIENT_DIR.is_dir():
        for ovpn in OVPN_CLIENT_DIR.glob("*.ovpn"):
            if ovpn.stem in {"GL-MT6000"}:
                continue
            names.add(ovpn.stem)
    for name in sorted(names, key=str.lower):
        ovpn_path = OVPN_CLIENT_DIR / f"{name}.ovpn"
        live = online.get(name.lower())
        clients.append(
            {
                "name": name,
                "protected": name.lower() in OVPN_PROTECTED_CLIENTS,
                "has_profile": ovpn_path.is_file(),
                "download": f"/api/openvpn/clients/{name}",
                "online": bool(live),
                "real_address": (live or {}).get("real_address") or "",
                "bytes_received": (live or {}).get("bytes_received") or 0,
                "bytes_sent": (live or {}).get("bytes_sent") or 0,
                "connected_since": (live or {}).get("connected_since") or "",
            }
        )
    return clients


def create_openvpn_client(name: str, redirect_gateway: bool = True) -> dict:
    """Create (or rebuild) an OpenVPN client profile via easy-rsa."""
    name = _ovpn_validate_name(name)
    if not OVPN_CREATE_SCRIPT.is_file():
        raise RuntimeError(f"missing create script {OVPN_CREATE_SCRIPT}")
    redirect = "1" if redirect_gateway and name.lower() != "flint" else "0"
    proc = subprocess.run(
        ["bash", str(OVPN_CREATE_SCRIPT), name, redirect],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env={**os.environ, "OVPN_REDIRECT_GATEWAY": redirect},
    )
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "create failed").strip()
        raise RuntimeError(err[-500:])
    ovpn = OVPN_CLIENT_DIR / f"{name}.ovpn"
    if not ovpn.is_file():
        raise RuntimeError("client created but profile missing")
    return {
        "ok": True,
        "name": name,
        "download": f"/api/openvpn/clients/{name}",
        "stdout": (proc.stdout or "").strip()[-500:],
        "clients": list_openvpn_clients(),
    }


def revoke_openvpn_client(name: str) -> dict:
    """Revoke a client cert and remove its .ovpn."""
    name = _ovpn_validate_name(name)
    if name.lower() in OVPN_PROTECTED_CLIENTS:
        raise ValueError(f"refusing to revoke protected client {name}")
    if not OVPN_REVOKE_SCRIPT.is_file():
        raise RuntimeError(f"missing revoke script {OVPN_REVOKE_SCRIPT}")
    proc = subprocess.run(
        ["bash", str(OVPN_REVOKE_SCRIPT), name],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "revoke failed").strip()
        raise RuntimeError(err[-500:])
    return {
        "ok": True,
        "name": name,
        "stdout": (proc.stdout or "").strip()[-500:],
        "clients": list_openvpn_clients(),
    }


def load_openvpn_client_by_name(name: str) -> tuple[str, bytes]:
    name = _ovpn_validate_name(name)
    path = OVPN_CLIENT_DIR / f"{name}.ovpn"
    if not path.is_file():
        # Rebuild from cert if present
        if OVPN_BUILD_SCRIPT.is_file() and (
            Path("/opt/openvpn/easy-rsa/pki/issued") / f"{name}.crt"
        ).is_file():
            subprocess.run(
                ["bash", str(OVPN_BUILD_SCRIPT), name],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
    if not path.is_file():
        raise FileNotFoundError(f"missing OpenVPN profile for {name}")
    if path.resolve().parent != OVPN_CLIENT_DIR.resolve():
        raise ValueError("invalid OpenVPN profile path")
    filename = "GL-MT6000.ovpn" if name.lower() == "flint" else f"{name}.ovpn"
    return filename, path.read_bytes()


def load_openvpn_client_conf(filename: str) -> bytes:
    path = OVPN_CLIENT_DIR / filename
    if not path.is_file():
        raise FileNotFoundError(f"missing OpenVPN profile {path}")
    # Refuse path escape
    if path.resolve().parent != OVPN_CLIENT_DIR.resolve():
        raise ValueError("invalid OpenVPN profile path")
    return path.read_bytes()


def load_openvpn_script(filename: str) -> bytes:
    path = OVPN_SCRIPTS_DIR / filename
    if not path.is_file():
        # Fall back to repo-relative scripts next to this file (dev / deploy sync).
        alt = Path(__file__).resolve().parent / "scripts" / "openvpn" / filename
        if alt.is_file():
            path = alt
        else:
            raise FileNotFoundError(f"missing OpenVPN script {filename}")
    if ".." in Path(filename).parts:
        raise ValueError("invalid OpenVPN script path")
    return path.read_bytes()


def build_flint_wireguard_conf(client_name: str = "") -> bytes:
    """Build a client .conf from live wg-easy keys (never trust a stale on-disk copy)."""
    import sqlite3
    import tempfile

    name = (client_name or WG_CLIENT_NAME).strip() or "GL-MT6000"
    tmp = Path(tempfile.mkdtemp(prefix="wg-easy-db-"))
    db_local = tmp / "wg-easy.db"
    try:
        proc = subprocess.run(
            ["docker", "cp", f"{WG_EASY_DB_CONTAINER}:{WG_EASY_DB_PATH}", str(db_local)],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if proc.returncode != 0 or not db_local.is_file():
            raise RuntimeError((proc.stderr or proc.stdout or "docker cp failed").strip())
        pub_proc = subprocess.run(
            ["docker", "exec", WG_EASY_DB_CONTAINER, "wg", "show", "wg0", "public-key"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if pub_proc.returncode != 0:
            raise RuntimeError((pub_proc.stderr or "wg public-key failed").strip())
        server_pub = (pub_proc.stdout or "").strip()
        if not server_pub:
            raise RuntimeError("empty server public key")

        conn = sqlite3.connect(str(db_local))
        conn.row_factory = sqlite3.Row
        try:
            cli = conn.execute(
                "SELECT * FROM clients_table WHERE name = ? LIMIT 1", (name,)
            ).fetchone()
            if cli is None:
                raise RuntimeError(f"client {name!r} not found in wg-easy")
            cfg = conn.execute(
                "SELECT * FROM user_configs_table WHERE id = ? LIMIT 1",
                (cli["interface_id"],),
            ).fetchone()
        finally:
            conn.close()

        host = str((cfg["host"] if cfg else None) or "74.208.76.213").strip()
        port = int((cfg["port"] if cfg else None) or 443)
        mtu = int(cli["mtu"] or 1280)
        keepalive = int(cli["persistent_keepalive"] or 25)
        try:
            dns = json.loads(cli["dns"] or '["10.8.0.1"]')
        except Exception:
            dns = ["10.8.0.1"]
        try:
            allowed = json.loads(cli["allowed_ips"] or '["10.8.0.0/24","10.42.42.0/24"]')
        except Exception:
            allowed = ["10.8.0.0/24", "10.42.42.0/24"]
        if not isinstance(dns, list) or not dns:
            dns = ["10.8.0.1"]
        if not isinstance(allowed, list) or not allowed:
            allowed = ["10.8.0.0/24", "10.42.42.0/24"]
        addr = str(cli["ipv4_address"] or "").strip()
        if addr and "/" not in addr:
            addr = addr + "/32"
        if not addr:
            raise RuntimeError("client has no ipv4 address")

        text = (
            "[Interface]\n"
            f"PrivateKey = {cli['private_key']}\n"
            f"Address = {addr}\n"
            f"DNS = {', '.join(str(x) for x in dns)}\n"
            f"MTU = {mtu}\n"
            "\n"
            "[Peer]\n"
            f"PublicKey = {server_pub}\n"
            f"PresharedKey = {cli['pre_shared_key']}\n"
            f"Endpoint = {host}:{port}\n"
            f"AllowedIPs = {', '.join(str(x) for x in allowed)}\n"
            f"PersistentKeepalive = {keepalive}\n"
        )
        body = text.encode("utf-8")
        try:
            WG_CLIENT_CONF.write_bytes(body)
            WG_CLIENT_CONF.chmod(0o600)
        except Exception:
            pass
        return body
    finally:
        try:
            if db_local.exists():
                db_local.unlink()
            tmp.rmdir()
        except Exception:
            pass


def load_flint_wireguard_conf() -> bytes:
    try:
        return build_flint_wireguard_conf()
    except Exception:
        if WG_CLIENT_CONF.is_file():
            return WG_CLIENT_CONF.read_bytes()
        raise
# Dark admin theme (ServerManager / AdGuard / Pi-hole style) + full-bleed layout.
BUFFALO_FIT_CSS = """
:root {
  --sm-bg0: #0a0f0d;
  --sm-bg1: #111916;
  --sm-bg2: #17221d;
  --sm-bg3: #1e2b25;
  --sm-line: rgba(170, 210, 185, 0.14);
  --sm-text: #e8f2ec;
  --sm-muted: #84998c;
  --sm-accent: #3ddea0;
  --sm-accent-dim: rgba(61, 222, 160, 0.14);
  --sm-danger: #ff6b6b;
}
html, body, body#buffalo {
  width: 100% !important;
  height: 100% !important;
  min-height: 100% !important;
  margin: 0 !important;
  padding: 0 !important;
  overflow: hidden !important;
  background: var(--sm-bg0) !important;
  color: var(--sm-text) !important;
  font-family: "Sora", "Segoe UI", system-ui, sans-serif !important;
  zoom: 1 !important;
  touch-action: manipulation !important;
  -webkit-text-size-adjust: 100% !important;
  text-size-adjust: 100% !important;
}
body#buffalo *,
body#buffalo *::before,
body#buffalo *::after {
  border-color: var(--sm-line) !important;
  box-shadow: none !important;
  text-shadow: none !important;
}
body#buffalo a { color: var(--sm-accent) !important; }
body#buffalo .container,
body#buffalo #header,
body#buffalo #nav,
body#buffalo #nav .container,
body#buffalo #footer,
* body#buffalo #footer,
body#buffalo #main,
body#buffalo #top,
body#buffalo .container.portal,
body#buffalo .container.footer {
  width: 100% !important;
  max-width: none !important;
  margin-left: 0 !important;
  margin-right: 0 !important;
  box-sizing: border-box !important;
  background: transparent !important;
}
/* Kill original 80px header-bg.gif chrome (line through icons) */
body#buffalo #header,
body#buffalo #header > .container,
body#buffalo #nav,
body#buffalo #nav > .container,
body#buffalo #nav > .container.portal {
  background: var(--sm-bg1) !important;
  background-image: none !important;
  background-color: var(--sm-bg1) !important;
  padding: 0 !important;
  margin: 0 !important;
  float: none !important;
  position: relative !important;
  z-index: 20 !important;
  overflow: visible !important;
  border: 0 !important;
  border-radius: 0 !important;
  box-shadow: none !important;
}
body#buffalo #header {
  display: block !important;
  min-height: 56px !important;
  height: 56px !important;
  max-height: 56px !important;
  padding: 0 18px !important;
  box-sizing: border-box !important;
  border-bottom: 0 !important;
}
body#buffalo #header > .container {
  display: flex !important;
  flex-wrap: nowrap !important;
  align-items: center !important;
  justify-content: space-between !important;
  gap: 16px !important;
  width: 100% !important;
  height: 56px !important;
  min-height: 56px !important;
  max-height: 56px !important;
  margin: 0 !important;
  padding: 0 !important;
  float: none !important;
  box-sizing: border-box !important;
  overflow: visible !important;
}
/* Brand: replace clipped GIF with crisp CSS wordmark */
body#buffalo #header #header-logo {
  display: flex !important;
  align-items: center !important;
  float: none !important;
  flex: 0 0 auto !important;
  width: auto !important;
  min-width: 0 !important;
  height: 56px !important;
  margin: 0 !important;
  padding: 0 !important;
  background: transparent !important;
  background-image: none !important;
  overflow: visible !important;
}
body#buffalo #header #header-logo .logo {
  display: flex !important;
  align-items: center !important;
  margin: 0 !important;
  padding: 4px 2px !important;
  line-height: 1.2 !important;
  overflow: visible !important;
}
body#buffalo #header #header-logo .logo img,
body#buffalo #header #BUFFALO_LOGO,
body#buffalo #header #header-logo .product-name {
  display: none !important;
  width: 0 !important;
  height: 0 !important;
  margin: 0 !important;
  padding: 0 !important;
  border: 0 !important;
}
body#buffalo #header #header-logo .logo::before {
  content: "BUFFALO" !important;
  display: block !important;
  font-family: "Sora", "Segoe UI", sans-serif !important;
  font-weight: 700 !important;
  font-style: italic !important;
  font-size: 18px !important;
  letter-spacing: 0.1em !important;
  line-height: 1.4 !important;
  padding: 6px 8px 6px 2px !important;
  color: #ff4d4d !important;
  text-shadow: none !important;
  white-space: nowrap !important;
  overflow: visible !important;
  box-sizing: content-box !important;
}
/* Utility icons in header-search: home / download / help (keep search field hidden) */
body#buffalo #header #header-search {
  display: flex !important;
  align-items: center !important;
  float: none !important;
  flex: 0 0 auto !important;
  width: auto !important;
  height: 56px !important;
  margin: 0 0 0 auto !important;
  padding: 0 !important;
  overflow: visible !important;
  background: transparent !important;
  background-image: none !important;
}
body#buffalo #header #header-search .search {
  display: none !important;
}
body#buffalo #header #header-search .text {
  display: flex !important;
  flex-wrap: nowrap !important;
  align-items: center !important;
  gap: 4px !important;
  margin: 0 !important;
  padding: 0 !important;
  float: none !important;
  text-align: left !important;
  height: 36px !important;
}
body#buffalo #header #header-search .text .title {
  display: none !important;
}
body#buffalo #header #header-search .text .back-home,
body#buffalo #header #header-search .text a.dl,
body#buffalo #header #header-search .text .hint {
  display: flex !important;
  align-items: center !important;
  justify-content: center !important;
  float: none !important;
  width: 36px !important;
  height: 36px !important;
  margin: 0 !important;
  padding: 0 !important;
  border-radius: 8px !important;
  background: transparent !important;
  background-image: none !important;
  position: relative !important;
}
body#buffalo #header #header-search .text .back-home:hover,
body#buffalo #header #header-search .text a.dl:hover,
body#buffalo #header #header-search .text .hint:hover {
  background: var(--sm-bg3) !important;
}
body#buffalo #header #header-search .text .back-home a,
body#buffalo #header #header-search .text a.dl,
body#buffalo #header #header-search .text .hint a#hint {
  display: flex !important;
  align-items: center !important;
  justify-content: center !important;
  width: 36px !important;
  height: 36px !important;
  margin: 0 !important;
  padding: 0 !important;
  background: transparent !important;
  background-image: none !important;
  border: 0 !important;
  border-radius: 8px !important;
  line-height: 0 !important;
}
body#buffalo #header #header-search .text img,
body#buffalo #header #header-search .text .pressbtn,
body#buffalo #header #header-search .text .toggle {
  display: none !important;
  width: 0 !important;
  height: 0 !important;
}
body#buffalo #header #header-search .text .back-home a#back-home::before,
body#buffalo #header #header-search .text a.dl#dl_utils::before,
body#buffalo #header #header-search .text .hint a#hint::before {
  content: "" !important;
  display: block !important;
  width: 18px !important;
  height: 18px !important;
  background-color: var(--sm-muted) !important;
  pointer-events: none !important;
  -webkit-mask-repeat: no-repeat !important;
  mask-repeat: no-repeat !important;
  -webkit-mask-position: center !important;
  mask-position: center !important;
  -webkit-mask-size: contain !important;
  mask-size: contain !important;
}
body#buffalo #header #header-search .text .back-home a#back-home::before {
  -webkit-mask-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M3 10.5L12 3l9 7.5'/%3E%3Cpath d='M5 10v10h14V10'/%3E%3C/svg%3E") !important;
  mask-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M3 10.5L12 3l9 7.5'/%3E%3Cpath d='M5 10v10h14V10'/%3E%3C/svg%3E") !important;
}
body#buffalo #header #header-search .text a.dl#dl_utils::before {
  -webkit-mask-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M12 3v12'/%3E%3Cpath d='M7 10l5 5 5-5'/%3E%3Cpath d='M5 21h14'/%3E%3C/svg%3E") !important;
  mask-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M12 3v12'/%3E%3Cpath d='M7 10l5 5 5-5'/%3E%3Cpath d='M5 21h14'/%3E%3C/svg%3E") !important;
}
body#buffalo #header #header-search .text .hint a#hint::before {
  background-color: #5eb8ff !important;
  -webkit-mask-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Ccircle cx='12' cy='12' r='10'/%3E%3Cpath d='M9.1 9a3 3 0 0 1 5.8 1c0 2-3 2-3 4'/%3E%3Cline x1='12' y1='17' x2='12.01' y2='17'/%3E%3C/svg%3E") !important;
  mask-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Ccircle cx='12' cy='12' r='10'/%3E%3Cpath d='M9.1 9a3 3 0 0 1 5.8 1c0 2-3 2-3 4'/%3E%3Cline x1='12' y1='17' x2='12.01' y2='17'/%3E%3C/svg%3E") !important;
}
body#buffalo #header #header-search .text .back-home:hover a#back-home::before,
body#buffalo #header #header-search .text a.dl#dl_utils:hover::before {
  background-color: var(--sm-text) !important;
}
body#buffalo #header #header-search .text .hint:hover a#hint::before {
  background-color: #8fd0ff !important;
}
/* Action icons: status / power / logout */
body#buffalo #header #header-button {
  display: flex !important;
  align-items: center !important;
  float: none !important;
  flex: 0 0 auto !important;
  width: auto !important;
  height: 56px !important;
  margin: 0 0 0 4px !important;
  padding: 0 !important;
  background: transparent !important;
  background-image: none !important;
}
body#buffalo #header #header-button ul,
body#buffalo #header #header-button ul.right {
  display: flex !important;
  flex-wrap: nowrap !important;
  align-items: center !important;
  gap: 4px !important;
  margin: 0 !important;
  padding: 0 !important;
  float: none !important;
  list-style: none !important;
  height: 36px !important;
  width: auto !important;
}
body#buffalo #header #header-button > ul > li,
body#buffalo #header #header-button > ul > li.status,
body#buffalo #header #header-button > ul > li.power,
body#buffalo #header #header-button > ul > li.logout {
  display: flex !important;
  align-items: center !important;
  justify-content: center !important;
  float: none !important;
  margin: 0 !important;
  padding: 0 !important;
  width: 36px !important;
  height: 36px !important;
  background: transparent !important;
  background-image: none !important;
  border: 0 !important;
  border-radius: 8px !important;
  position: relative !important;
  overflow: visible !important;
}
body#buffalo #header #header-button > ul > li:hover {
  background: var(--sm-bg3) !important;
}
body#buffalo #header #header-button > ul > li > a,
body#buffalo #header #header-button > ul > li.logout > a#logout,
body#buffalo #header #header-button > ul > li.logout > a#logout:hover,
body#buffalo #header #header-button > ul > li.logout > a#logout:active {
  display: flex !important;
  align-items: center !important;
  justify-content: center !important;
  width: 36px !important;
  height: 36px !important;
  margin: 0 !important;
  padding: 0 !important;
  background: transparent !important;
  background-image: none !important;
  border: 0 !important;
  border-radius: 8px !important;
  line-height: 0 !important;
}
/* Ext often leaves status/power <img> with no src before NAS login — hide them */
body#buffalo #header #header-button ul li img,
body#buffalo #header #header-button ul li .pressbtn,
body#buffalo #header #header-button ul li .toggle {
  display: none !important;
  width: 0 !important;
  height: 0 !important;
  margin: 0 !important;
  padding: 0 !important;
  border: 0 !important;
}
/* Flat CSS glyphs: status / power / logout */
body#buffalo #header #header-button ul li.status a#status,
body#buffalo #header #header-button ul li.power a#power,
body#buffalo #header #header-button ul li.logout a#logout,
body#buffalo #header #header-search .text .back-home a,
body#buffalo #header #header-search .text a.dl,
body#buffalo #header #header-search .text .hint a#hint {
  pointer-events: auto !important;
  cursor: pointer !important;
  position: relative !important;
  z-index: 2 !important;
}
body#buffalo #header #header-button ul li.status a#status::before,
body#buffalo #header #header-button ul li.power a#power::before,
body#buffalo #header #header-button ul li.logout a#logout::before {
  content: "" !important;
  display: block !important;
  width: 18px !important;
  height: 18px !important;
  background-color: var(--sm-muted) !important;
  pointer-events: none !important;
  -webkit-mask-repeat: no-repeat !important;
  mask-repeat: no-repeat !important;
  -webkit-mask-position: center !important;
  mask-position: center !important;
  -webkit-mask-size: contain !important;
  mask-size: contain !important;
}
body#buffalo #header #header-button ul li.status a#status::before {
  background-color: #5eb8ff !important;
  -webkit-mask-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Ccircle cx='12' cy='12' r='10'/%3E%3Cline x1='12' y1='16' x2='12' y2='12'/%3E%3Cline x1='12' y1='8' x2='12.01' y2='8'/%3E%3C/svg%3E") !important;
  mask-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Ccircle cx='12' cy='12' r='10'/%3E%3Cline x1='12' y1='16' x2='12' y2='12'/%3E%3Cline x1='12' y1='8' x2='12.01' y2='8'/%3E%3C/svg%3E") !important;
}
body#buffalo #header #header-button ul li.power a#power::before {
  background-color: var(--sm-danger) !important;
  -webkit-mask-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M12 2v10'/%3E%3Cpath d='M18.4 6.6a9 9 0 1 1-12.8 0'/%3E%3C/svg%3E") !important;
  mask-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M12 2v10'/%3E%3Cpath d='M18.4 6.6a9 9 0 1 1-12.8 0'/%3E%3C/svg%3E") !important;
}
body#buffalo #header #header-button ul li.logout a#logout::before {
  background-color: var(--sm-muted) !important;
  -webkit-mask-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4'/%3E%3Cpolyline points='16 17 21 12 16 7'/%3E%3Cline x1='21' y1='12' x2='9' y2='12'/%3E%3C/svg%3E") !important;
  mask-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='black' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4'/%3E%3Cpolyline points='16 17 21 12 16 7'/%3E%3Cline x1='21' y1='12' x2='9' y2='12'/%3E%3C/svg%3E") !important;
}
body#buffalo #header #header-button ul li.status:hover a#status::before {
  background-color: #8fd0ff !important;
}
body#buffalo #header #header-button ul li.power:hover a#power::before {
  background-color: #ff8a8a !important;
}
body#buffalo #header #header-button ul li.logout:hover a#logout::before {
  background-color: var(--sm-text) !important;
}
body#buffalo #header #header-button ul li.logout a#logout span {
  display: none !important;
}
body#buffalo #header .dropmenu-parent .dropmenu {
  top: 40px !important;
  right: 0 !important;
  left: auto !important;
  border: 1px solid var(--sm-line) !important;
  border-radius: 10px !important;
  overflow: visible !important;
  background: var(--sm-bg2) !important;
  background-image: none !important;
  z-index: 1000 !important;
  position: absolute !important;
  min-width: 160px !important;
  height: auto !important;
  max-height: none !important;
  padding: 4px 0 !important;
}
body#buffalo #header .dropmenu-parent .dropmenu.show,
body#buffalo #header .dropmenu-parent .dropdownbox.show,
body#buffalo #header .status .dropdownbox.show,
body#buffalo #header .hint .dropmenu.show {
  display: block !important;
  visibility: visible !important;
  z-index: 1000 !important;
}
body#buffalo #header .dropmenu-parent .dropmenu.hide,
body#buffalo #header .dropmenu-parent .dropdownbox.hide,
body#buffalo #header .status .dropdownbox.hide,
body#buffalo #header .hint .dropmenu.hide {
  display: none !important;
}
body#buffalo #header .dropmenu-parent .dropmenu li,
body#buffalo #header .dropmenu-parent .dropmenu li a {
  display: block !important;
  width: auto !important;
  min-width: 140px !important;
  height: auto !important;
  padding: 10px 14px !important;
  margin: 0 !important;
  background-color: var(--sm-bg2) !important;
  background-image: none !important;
  color: var(--sm-text) !important;
  border-color: var(--sm-line) !important;
  font-size: 13px !important;
  line-height: 1.3 !important;
  text-decoration: none !important;
  white-space: nowrap !important;
}
body#buffalo #header .dropmenu-parent .dropmenu li a:hover {
  background: var(--sm-bg3) !important;
  color: var(--sm-accent) !important;
}
body#buffalo #header .dropmenu-parent .dropmenu li a span {
  display: inline !important;
  color: inherit !important;
  width: auto !important;
  height: auto !important;
}
body#buffalo #header .status .dropdownbox,
body#buffalo #header .search .dropdownbox {
  background: var(--sm-bg2) !important;
  background-image: none !important;
  border: 1px solid var(--sm-line) !important;
  border-radius: 10px !important;
  color: var(--sm-text) !important;
}
/* Hide entire secondary nav (Rearrange Tiles / language strip) */
body#buffalo #nav,
body#buffalo #nav > .container,
body#buffalo #nav > .container.portal,
body#buffalo #nav ul,
body#buffalo #nav ul li,
body#buffalo #nav ul li.layout,
body#buffalo #nav #change_layout,
body#buffalo #nav .back-home,
body#buffalo #nav .sound,
body#buffalo #nav .name {
  display: none !important;
  height: 0 !important;
  min-height: 0 !important;
  max-height: 0 !important;
  width: 0 !important;
  margin: 0 !important;
  padding: 0 !important;
  overflow: hidden !important;
  border: 0 !important;
  visibility: hidden !important;
  background: transparent !important;
  background-image: none !important;
}
body#buffalo #nav ul li.language,
body#buffalo #nav ul li.language #language-label,
body#buffalo #nav ul li.language #language-label a#change-language,
body#buffalo #nav ul li.language span#language-name-cover,
body#buffalo #nav ul li.language span#language-name-cover span#language-name,
body#buffalo #nav ul#language-list,
body#buffalo #nav ul li.language .dropmenu,
body#buffalo #nav #language-list,
body#buffalo #nav .sep_r,
body#buffalo #header .sep_r,
body#buffalo #nav ul li.username,
body#buffalo #nav ul li.username #mainField,
body#buffalo #nav ul li.username #mainField .icon,
body#buffalo #nav ul li.username #mainField .text {
  display: none !important;
  width: 0 !important;
  height: 0 !important;
  margin: 0 !important;
  padding: 0 !important;
  overflow: hidden !important;
  visibility: hidden !important;
  background: transparent !important;
  background-image: none !important;
  border: 0 !important;
}
/* Keep footer at bottom; hide empty product glyph (shows as white box) */
body#buffalo #footer.preload,
body#buffalo div#footer.preload {
  display: none !important;
}
body#buffalo #BUFFALO_PROD_NAME,
body#buffalo #footer .product-name img {
  display: none !important;
}
body#buffalo #main {
  min-height: calc(100vh - 96px) !important;
}
body#buffalo #footer,
* body#buffalo #footer {
  background: var(--sm-bg1) !important;
  border-top: 1px solid var(--sm-line) !important;
  padding: 10px 16px !important;
}
body#buffalo #footer .copyright {
  width: auto !important;
  max-width: none !important;
  background: transparent !important;
  color: var(--sm-muted) !important;
  margin: 0 !important;
  padding: 0 !important;
}
body#buffalo #main,
body#buffalo #top,
body#buffalo .container.portal {
  background: var(--sm-bg0) !important;
}
body#buffalo div#main div#top div#menu_box {
  display: grid !important;
  grid-template-columns: repeat(3, minmax(0, 1fr)) !important;
  grid-auto-rows: minmax(200px, auto) !important;
  gap: 14px !important;
  align-content: start !important;
  width: calc(100% - 28px) !important;
  max-width: none !important;
  height: calc(100vh - 120px) !important;
  min-height: 360px !important;
  max-height: none !important;
  margin: 12px 14px !important;
  padding: 4px !important;
  overflow: auto !important;
  box-sizing: border-box !important;
  background: transparent !important;
  border: 0 !important;
  box-shadow: none !important;
}
body#buffalo #main .container_sd,
body#buffalo #main.kantan,
body#buffalo #main,
body#buffalo #top {
  background: var(--sm-bg0) !important;
  border: 0 !important;
  box-shadow: none !important;
}
/* Hide Buffalo layout spacers */
body#buffalo #menu_box > .item-box.fixed:not(#advanced) {
  display: none !important;
}
/* Pin Advanced Settings under BitTorrent (3rd column) */
body#buffalo #menu_box > #advanced {
  grid-column: 3 !important;
  display: block !important;
}
/* Unified dark service tiles (kill white PNG chrome + double box) */
body#buffalo #menu_box > .item-box {
  position: relative !important;
  display: flex !important;
  flex-direction: column !important;
  float: none !important;
  width: auto !important;
  max-width: none !important;
  height: auto !important;
  min-height: 200px !important;
  margin: 0 !important;
  padding: 0 !important;
  box-sizing: border-box !important;
  background: var(--sm-bg2) !important;
  background-image: none !important;
  border: 1px solid var(--sm-line) !important;
  border-radius: 14px !important;
  box-shadow: none !important;
  overflow: hidden !important;
  color: var(--sm-text) !important;
}
body#buffalo #menu_box > .item-box:hover {
  background: var(--sm-bg3) !important;
  border-color: rgba(61, 222, 160, 0.35) !important;
}
body#buffalo #menu_box > .item-box a.panel,
body#buffalo #menu_box > .item-box a.panel-advanced,
body#buffalo #menu_box > .item-box a.panel:hover,
body#buffalo #menu_box > .item-box a.panel:active,
body#buffalo #menu_box > .item-box a.panel-advanced:hover,
body#buffalo #menu_box > .item-box a.panel-advanced:active {
  display: flex !important;
  flex-direction: column !important;
  align-items: flex-start !important;
  flex: 1 1 auto !important;
  width: 100% !important;
  height: 100% !important;
  min-height: 200px !important;
  margin: 0 !important;
  padding: 18px 18px 52px !important;
  box-sizing: border-box !important;
  background: transparent !important;
  background-image: none !important;
  border: 0 !important;
  border-radius: 0 !important;
  box-shadow: none !important;
  text-decoration: none !important;
  color: var(--sm-text) !important;
}
body#buffalo #menu_box > .item-box a h2.title,
body#buffalo #menu_box > .item-box a.panel-advanced h2.title {
  color: var(--sm-text) !important;
  font-family: "Sora", "Segoe UI", sans-serif !important;
  font-size: 15px !important;
  font-weight: 600 !important;
  line-height: 1.3 !important;
  margin: 10px 0 6px !important;
  padding: 0 !important;
}
body#buffalo #menu_box > .item-box a p.description,
body#buffalo #menu_box > .item-box a.panel-advanced p.description {
  color: var(--sm-muted) !important;
  font-size: 12px !important;
  line-height: 1.45 !important;
  height: auto !important;
  min-height: 0 !important;
  max-height: none !important;
  margin: 0 !important;
  padding: 0 !important;
  overflow: visible !important;
}
body#buffalo #menu_box > .item-box [id^="wizard-"] {
  display: inline-block !important;
  margin: 4px 0 0 !important;
  background-color: transparent !important;
  border: 0 !important;
  border-radius: 0 !important;
  box-shadow: none !important;
  filter: brightness(1.05) !important;
}
body#buffalo #menu_box > .item-box [id^="function-logo-"] {
  display: none !important;
}
body#buffalo #menu_box > .item-box div.toggle_jscls {
  position: absolute !important;
  top: 14px !important;
  right: 14px !important;
  left: auto !important;
  margin: 0 !important;
  z-index: 3 !important;
  background: transparent !important;
  border: 0 !important;
  box-shadow: none !important;
}
body#buffalo #menu_box > .item-box .setting-btn {
  position: absolute !important;
  right: 14px !important;
  bottom: 14px !important;
  width: 28px !important;
  height: 28px !important;
  margin: 0 !important;
  z-index: 3 !important;
  background: var(--sm-bg3) !important;
  border: 1px solid var(--sm-line) !important;
  border-radius: 8px !important;
  box-shadow: none !important;
  display: flex !important;
  align-items: center !important;
  justify-content: center !important;
  cursor: pointer !important;
}
body#buffalo #menu_box > .item-box .setting-btn:hover {
  border-color: var(--sm-accent) !important;
}
body#buffalo #menu_box > .item-box .setting-btn span.setting-btn-icon {
  display: block !important;
  width: 16px !important;
  height: 16px !important;
  margin: 0 !important;
  background-size: contain !important;
  background-repeat: no-repeat !important;
  background-position: center !important;
  filter: brightness(1.25) !important;
}
body#buffalo #menu_box img {
  filter: none !important;
  opacity: 0.95 !important;
  border: 0 !important;
  background: transparent !important;
  box-shadow: none !important;
}
body#buffalo #main #top div.subsequent {
  margin-top: 0 !important;
  border: 0 !important;
}
/* ExtJS chrome */
body#buffalo .x-body,
body#buffalo .x-panel-body,
body#buffalo .x-window-body,
body#buffalo .x-form-item,
body#buffalo .x-fieldset,
body#buffalo .x-panel,
body#buffalo .x-panel-default,
body#buffalo .x-container {
  background: var(--sm-bg1) !important;
  color: var(--sm-text) !important;
  border-color: var(--sm-line) !important;
}
body#buffalo .x-mask {
  background-color: rgba(8, 14, 11, 0.72) !important;
  opacity: 1 !important;
}
body#buffalo .x-window {
  background: var(--sm-bg1) !important;
  border: 1px solid var(--sm-line) !important;
  border-radius: 14px !important;
  overflow: hidden !important;
  zoom: 1 !important;
}
body#buffalo .x-window-header,
body#buffalo .x-panel-header,
body#buffalo .x-toolbar,
body#buffalo .x-toolbar-default {
  background: var(--sm-bg2) !important;
  border-color: var(--sm-line) !important;
  color: var(--sm-text) !important;
}
body#buffalo .x-window-header-text,
body#buffalo .x-panel-header-text,
body#buffalo .x-form-item-label,
body#buffalo .x-form-cb-label,
body#buffalo label,
body#buffalo .x-component {
  color: var(--sm-text) !important;
}
body#buffalo .x-window-body {
  background: var(--sm-bg1) !important;
  padding: 14px !important;
}
body#buffalo .x-form-text,
body#buffalo .x-form-field,
body#buffalo input[type="text"],
body#buffalo input[type="password"],
body#buffalo input[type="number"],
body#buffalo select,
body#buffalo textarea,
body#buffalo .x-form-trigger-wrap {
  background: var(--sm-bg0) !important;
  color: var(--sm-text) !important;
  border: 1px solid var(--sm-line) !important;
  border-radius: 9px !important;
  padding: 8px 10px !important;
}
body#buffalo .x-btn,
body#buffalo .x-btn-default-small,
body#buffalo .x-btn-default-medium,
body#buffalo button,
body#buffalo .pressbtn,
body#buffalo a.btn9p {
  background: var(--sm-bg3) !important;
  color: var(--sm-text) !important;
  border: 1px solid var(--sm-line) !important;
  border-radius: 9px !important;
  filter: none !important;
}
body#buffalo .x-btn-inner,
body#buffalo .x-btn button,
body#buffalo .x-btn a {
  color: var(--sm-text) !important;
  font-weight: 600 !important;
}
body#buffalo .x-btn-primary,
body#buffalo .x-btn.x-btn-default-toolbar-small.primary,
body#buffalo a.btn9p:hover {
  background: var(--sm-accent) !important;
  border-color: transparent !important;
  color: #062016 !important;
}
body#buffalo .x-btn-primary .x-btn-inner {
  color: #062016 !important;
}
body#buffalo .x-grid-view,
body#buffalo .x-grid-table,
body#buffalo .x-grid-row,
body#buffalo .x-grid-cell,
body#buffalo .x-grid-header-ct {
  background: var(--sm-bg1) !important;
  color: var(--sm-text) !important;
  border-color: var(--sm-line) !important;
}
body#buffalo .x-grid-row-over .x-grid-cell {
  background: var(--sm-bg2) !important;
}
body#buffalo .x-tab-bar,
body#buffalo .x-tab,
body#buffalo .x-tab-default {
  background: var(--sm-bg2) !important;
  color: var(--sm-muted) !important;
  border-color: var(--sm-line) !important;
}
body#buffalo .x-tab-active,
body#buffalo .x-tab.x-tab-active {
  background: var(--sm-accent-dim) !important;
  color: var(--sm-accent) !important;
}
body#buffalo .x-tip,
body#buffalo .x-menu,
body#buffalo .dropdownbox,
body#buffalo .dropmenu {
  background: var(--sm-bg2) !important;
  color: var(--sm-text) !important;
  border: 1px solid var(--sm-line) !important;
  border-radius: 10px !important;
}
body#buffalo .dropmenu li,
body#buffalo .dropdownbox table,
body#buffalo .dropdownbox th,
body#buffalo .dropdownbox td {
  background: transparent !important;
  color: var(--sm-text) !important;
  border-color: var(--sm-line) !important;
}
body#buffalo img[src*="footer"],
body#buffalo img[src*="sidebar-bg"],
body#buffalo img[src*="header-search-bg"] {
  opacity: 0 !important;
  display: none !important;
}
""".strip()

BUFFALO_FIT_SNIPPET = (
    "<base href=\"/buffalo-frame/\" />"
    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1, minimum-scale=1, maximum-scale=1, user-scalable=no, viewport-fit=cover\" />"
    "<link rel=\"preconnect\" href=\"https://fonts.googleapis.com\" />"
    "<link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin />"
    "<link href=\"https://fonts.googleapis.com/css2?family=Sora:wght@400;500;600;700&display=swap\" rel=\"stylesheet\" />"
    "<style id=\"sm-buffalo-fit\">"
    + BUFFALO_FIT_CSS.replace("\n", " ")
    + "</style>"
    "<script id=\"sm-buffalo-fit-js\">(function(){"
    "var P='/buffalo-frame';"
    "try{document.documentElement.style.setProperty('zoom','1','important');"
    "document.body&&document.body.style.setProperty('zoom','1','important');}catch(e){}"
    "function ensureHeaderImgs(){"
    "var skin=(document.getElementById('switch_css')&&"
    "(document.getElementById('switch_css').href||'').indexOf('fortera')>=0)?'fortera':'forlink';"
    "var map={"
    "'QT_NAS_03_BUTTON_TOOLTIP':'img/common/'+skin+'/header-status-btn-off.png',"
    "'QT_NAS_04_BUTTON_TOOLTIP':'img/common/'+skin+'/header-power-btn-off.png',"
    "'QT_NAS_02_BUTTON_TOOLTIP':'img/common/'+skin+'/header-hint-btn-off.gif',"
    "'QT_NAS_00604_LABEL_CAPTION':'img/common/'+skin+'/nav-home-btn.gif'"
    "};"
    "Object.keys(map).forEach(function(id){"
    "var el=document.getElementById(id);"
    "if(el&&!el.getAttribute('src'))el.setAttribute('src',map[id]);});}"
    "ensureHeaderImgs();"
    "document.addEventListener('DOMContentLoaded',ensureHeaderImgs);"
    "setInterval(ensureHeaderImgs,1500);"
    "function fillHeaderCaptions(){"
    "if(!(window.Ext&&Ext.words))return;"
    "['NAS_04_MENU01_CAPTION','NAS_04_MENU02_CAPTION',"
    "'NAS_02_MENU01_CAPTION','NAS_02_MENU02_CAPTION','NAS_02_MENU03_CAPTION'].forEach(function(id){"
    "var el=document.getElementById(id); if(!el)return;"
    "if(!(el.textContent||'').trim()&&Ext.words[id])el.textContent=Ext.words[id];});}"
    "function bindHeaderMenus(){"
    "fillHeaderCaptions();"
    "function hideAll(){"
    "document.querySelectorAll('#header .dropmenu,#header .dropdownbox').forEach(function(d){"
    "d.classList.add('hide');d.classList.remove('show');"
    "d.style.setProperty('display','none','important');});}"
    "function showBox(box){if(!box)return;fillHeaderCaptions();hideAll();"
    "box.classList.remove('hide');box.classList.add('show');"
    "box.style.setProperty('display','block','important');"
    "box.style.setProperty('visibility','visible','important');"
    "box.style.setProperty('z-index','1000','important');"
    "box.style.setProperty('min-width','180px','important');"
    "box.style.setProperty('height','auto','important');"
    "box.style.setProperty('max-height','none','important');"
    "box.style.setProperty('overflow','visible','important');}"
    "function toggleFor(anchor,sel){"
    "if(!anchor||!anchor.parentNode)return;"
    "var box=anchor.parentNode.querySelector(sel); if(!box)return;"
    "if(box.classList.contains('hide')||getComputedStyle(box).display==='none')showBox(box); else hideAll();"
    "}"
    "[['status','.dropdownbox'],['power','.dropmenu'],['hint','.dropmenu']].forEach(function(pair){"
    "var el=document.getElementById(pair[0]); if(!el||el.getAttribute('data-sm-bound')==='1')return;"
    "el.setAttribute('data-sm-bound','1');"
    "el.addEventListener('click',function(ev){"
    "ev.preventDefault(); ev.stopPropagation();"
    "var box=el.parentNode&&el.parentNode.querySelector(pair[1]);"
    "if(pair[0]==='status'&&box&&(box.classList.contains('hide')||getComputedStyle(box).display==='none')&&"
    "window.Ext&&Ext.header&&Ext.header.get_portal_info){"
    "try{Ext.header.get_portal_info(function(){"
    "try{if(Ext.header.status&&Ext.header.status.load)Ext.header.status.load();}catch(e){}"
    "showBox(box);});return;}catch(e){}"
    "}"
    "toggleFor(el,pair[1]);"
    "},true);});"
    "fillHeaderCaptions();"
    "[['reboot','Ext.header.reboot'],['shutdown','Ext.header.shutdown']].forEach(function(pair){"
    "var el=document.getElementById(pair[0]); if(!el||el.getAttribute('data-sm-bound')==='1')return;"
    "el.setAttribute('data-sm-bound','1');"
    "el.addEventListener('click',function(ev){"
    "ev.preventDefault(); ev.stopPropagation(); hideAll();"
    "try{if(window.Ext)Ext.create(pair[1]).init();}catch(e){}"
    "},true);});"
    "document.addEventListener('click',function(ev){"
    "if(!ev.target.closest||!ev.target.closest('#header .dropmenu-parent'))hideAll();"
    "});}"
    "function goBuffaloHome(ev){"
    "if(ev){ev.preventDefault();ev.stopPropagation();if(ev.stopImmediatePropagation)ev.stopImmediatePropagation();}"
    "try{location.assign(P+'/root.html');}catch(e){location.href=P+'/root.html';}}"
    "function bindBackHome(){"
    "var el=document.getElementById('back-home'); if(!el)return;"
    "try{el.setAttribute('href',P+'/root.html');el.removeAttribute('target');}catch(e){}"
    "if(el.getAttribute('data-sm-home')==='1')return;"
    "el.setAttribute('data-sm-home','1');"
    "el.addEventListener('click',goBuffaloHome,true);}"
    "function fix(u){if(typeof u!=='string')return u;"
    "if(!u||u.charAt(0)==='#'||u.indexOf('data:')===0||u.indexOf('blob:')===0)return u;"
    "if(u.indexOf(P+'/')===0||u===P)return u;"
    "if(u.indexOf('http://192.168.8.159')===0)return P+u.slice(20);"
    "if(u.indexOf('https://buffalo.vpstruelord.com')===0)return P+u.slice(30);"
    "if(u.indexOf('http://buffalo.vpstruelord.com')===0)return P+u.slice(29);"
    "if(u.charAt(0)==='/'&&u.charAt(1)!=='/')return P+u;"
    "return u;}"
    "var xo=XMLHttpRequest.prototype.open;"
    "XMLHttpRequest.prototype.open=function(m,u){try{arguments[1]=fix(u);}catch(e){}"
    "return xo.apply(this,arguments);};"
    "if(window.fetch){var _f=window.fetch;window.fetch=function(i,n){"
    "try{if(typeof i==='string')i=fix(i);else if(i&&i.url)i=new Request(fix(i.url),i);}catch(e){}"
    "return _f.call(this,i,n);};}"
    "function fit(){"
    "try{document.documentElement.style.setProperty('zoom','1','important');"
    "document.body.style.setProperty('zoom','1','important');}catch(e){}"
    "ensureHeaderImgs();"
    "bindHeaderMenus();"
    "bindBackHome();"
    "fillHeaderCaptions();"
    "function force(el,props){if(!el)return;Object.keys(props).forEach(function(k){"
    "el.style.setProperty(k,props[k],'important');});}"
    "['header','nav'].forEach(function(id){var el=document.getElementById(id);"
    "if(el){el.classList.remove('preload');}});"
    "var hdr=document.getElementById('header');"
    "force(hdr,{display:'block',height:'56px','min-height':'56px','max-height':'56px',"
    "margin:'0',padding:'0 18px',overflow:'visible',"
    "background:'#111916','background-image':'none','border-bottom':'0'});"
    "var hbox=hdr&&hdr.querySelector('.container');"
    "force(hbox,{display:'flex','flex-wrap':'nowrap','align-items':'center',"
    "'justify-content':'space-between',height:'56px',width:'100%',margin:'0',padding:'0',"
    "float:'none',background:'transparent','background-image':'none',overflow:'visible'});"
    "var search=document.getElementById('header-search');"
    "force(search,{display:'flex','align-items':'center',float:'none',margin:'0 0 0 auto',"
    "padding:'0',height:'56px',width:'auto',overflow:'visible',background:'transparent'});"
    "var searchField=search&&search.querySelector('.search'); force(searchField,{display:'none'});"
    "var searchText=search&&search.querySelector('.text');"
    "force(searchText,{display:'flex','flex-wrap':'nowrap','align-items':'center',gap:'4px',"
    "margin:'0',padding:'0',float:'none',height:'36px'});"
    "var logoWrap=document.getElementById('header-logo');"
    "force(logoWrap,{display:'flex','align-items':'center',float:'none',margin:'0',padding:'0',"
    "height:'56px',width:'auto',background:'transparent',overflow:'visible'});"
    "var logo=document.getElementById('BUFFALO_LOGO');"
    "force(logo,{display:'none',width:'0',height:'0'});"
    "var btns=document.getElementById('header-button');"
    "force(btns,{display:'flex','align-items':'center',float:'none',margin:'0 0 0 4px',"
    "padding:'0',height:'56px',width:'auto',background:'transparent','background-image':'none'});"
    "var ul=btns&&btns.querySelector('ul');"
    "force(ul,{display:'flex','flex-wrap':'nowrap','align-items':'center',gap:'4px',"
    "margin:'0',padding:'0',float:'none',height:'36px','list-style':'none'});"
    "if(ul){Array.prototype.forEach.call(ul.children,function(li){"
    "force(li,{display:'flex','align-items':'center','justify-content':'center',"
    "float:'none',margin:'0',padding:'0',width:'36px',height:'36px',"
    "background:'transparent','background-image':'none'});});}"
    "document.querySelectorAll('#header .dropmenu.hide, #header .dropdownbox.hide').forEach(function(el){"
    "force(el,{display:'none'});});"
    "var sound=document.querySelector('#nav .sound'); force(sound,{display:'none'});"
    "var foot=document.getElementById('footer');"
    "if(foot&&foot.classList.contains('preload')){force(foot,{display:'none'});}"
    "var prod=document.getElementById('BUFFALO_PROD_NAME'); force(prod,{display:'none'});"
    "var userLi=document.querySelector('#nav li.username'); force(userLi,{display:'none'});"
    "var langLi=document.querySelector('#nav li.language'); force(langLi,{display:'none'});"
    "var langList=document.getElementById('language-list'); force(langList,{display:'none'});"
    "var nav=document.getElementById('nav');"
    "force(nav,{display:'none',height:'0','min-height':'0','max-height':'0',"
    "'border-bottom':'0',padding:'0',margin:'0',overflow:'hidden',visibility:'hidden'});"
    "var box=document.getElementById('menu_box');"
    "if(box){var top=box.getBoundingClientRect().top;"
    "box.style.setProperty('width','calc(100% - 28px)','important');"
    "box.style.setProperty('height',Math.max(280,window.innerHeight-top-48)+'px','important');"
    "box.style.setProperty('max-width','none','important');"
    "box.style.setProperty('overflow','auto','important');"
    "box.style.setProperty('display','grid','important');"
    "box.style.setProperty('grid-template-columns','repeat(3, minmax(0, 1fr))','important');"
    "box.style.setProperty('gap','12px','important');"
    "try{"
    "var real={initialization:1,webaxs:1,btcloud:1,bittorrent:1,flickr:1,eyefi:1,"
    "dlna:1,usbdeviceserver:1,access:1,raid:1,domain:1,backup:1,terasearch:1,share:1};"
    "var bt=document.getElementById('bittorrent');"
    "var adv=document.getElementById('advanced');"
    "var items=Array.prototype.filter.call(box.children,function(n){return n.nodeType===1;});"
    "var reals=[], spacers=[];"
    "items.forEach(function(el){"
    "if(el===adv)return;"
    "if(el.id&&real[el.id])reals.push(el); else spacers.push(el);});"
    "spacers.forEach(function(el){el.style.setProperty('display','none','important');});"
    "if(adv){adv.style.setProperty('display','block','important');"
    "adv.style.setProperty('grid-column','3','important');"
    "var btIdx=bt?reals.indexOf(bt):-1;"
    "var insertAt=(btIdx>=0)?Math.min(btIdx+3,reals.length):reals.length;"
    "var desired=reals.slice(); desired.splice(insertAt,0,adv);"
    "var same=desired.length===items.filter(function(el){return el===adv||(el.id&&real[el.id]);}).length;"
    "var cur=items.filter(function(el){return el===adv||(el.id&&real[el.id]);});"
    "same=same&&desired.every(function(el,i){return el===cur[i];});"
    "if(!same){desired.forEach(function(el){box.appendChild(el);});"
    "spacers.forEach(function(el){box.appendChild(el);});}}"
    "}catch(e){}"
    "}"
    "document.querySelectorAll('.x-window').forEach(function(w){"
    "w.style.setProperty('zoom','normal','important');"
    "var r=w.getBoundingClientRect();"
    "if(r.bottom>window.innerHeight-8){"
    "w.style.top=Math.max(12,(window.innerHeight-r.height)/2)+'px';}"
    "if(r.right>window.innerWidth-8){"
    "w.style.left=Math.max(12,(window.innerWidth-r.width)/2)+'px';}"
    "});}"
    "window.addEventListener('resize',fit);"
    "document.addEventListener('DOMContentLoaded',fit);"
    "setTimeout(fit,300);setTimeout(fit,1200);setTimeout(fit,2500);setInterval(fit,2000);"
    "})();</script>"
)

# ServerManager theme for wg-easy (injected into /wg-ui HTML).
WG_UI_THEME_CSS = """
:root{
  --sm-bg0:#07110e;
  --sm-bg1:#0e1a15;
  --sm-bg2:#15241d;
  --sm-bg3:#1a2c24;
  --sm-line:rgba(170,210,185,.14);
  --sm-text:#e8f2ec;
  --sm-muted:#84998c;
  --sm-accent:#3ddea0;
  --sm-accent-dim:rgba(61,222,160,.14);
  --sm-accent-strong:rgba(61,222,160,.35);
  --sm-danger:#ff6b6b;
}
html,body{
  font-family:"Sora",system-ui,sans-serif!important;
  color:var(--sm-text)!important;
  background:
    radial-gradient(900px 420px at 10% -10%,rgba(61,222,160,.16),transparent 55%),
    radial-gradient(700px 380px at 100% 0%,rgba(45,120,95,.18),transparent 50%),
    linear-gradient(180deg,#0a1511 0%,var(--sm-bg0) 45%,#050a08 100%)!important;
  min-height:100%!important;
}
body.bg-gray-50,body.dark\\:bg-neutral-800,.bg-gray-50,.dark\\:bg-neutral-800:where(.dark,.dark *){
  background:transparent!important;
}
#__nuxt,main,header,[class*="max-w-"]{
  color:var(--sm-text);
}
/* Force dark panels */
.bg-white,.bg-gray-50,.bg-gray-100,.bg-gray-200,
.dark\\:bg-black:where(.dark,.dark *),
.dark\\:bg-neutral-800:where(.dark,.dark *),
.dark\\:bg-neutral-700:where(.dark,.dark *),
.dark\\:bg-neutral-600:where(.dark,.dark *),
.dark\\:bg-neutral-500:where(.dark,.dark *),
.dark\\:bg-neutral-400:where(.dark,.dark *){
  background-color:var(--sm-bg1)!important;
}
.dark\\:bg-neutral-700:where(.dark,.dark *),
.bg-neutral-700,[class*="bg-neutral-700"]{
  background-color:var(--sm-bg2)!important;
}
.dark\\:bg-neutral-800:where(.dark,.dark *),
.bg-neutral-800,[class*="bg-neutral-800"]{
  background-color:var(--sm-bg1)!important;
}
.border-gray-100,.border-gray-200,.border-neutral-800,
.dark\\:border-neutral-800:where(.dark,.dark *),
.dark\\:border-neutral-600:where(.dark,.dark *),
.dark\\:divide-neutral-800:where(.dark,.dark *)>:not([hidden])~:not([hidden]){
  border-color:var(--sm-line)!important;
}
.text-gray-500,.text-gray-400,.text-neutral-400,.text-neutral-500,
.dark\\:text-neutral-400:where(.dark,.dark *),
.dark\\:text-neutral-500:where(.dark,.dark *),
.dark\\:text-gray-400:where(.dark,.dark *){
  color:var(--sm-muted)!important;
}
.text-gray-200,.text-neutral-200,.text-neutral-300,.dark\\:text-neutral-200:where(.dark,.dark *),
.dark\\:text-neutral-300:where(.dark,.dark *),
.dark\\:text-gray-200:where(.dark,.dark *),
.dark\\:text-white:where(.dark,.dark *),
.text-white{
  color:var(--sm-text)!important;
}
/* Accent: map wg-easy reds → ServerManager green */
.bg-red-800,.bg-red-700,.bg-red-600,
.dark\\:bg-red-800:where(.dark,.dark *),
.dark\\:bg-red-600:where(.dark,.dark *),
[class*="bg-red-8"],[class*="bg-red-7"],[class*="bg-red-6"],
.data-\\[state\\=checked\\]\\:bg-red-800[data-state=checked]{
  background-color:var(--sm-accent)!important;
  color:#07110e!important;
  border-color:var(--sm-accent-strong)!important;
}
.hover\\:bg-red-700:hover,.dark\\:hover\\:bg-red-700:hover:where(.dark,.dark *),
.dark\\:hover\\:bg-red-600:hover:where(.dark,.dark *),
.dark\\:hover\\:bg-red-800:hover:where(.dark,.dark *),
[class*="hover:bg-red-"]:hover{
  background-color:#2fc48c!important;
  color:#07110e!important;
}
.text-red-600,.text-red-300,.text-red-800,
.dark\\:text-red-600:where(.dark,.dark *),
.dark\\:text-red-300:where(.dark,.dark *),
[class*="text-red-"]{
  color:var(--sm-accent)!important;
}
.border-red-600,.border-red-800,.focus\\:border-red-800:focus,
.dark\\:border-red-600:where(.dark,.dark *),
.dark\\:hover\\:border-red-600:hover:where(.dark,.dark *),
[class*="border-red-"],[class*="focus:border-red-"]:focus{
  border-color:var(--sm-accent-strong)!important;
}
.ring-red-600,.focus\\:ring-red-600:focus,.focus\\:ring-red-700:focus,
.dark\\:focus\\:ring-red-700:focus:where(.dark,.dark *),
[class*="ring-red-"]{
  --tw-ring-color:rgba(61,222,160,.45)!important;
}
.bg-red-100,.dark\\:bg-red-100:where(.dark,.dark *),
[class*="bg-red-1"]{
  background-color:var(--sm-accent-dim)!important;
  color:var(--sm-accent)!important;
}
input,textarea,select,
input:where(:not([type])),input:where([type=text]),input:where([type=password]),
input:where([type=email]),input:where([type=search]),input:where([type=number]),
textarea,select{
  background-color:var(--sm-bg0)!important;
  color:var(--sm-text)!important;
  border-color:var(--sm-line)!important;
  border-radius:10px!important;
}
input:focus,textarea:focus,select:focus{
  border-color:var(--sm-accent-strong)!important;
  --tw-ring-color:rgba(61,222,160,.35)!important;
  outline:none!important;
}
button,a,[role=button]{
  border-radius:10px!important;
}
button.rounded-full,[class*="rounded-full"]{
  border-radius:999px!important;
}
/* Keep destructive actions readable */
button[class*="danger"],.text-red-600.font-bold{
  color:var(--sm-danger)!important;
}
/* wg-easy header: centered logo only (hide language/theme/charts/user menu) */
header{
  display:flex!important;
  visibility:visible!important;
  height:auto!important;
  min-height:0!important;
  margin:1rem auto 0.5rem!important;
  padding:0!important;
  overflow:visible!important;
  pointer-events:auto!important;
  flex-direction:column!important;
  align-items:center!important;
  justify-content:center!important;
  text-align:center!important;
  border:none!important;
}
header > .mb-5{
  display:flex!important;
  visibility:visible!important;
  height:auto!important;
  min-height:0!important;
  margin:0 0 0.75rem!important;
  padding:0!important;
  overflow:visible!important;
  pointer-events:auto!important;
  width:100%!important;
  flex-direction:column!important;
  align-items:center!important;
  justify-content:center!important;
}
header > .mb-5 > a,
header > .mb-5 > a h1,
header > .mb-5 > a img,
header > .mb-5 > a span{
  display:inline-flex!important;
  visibility:visible!important;
  height:auto!important;
  min-height:0!important;
  margin:0!important;
  padding:0!important;
  overflow:visible!important;
  pointer-events:auto!important;
  align-items:center!important;
  justify-content:center!important;
}
header .flex.flex-row.gap-3,
header > .my-4{
  display:none!important;
  visibility:hidden!important;
  height:0!important;
  min-height:0!important;
  margin:0!important;
  padding:0!important;
  overflow:hidden!important;
  pointer-events:none!important;
  border:none!important;
}
/* Hide wg-easy license / donate footer */
footer,
footer p,
footer a{
  display:none!important;
  visibility:hidden!important;
  height:0!important;
  margin:0!important;
  padding:0!important;
  overflow:hidden!important;
  pointer-events:none!important;
}
""".strip()

WG_UI_THEME_SNIPPET = (
    f'<base href="{WG_UI_PREFIX}/" />'
    '<link rel="preconnect" href="https://fonts.googleapis.com" />'
    '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />'
    '<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Sora:wght@400;500;600;700&display=swap" rel="stylesheet" />'
    '<style id="sm-wg-theme">'
    + WG_UI_THEME_CSS.replace("\n", " ")
    + "</style>"
    '<script id="sm-wg-theme-js">(function(){'
    f"var P='{WG_UI_PREFIX}';"
    "try{"
    "document.cookie='theme=dark; Path='+P+'/; Max-Age=31536000; SameSite=Lax';"
    "document.documentElement.classList.add('dark');"
    "document.documentElement.classList.remove('light');"
    "document.documentElement.setAttribute('data-color-mode-forced','dark');"
    "}catch(e){}"
    "function fix(u){if(typeof u!=='string')return u;"
    "if(!u||u.charAt(0)==='#'||u.indexOf('data:')===0||u.indexOf('blob:')===0||u.indexOf('mailto:')===0)return u;"
    "if(u.indexOf(P+'/')===0||u===P)return u;"
    "if(u.indexOf('https://vpn.vpstruelord.com')===0){var r=u.slice(29);return r?P+r:P+'/';}"
    "if(u.indexOf('http://vpn.vpstruelord.com')===0){var r2=u.slice(28);return r2?P+r2:P+'/';}"
    "if(u.charAt(0)==='/'&&u.charAt(1)!=='/')return P+u;"
    "return u;}"
    "var xo=XMLHttpRequest.prototype.open;"
    "XMLHttpRequest.prototype.open=function(m,u){try{arguments[1]=fix(u);}catch(e){}"
    "return xo.apply(this,arguments);};"
    "if(window.fetch){var _f=window.fetch;window.fetch=function(i,n){"
    "try{if(typeof i==='string')i=fix(i);else if(i&&i.url)i=new Request(fix(i.url),i);}catch(e){}"
    "return _f.call(this,i,n);};}"
    "var _ps=history.pushState;history.pushState=function(s,t,u){"
    "if(u!=null)try{arguments[2]=fix(String(u));}catch(e){}"
    "return _ps.apply(this,arguments);};"
    "var _rs=history.replaceState;history.replaceState=function(s,t,u){"
    "if(u!=null)try{arguments[2]=fix(String(u));}catch(e){}"
    "return _rs.apply(this,arguments);};"
    "document.addEventListener('click',function(ev){"
    "var a=ev.target&&ev.target.closest&&ev.target.closest('a[href]');"
    "if(!a)return;"
    "var href=a.getAttribute('href');"
    "if(!href||href.charAt(0)!=='/'||href.charAt(1)==='/'||href.indexOf(P+'/')===0||href===P)return;"
    "if(a.target&&a.target!=='_self')return;"
    "ev.preventDefault();try{location.assign(P+href);}catch(e){location.href=P+href;}"
    "},true);"
    "})();</script>"
)

PANEL_TAGLINE = os.environ.get("PANEL_TAGLINE", "")
SESSION_HOURS = float(os.environ.get("SESSION_HOURS", "12"))
COOKIE_NAME = "sm_session"
ALLOW_BASIC_AUTH = os.environ.get("ALLOW_BASIC_AUTH", "0").strip().lower() in (
    "1",
    "true",
    "yes",
)

_sessions: dict[str, float] = {}
_sessions_lock = threading.Lock()
# Timed unlock for Security → VPS login method & SSH keys mutations.
SSH_PANEL_UNLOCK_SECONDS = int(os.environ.get("SSH_PANEL_UNLOCK_SECONDS", "300"))
_ssh_panel_unlocks: dict[str, float] = {}
_ssh_panel_unlocks_lock = threading.RLock()
NAS_DL_TOKEN_TTL = float(os.environ.get("NAS_DL_TOKEN_TTL", "600"))
_nas_dl_tokens: dict[str, float] = {}
_nas_dl_tokens_lock = threading.Lock()


def _purge_nas_download_tokens(now: float | None = None) -> None:
    ts = now if now is not None else time.time()
    expired = [tok for tok, exp in _nas_dl_tokens.items() if exp <= ts]
    for tok in expired:
        _nas_dl_tokens.pop(tok, None)


def issue_nas_download_token() -> str:
    now = time.time()
    with _nas_dl_tokens_lock:
        _purge_nas_download_tokens(now)
        token = secrets.token_urlsafe(18)
        _nas_dl_tokens[token] = now + NAS_DL_TOKEN_TTL
        return token


def nas_download_token_valid(token: str) -> bool:
    tok = (token or "").strip()
    if not tok:
        return False
    now = time.time()
    with _nas_dl_tokens_lock:
        _purge_nas_download_tokens(now)
        exp = _nas_dl_tokens.get(tok)
        return bool(exp and exp > now)


def build_nas_download_urls(token: str) -> dict[str, str]:
    from urllib.parse import quote

    q = f"?t={quote(token)}"
    return {
        "ps1": f"/api/nas/windows-ps1{q}",
        "cmd": f"/api/nas/windows-setup{q}",
        "setup": f"/api/nas/windows-setup{q}",
    }


def log_failed_login(ip: str, user: str, reason: str = "bad password") -> None:
    try:
        syslog.openlog("port-forward-ui", syslog.LOG_PID, syslog.LOG_AUTH)
        syslog.syslog(syslog.LOG_WARNING, f"Failed login attempt from {ip} user={user} reason={reason}")
    except OSError:
        pass


ROUTER_PUBLIC_HOST = os.environ.get("ROUTER_PUBLIC_HOST", "router.vpstruelord.com").strip() or "router.vpstruelord.com"
# LAN IP the Flint admin UI expects (Host header + redirects). SSH may use ROUTER_HOST (VPN IP).
ROUTER_ADMIN_HOST = os.environ.get("ROUTER_ADMIN_HOST", "192.168.8.1").strip() or "192.168.8.1"
ROUTER_HOST = os.environ.get("ROUTER_HOST", ROUTER_ADMIN_HOST)
PROXMOX_PUBLIC_HOST = (
    os.environ.get("PROXMOX_PUBLIC_HOST", "proxmox.vpstruelord.com").strip()
    or "proxmox.vpstruelord.com"
)
PROXMOX_HOST = os.environ.get("PROXMOX_HOST", "192.168.8.160").strip() or "192.168.8.160"
PROXMOX_PORT = int(os.environ.get("PROXMOX_PORT", "8006") or "8006")
PLEX_PUBLIC_HOST = (
    os.environ.get("PLEX_PUBLIC_HOST", "plex.vpstruelord.com").strip()
    or "plex.vpstruelord.com"
)
PLEX_HOST = os.environ.get("PLEX_HOST", "192.168.8.161").strip() or "192.168.8.161"
PLEX_PORT = int(os.environ.get("PLEX_PORT", "32400") or "32400")
GRAFANA_PUBLIC_HOST = (
    os.environ.get("GRAFANA_PUBLIC_HOST", "grafana.vpstruelord.com").strip()
    or "grafana.vpstruelord.com"
)
# Caddy (truemail network) reaches the container by name — not a public host port.
GRAFANA_HOST = os.environ.get("GRAFANA_HOST", "sm-grafana").strip() or "sm-grafana"
GRAFANA_PORT = int(os.environ.get("GRAFANA_PORT", "3000") or "3000")
# Host-local upstream for portal SSO (compose publishes 127.0.0.1:3016 only).
GRAFANA_UPSTREAM = os.environ.get(
    "GRAFANA_UPSTREAM", "http://127.0.0.1:3016"
).rstrip("/") or "http://127.0.0.1:3016"
GRAFANA_ENV_FILE = Path(
    os.environ.get("GRAFANA_ENV_FILE", "/opt/grafana/.env")
)
GRAFANA_COOKIE = "grafana_session"
GRAFANA_COOKIE_EXPIRY = "grafana_session_expiry"
PLEX_CTID = os.environ.get("PLEX_CTID", "101").strip() or "101"


def _load_grafana_admin() -> tuple[str, str]:
    """Read Grafana admin user/password from env or /opt/grafana/.env."""
    user = (os.environ.get("GRAFANA_ADMIN_USER") or os.environ.get("GF_ADMIN_USER") or "").strip()
    password = (
        os.environ.get("GRAFANA_ADMIN_PASSWORD")
        or os.environ.get("GF_ADMIN_PASSWORD")
        or ""
    ).strip()
    if GRAFANA_ENV_FILE.is_file():
        parsed: dict[str, str] = {}
        try:
            raw_text = GRAFANA_ENV_FILE.read_text(encoding="utf-8", errors="replace")
        except Exception:
            raw_text = ""
        for raw in raw_text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            parsed[key.strip()] = val.strip().strip("'\"")
        user = user or (parsed.get("GF_ADMIN_USER") or "admin").strip() or "admin"
        password = password or (parsed.get("GF_ADMIN_PASSWORD") or "").strip()
    return (user or "admin"), password


GRAFANA_SSO_USER, GRAFANA_SSO_PASS = _load_grafana_admin()

PROXMOX_SSH_HOST = os.environ.get("PROXMOX_SSH_HOST", PROXMOX_HOST).strip() or PROXMOX_HOST
PROXMOX_SSH_USER = os.environ.get("PROXMOX_SSH_USER", "root").strip() or "root"
PROXMOX_SSH_KEY = os.environ.get("PROXMOX_SSH_KEY", "/root/.ssh/id_ed25519").strip() or "/root/.ssh/id_ed25519"
PROXMOX_LED_CMD = os.environ.get(
    "PROXMOX_LED_CMD", "/usr/local/sbin/alienware-leds"
).strip() or "/usr/local/sbin/alienware-leds"
PROXMOX_LED_OWNER_CMD = os.environ.get(
    "PROXMOX_LED_OWNER_CMD", "/usr/local/sbin/aw-elc-usb-owner"
).strip() or "/usr/local/sbin/aw-elc-usb-owner"
# Windows GPU VM that can run Alienware FX Lighting when it owns the AW-ELC USB.
PROXMOX_LED_WINDOWS_VMID = os.environ.get("PROXMOX_LED_WINDOWS_VMID", "100").strip() or "100"
PROXMOX_BT_OWNER_CMD = os.environ.get(
    "PROXMOX_BT_OWNER_CMD", "/usr/local/sbin/bt-usb-owner"
).strip() or "/usr/local/sbin/bt-usb-owner"
PROXMOX_BT_WINDOWS_VMID = os.environ.get(
    "PROXMOX_BT_WINDOWS_VMID", PROXMOX_LED_WINDOWS_VMID
).strip() or PROXMOX_LED_WINDOWS_VMID
PROXMOX_BT_USB_ID = os.environ.get("PROXMOX_BT_USB_ID", "0bda:2852").strip() or "0bda:2852"
PROXMOX_XBOX_OWNER_CMD = os.environ.get(
    "PROXMOX_XBOX_OWNER_CMD", "/usr/local/sbin/xbox-usb-owner"
).strip() or "/usr/local/sbin/xbox-usb-owner"
PROXMOX_XBOX_WINDOWS_VMID = os.environ.get(
    "PROXMOX_XBOX_WINDOWS_VMID", PROXMOX_LED_WINDOWS_VMID
).strip() or PROXMOX_LED_WINDOWS_VMID
PROXMOX_XBOX_USB_ID = os.environ.get("PROXMOX_XBOX_USB_ID", "045e:0b12").strip() or "045e:0b12"
PROXMOX_ELEMENTS_CMD = os.environ.get(
    "PROXMOX_ELEMENTS_CMD", "/usr/local/sbin/elements-plex-hookup"
).strip() or "/usr/local/sbin/elements-plex-hookup"
PROXMOX_ELEMENTS_PIPELINE_CMD = os.environ.get(
    "PROXMOX_ELEMENTS_PIPELINE_CMD", "/usr/local/sbin/elements-media-pipeline"
).strip() or "/usr/local/sbin/elements-media-pipeline"
ELEMENTS_UPLOAD_MAX_BYTES = int(
    os.environ.get("ELEMENTS_UPLOAD_MAX_BYTES", str(16 * 1024 * 1024 * 1024))
)

ROUTER_HOSTS = [
    h.strip()
    for h in os.environ.get("ROUTER_HOSTS", "10.9.0.2,192.168.8.1,10.8.0.3").split(",")
    if h.strip()
]
if ROUTER_HOST not in ROUTER_HOSTS:
    ROUTER_HOSTS.insert(0, ROUTER_HOST)
ROUTER_USER = os.environ.get("ROUTER_USER", "root")
ROUTER_CONF = os.environ.get("ROUTER_CONF", "/etc/config/port_forward")
OVPN_STATUS_LOG = Path(
    os.environ.get("OVPN_STATUS_LOG", "/var/log/openvpn-status.log")
)
OVPN_FLINT_VPN_IP = os.environ.get("OVPN_FLINT_VPN_IP", "10.9.0.2").strip() or "10.9.0.2"
OVPN_SERVICE = os.environ.get("OVPN_SERVICE", "openvpn-server-sm").strip() or "openvpn-server-sm"
OVPN_LISTEN = os.environ.get("OVPN_LISTEN", "74.208.76.213:443").strip() or "74.208.76.213:443"
OVPN_DNS_ADGUARD = os.environ.get("OVPN_DNS_ADGUARD", "10.42.42.44").strip() or "10.42.42.44"
IKEV2_DIR = Path(os.environ.get("IKEV2_DIR", "/opt/ikev2"))
IKEV2_HOST = os.environ.get("IKEV2_HOST", PORTAL_HOST or "portal.vpstruelord.com").strip() or (
    "portal.vpstruelord.com"
)
IKEV2_USER = os.environ.get("IKEV2_USER", "windows").strip() or "windows"
IKEV2_POOL = os.environ.get("IKEV2_POOL", "10.10.0.0/24").strip() or "10.10.0.0/24"
IKEV2_DNS = os.environ.get("IKEV2_DNS", "10.9.0.1").strip() or "10.9.0.1"
IKEV2_SERVICE = os.environ.get("IKEV2_SERVICE", "strongswan-starter").strip() or "strongswan-starter"


def build_ikev2_status() -> dict:
    """Status + credentials for Windows built-in IKEv2 VPN."""
    active = False
    detail = ""
    try:
        proc = subprocess.run(
            ["systemctl", "is-active", IKEV2_SERVICE],
            capture_output=True,
            text=True,
            timeout=8,
        )
        active = (proc.stdout or "").strip() == "active"
        detail = (proc.stdout or proc.stderr or "").strip() or ("active" if active else "inactive")
    except Exception as exc:
        detail = str(exc)

    password = ""
    pass_file = IKEV2_DIR / "windows.pass"
    if pass_file.is_file():
        try:
            password = pass_file.read_text(encoding="utf-8", errors="replace").strip()
        except Exception:
            password = ""

    peers: list[dict] = []
    try:
        proc = subprocess.run(
            ["ipsec", "statusall"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        text = proc.stdout or ""
        for line in text.splitlines():
            # Example: ikev2-eap[3]: ESTABLISHED ... 74.x[...]...10.y[...]
            if "ESTABLISHED" in line and "ikev2" in line.lower():
                peers.append({"id": line.strip().split(":", 1)[0].strip(), "remote": line.strip()})
            elif "===" in line and "10.10." in line:
                peers.append({"vip": line.strip(), "remote": ""})
    except Exception:
        pass

    return {
        "ok": True,
        "active": active,
        "detail": detail,
        "host": IKEV2_HOST,
        "username": IKEV2_USER,
        "password": password,
        "pool": IKEV2_POOL,
        "dns": IKEV2_DNS,
        "adguard": OVPN_DNS_ADGUARD,
        "ports": "UDP 500 / 4500",
        "peers": peers[:20],
        "ps1": "/api/ikev2/windows-ps1",
    }


def load_ikev2_ca_pem() -> str:
    """Return the IKEv2 CA PEM Windows must trust (empty if missing)."""
    for path in (IKEV2_DIR / "certs" / "ca.crt", Path("/etc/ipsec.d/cacerts/ikev2-ca.pem")):
        if path.is_file():
            try:
                text = path.read_text(encoding="utf-8", errors="replace").strip()
                if "BEGIN CERTIFICATE" in text:
                    return text + "\n"
            except Exception:
                continue
    return ""


def load_ikev2_windows_ps1() -> bytes:
    """PowerShell helper that trusts the IKEv2 CA and creates the VPN profile."""
    candidates = [
        Path(__file__).resolve().parent / "scripts" / "ikev2" / "Setup-ServerManagerVpn.ps1",
        IKEV2_DIR / "Setup-ServerManagerVpn.ps1",
    ]
    ca_pem = load_ikev2_ca_pem().strip() or "@@CA_CERT_PEM@@"
    text = ""
    for path in candidates:
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="replace")
            break
    if not text:
        text = f"""# ServerManager Windows IKEv2
$Server = "{IKEV2_HOST}"
$Name = "ServerManager IKEv2"
$Username = "{IKEV2_USER}"
$CaPem = @"
@@CA_CERT_PEM@@
"@
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {{ throw "Run PowerShell as Administrator" }}
if ($CaPem -match "BEGIN CERTIFICATE") {{
  $caPath = Join-Path $env:TEMP "ServerManager-IKEv2-CA.crt"
  Set-Content -Path $caPath -Value $CaPem.Trim() -Encoding ASCII
  Import-Certificate -FilePath $caPath -CertStoreLocation Cert:\\LocalMachine\\Root | Out-Null
}}
Get-VpnConnection -Name $Name -AllUserConnection -ErrorAction SilentlyContinue | Remove-VpnConnection -Force -AllUserConnection -ErrorAction SilentlyContinue
Add-VpnConnection -Name $Name -ServerAddress $Server -TunnelType Ikev2 -AuthenticationMethod Eap -EncryptionLevel Required -RememberCredential -AllUserConnection -Force
Set-VpnConnectionIPsecConfiguration -ConnectionName $Name -AuthenticationTransformConstants SHA256128 -CipherTransformConstants AES256 -DHGroup Group14 -EncryptionMethod AES256 -IntegrityCheckMethod SHA256 -PfsGroup None -AllUserConnection -Force
Write-Host "Connect via Settings -> VPN -> $Name (user $Username)"
"""
    text = text.replace("portal.vpstruelord.com", IKEV2_HOST)
    text = text.replace('Username = "windows"', f'Username = "{IKEV2_USER}"')
    text = text.replace("@@CA_CERT_PEM@@", ca_pem)
    # UTF-8 BOM so Windows PowerShell 5.1 parses the file correctly
    return b"\xef\xbb\xbf" + text.encode("utf-8")


def load_ikev2_windows_cmd() -> bytes:
    """CMD launcher that elevates and runs the sibling .ps1 (same download folder)."""
    body = """@echo off
setlocal
NET SESSION >nul 2>&1
if %errorLevel% NEQ 0 (
  echo Requesting Administrator...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
set "PS1=%~dp0Setup-ServerManagerVpn.ps1"
if not exist "%PS1%" (
  echo ERROR: Setup-ServerManagerVpn.ps1 not found next to this .cmd
  echo Download both files into the same folder, then run this .cmd
  pause
  exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%"
if errorlevel 1 pause
"""
    return body.replace("\n", "\r\n").encode("ascii", errors="replace")


def parse_openvpn_status(text: str) -> dict:
    """Parse OpenVPN management status log into clients + routes."""
    clients: list[dict] = []
    routes: list[dict] = []
    updated = ""
    section = ""
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("OpenVPN CLIENT LIST"):
            section = "clients"
            continue
        if line.startswith("ROUTING TABLE"):
            section = "routes"
            continue
        if line.startswith("GLOBAL STATS") or line == "END":
            section = ""
            continue
        if line.startswith("Updated,"):
            updated = line.split(",", 1)[-1].strip()
            continue
        if section == "clients":
            if line.startswith("Common Name"):
                continue
            parts = line.split(",")
            if len(parts) < 5:
                continue
            clients.append(
                {
                    "name": parts[0].strip(),
                    "real_address": parts[1].strip(),
                    "bytes_received": int(parts[2]) if parts[2].isdigit() else 0,
                    "bytes_sent": int(parts[3]) if parts[3].isdigit() else 0,
                    "connected_since": parts[4].strip(),
                }
            )
        elif section == "routes":
            if line.startswith("Virtual Address"):
                continue
            parts = line.split(",")
            if len(parts) < 4:
                continue
            routes.append(
                {
                    "virtual": parts[0].strip(),
                    "name": parts[1].strip(),
                    "real_address": parts[2].strip(),
                    "last_ref": parts[3].strip(),
                }
            )
    return {"updated": updated, "clients": clients, "routes": routes}


def build_openvpn_status() -> dict:
    """Live OpenVPN server status for the OpenVPN admin website."""
    active = False
    detail = ""
    try:
        proc = subprocess.run(
            ["systemctl", "is-active", OVPN_SERVICE],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        active = (proc.stdout or "").strip() == "active"
        detail = (proc.stdout or proc.stderr or "").strip()
    except Exception as exc:  # noqa: BLE001
        detail = str(exc)

    parsed = {"updated": "", "clients": [], "routes": []}
    status_error = ""
    try:
        text = OVPN_STATUS_LOG.read_text(encoding="utf-8", errors="replace")
        parsed = parse_openvpn_status(text)
    except OSError as exc:
        status_error = str(exc)

    profiles = []  # legacy field; UI uses /api/openvpn/clients
    clients = list_openvpn_clients()

    return {
        "ok": True,
        "service": OVPN_SERVICE,
        "active": active,
        "detail": detail,
        "listen": OVPN_LISTEN,
        "proto": "tcp",
        "network": "10.9.0.0/24",
        "crypto": "tls-auth + AES-256-CBC",
        "updated": parsed.get("updated") or "",
        "clients": parsed.get("clients") or [],
        "routes": parsed.get("routes") or [],
        "client_count": len(parsed.get("clients") or []),
        "managed_clients": clients,
        "profiles": profiles,
        "allow_ssh_script": "/api/openvpn/allow-ssh",
        "status_error": status_error,
        "flint_connected": any(
            str(c.get("name") or "").lower() == "flint" for c in (parsed.get("clients") or [])
        ),
    }


_ovpn_flint_connected_cache: tuple[bool, float] = (False, 0.0)
_ovpn_flint_connected_cache_lock = threading.Lock()


def _ovpn_flint_connected() -> bool:
    """True when OpenVPN status shows the Flint client is online."""
    global _ovpn_flint_connected_cache
    now = time.time()
    with _ovpn_flint_connected_cache_lock:
        cached, ts = _ovpn_flint_connected_cache
        if now - ts < 5:
            return cached
    try:
        connected = bool(build_openvpn_status().get("flint_connected"))
    except Exception:
        connected = False
    with _ovpn_flint_connected_cache_lock:
        _ovpn_flint_connected_cache = (connected, now)
    return connected


def ensure_ovpn_home_lan_routes() -> dict:
    """Prefer tun0→Flint for 192.168.8.0/24 while school OpenVPN is up.

    wg-easy / docker often installs an *unmetered* via-10.42.42.42 route that
    beats OpenVPN's metric-5 path, so Buffalo admin/files time out from the VPS.
    """
    wg_gw = os.environ.get("WG_LAN_GW", "10.42.42.42").strip() or "10.42.42.42"
    ovpn_gw = OVPN_FLINT_VPN_IP
    actions: list[str] = []
    if not _ovpn_flint_connected():
        return {"ok": True, "skipped": "flint not on openvpn", "actions": actions}

    def _run(cmd: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=8)

    for cidr in ("192.168.8.0/24", "10.0.0.0/24", "10.8.0.0/24"):
        for _ in range(8):
            proc = _run(["ip", "route", "del", cidr, "via", wg_gw])
            if proc.returncode != 0:
                break
            actions.append(f"del {cidr} via {wg_gw}")
    for cidr in ("192.168.8.0/24", "10.0.0.0/24"):
        proc = _run(
            ["ip", "route", "replace", cidr, "via", ovpn_gw, "dev", "tun0", "metric", "5"]
        )
        if proc.returncode == 0:
            actions.append(f"ovpn {cidr} via {ovpn_gw} metric 5")
        else:
            actions.append(
                f"ovpn {cidr} failed: {(proc.stderr or proc.stdout or '').strip()}"
            )
    for cidr in ("192.168.8.0/24", "10.0.0.0/24", "10.8.0.0/24"):
        _run(["ip", "route", "replace", cidr, "via", wg_gw, "metric", "100"])
        actions.append(f"wg-backup {cidr} via {wg_gw} metric 100")
    return {"ok": True, "actions": actions}


def _prepare_nas_files_proxy(*, force: bool = False) -> dict:
    """Ensure VPS routes and Flint OVPN→LAN access before NAS Files proxy."""
    try:
        return ensure_flint_ovpn_lan_access(force=force)
    except Exception as exc:
        try:
            routes = ensure_ovpn_home_lan_routes()
            return {"ok": True, "routes": routes, "warn": str(exc)}
        except Exception as exc2:
            return {"ok": False, "error": str(exc2)}


def _nas_files_error_detail(exc: Exception) -> dict:
    """Actionable JSON for NAS Files proxy failures."""
    host = urlparse(NAS_FILES_UPSTREAM).hostname or "192.168.8.159"
    port = int(urlparse(NAS_FILES_UPSTREAM).port or 9000)
    ovpn = _ovpn_flint_connected()
    detail: dict = {
        "error": f"nas files proxy failed: {exc}",
        "upstream": f"{host}:{port}",
        "openvpn_flint": ovpn,
    }
    err = str(exc).lower()
    if "no route to host" in err or "errno 113" in err or "host unreachable" in err:
        if ovpn:
            detail["hint"] = (
                f"OpenVPN to home is connected, but the Buffalo NAS at {host} is not "
                "responding on your home network. Power it on and confirm it is on Wi‑Fi/Ethernet."
            )
        else:
            detail["hint"] = (
                "Home OpenVPN is not connected. Use the OpenVPN client profile from the "
                "portal while on a restricted network, or check the Flint router at home."
            )
    elif "timed out" in err or "timeout" in err:
        detail["hint"] = (
            "The NAS did not respond in time. Check home network routing or wake the NAS "
            f"at {host} if it is in sleep mode."
        )
    return detail


_flint_lan_ensure_ts = 0.0
_flint_lan_ensure_lock = threading.Lock()


def ensure_flint_ovpn_lan_access(*, force: bool = False) -> dict:
    """SSH to Flint and allow OVPN→LAN (Buffalo) + SSH. Rate-limited."""
    global _flint_lan_ensure_ts
    if not _ovpn_flint_connected():
        return {"ok": True, "skipped": "flint not on openvpn"}
    now = time.time()
    with _flint_lan_ensure_lock:
        if not force and (now - _flint_lan_ensure_ts) < 60:
            return {"ok": True, "skipped": "recently applied"}
        _flint_lan_ensure_ts = now

    ensure_ovpn_home_lan_routes()
    script_name = OVPN_ALLOW_SSH_SCRIPT
    try:
        body = load_openvpn_script(script_name)
    except Exception as exc:
        return {"ok": False, "error": f"script missing: {exc}"}

    remote = "/tmp/flint-allow-vpn-ssh.sh"
    upload = router_ssh(f"cat > {remote}", input_text=body.decode("utf-8", errors="replace"), timeout=20)
    if upload.returncode != 0:
        return {
            "ok": False,
            "error": (upload.stderr or upload.stdout or "upload failed").strip(),
        }
    run = router_ssh(f"chmod +x {remote} && sh {remote}", timeout=40)
    ok = run.returncode == 0
    return {
        "ok": ok,
        "stdout": (run.stdout or "")[-1500:],
        "stderr": (run.stderr or "")[-800:],
    }


def _router_hosts_for_ssh() -> list[str]:
    """Prefer OpenVPN Flint IP when the school tunnel is up."""
    hosts: list[str] = []
    if _ovpn_flint_connected() and OVPN_FLINT_VPN_IP:
        hosts.append(OVPN_FLINT_VPN_IP)
    for h in ROUTER_HOSTS:
        if h not in hosts:
            hosts.append(h)
    for h in ("192.168.8.1", "10.8.0.3"):
        if h not in hosts:
            hosts.append(h)
    return hosts


def _load_router_pass() -> str:
    raw = os.environ.get("ROUTER_PASS", "")
    b64 = os.environ.get("ROUTER_PASS_B64", "")
    if b64:
        try:
            return base64.b64decode(b64).decode("utf-8")
        except Exception as exc:  # noqa: BLE001
            raise SystemExit(f"Invalid ROUTER_PASS_B64: {exc}") from exc
    return raw


ROUTER_PASS = _load_router_pass()

# Optional: leave CADDYFILE_PATH empty to disable domain hookups
_caddy_raw = os.environ.get("CADDYFILE_PATH", "").strip()
CADDYFILE_PATH = Path(_caddy_raw) if _caddy_raw else Path("")
CADDY_CONTAINER = os.environ.get("CADDY_CONTAINER", "")
HOOKUPS_JSON = Path(
    os.environ.get("HOOKUPS_JSON", "/opt/servermanager/panel/hookups.json")
)
COREDNS_COREFILE = Path(
    os.environ.get("COREDNS_COREFILE", "/opt/wireguard/coredns/Corefile")
)
COREDNS_CONTAINER = os.environ.get("COREDNS_CONTAINER", "wg-portal-dns").strip()
COREDNS_BEGIN = "# BEGIN SM-VPN-DNS"
COREDNS_END = "# END SM-VPN-DNS"
HOOKUPS_BEGIN = "# BEGIN PORT-FORWARD-HOOKUPS"
HOOKUPS_END = "# END PORT-FORWARD-HOOKUPS"
VPS_PUBLIC_IP = os.environ.get("VPS_PUBLIC_IP", "0.0.0.0")
DOCKER_HOST_GW = os.environ.get("DOCKER_HOST_GW", "172.18.0.1")
# Cloudflare DNS automation (optional)
CF_API_TOKEN = os.environ.get("CF_API_TOKEN", "").strip()
CF_ZONE_ID = os.environ.get("CF_ZONE_ID", "").strip()
CF_ZONE_NAME = os.environ.get("CF_ZONE_NAME", "").strip()
CF_PROXIED = os.environ.get("CF_PROXIED", "false").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
# Source IPs allowed when a domain/port is marked VPN-only
VPN_CLIENT_CIDRS = os.environ.get(
    "VPN_CLIENT_CIDRS",
    # No blanket 192.168.8.0/24 — approved LAN /32s are appended by peer-acl sync.
    "10.8.0.0/24 10.42.42.0/24 10.9.0.0/24 10.10.0.0/24 100.64.0.0/10 127.0.0.1/32 74.208.76.213/32 10.11.0.1/32",
)
# Space/comma-separated CIDRs allowed when a UFW rule is marked VPN-only.
# Defaults cover WireGuard, OpenVPN, Tailscale CGNAT, and home LAN via Flint.
VPN_UFW_FROM = os.environ.get(
    "VPN_UFW_FROM",
    "10.8.0.0/24 10.9.0.0/24 100.64.0.0/10 192.168.8.0/24",
).strip() or "10.8.0.0/24 10.9.0.0/24 100.64.0.0/10 192.168.8.0/24"
PIHOLE_SSO_SECRET = os.environ.get("PIHOLE_SSO_SECRET", "").strip()
PIHOLE_SSO_URL = os.environ.get(
    "PIHOLE_SSO_URL", "https://pihole.vpstruelord.com/sm-autologin"
).strip()
BUFFALO_SSO_USER = os.environ.get("BUFFALO_USER", "admin").strip() or "admin"


def _load_buffalo_pass() -> str:
    raw = os.environ.get("BUFFALO_PASS", "")
    b64 = os.environ.get("BUFFALO_PASS_B64", "")
    if b64:
        try:
            return base64.b64decode(b64).decode("utf-8")
        except Exception:
            return raw
    return raw


BUFFALO_SSO_PASS = _load_buffalo_pass()


# --- Independent NAS Files via FTP (Drive-style UI) ---
FTP_HOST = os.environ.get("FTP_HOST", urlparse(BUFFALO_UPSTREAM).hostname or "192.168.8.159").strip()
FTP_PORT = int(os.environ.get("FTP_PORT", "21"))
FTP_USER = (os.environ.get("FTP_USER", "") or BUFFALO_SSO_USER).strip() or "admin"
FTP_TIMEOUT = float(os.environ.get("FTP_TIMEOUT", "30"))
FTP_LIST_CACHE_TTL = float(os.environ.get("FTP_LIST_CACHE_TTL", "4"))
FTP_POOL_MAX_IDLE = float(os.environ.get("FTP_POOL_MAX_IDLE", "120"))


def _load_ftp_pass() -> str:
    b64 = os.environ.get("FTP_PASS_B64", "").strip()
    raw = os.environ.get("FTP_PASS", "")
    if b64:
        try:
            return base64.b64decode(b64).decode("utf-8")
        except Exception:
            pass
    if raw:
        return raw
    return BUFFALO_SSO_PASS


FTP_PASS = _load_ftp_pass()

NAS_SMB_HOST = os.environ.get("NAS_SMB_HOST", FTP_HOST).strip() or FTP_HOST
NAS_SMB_SHARE = os.environ.get("NAS_SMB_SHARE", "share").strip() or "share"
NAS_SMB_NETBIOS = os.environ.get("NAS_SMB_NETBIOS", "741HOMECLOUDNET").strip() or "741HOMECLOUDNET"
NAS_SMB_PUBLIC_HOST = (
    os.environ.get("NAS_SMB_PUBLIC_HOST", PORTAL_HOST).strip() or PORTAL_HOST
)
NAS_SMB_PUBLIC_IP = os.environ.get("NAS_SMB_PUBLIC_IP", "74.208.76.213").strip() or "74.208.76.213"
NAS_SMB_PUBLIC_PORT = int(os.environ.get("NAS_SMB_PUBLIC_PORT", "1445"))
NAS_DRIVE_LETTER = (os.environ.get("NAS_DRIVE_LETTER", "Z").strip() or "Z")[:1].upper()
NAS_DRIVE_LABEL = os.environ.get("NAS_DRIVE_LABEL", "ServerManager NAS").strip() or "ServerManager NAS"
NAS_SMB_FORWARD_PUB = int(os.environ.get("NAS_SMB_FORWARD_PUB", str(NAS_SMB_PUBLIC_PORT)))
NAS_FTP_PUBLIC_PORT = int(os.environ.get("NAS_FTP_PUBLIC_PORT", "2121"))
NAS_FTP_PASV_START = int(os.environ.get("NAS_FTP_PASV_START", "50100"))
NAS_FTP_PASV_END = int(os.environ.get("NAS_FTP_PASV_END", "50200"))
NAS_FTP_PUBLIC_USER = (
    os.environ.get("NAS_FTP_PUBLIC_USER", "admin").strip() or "admin"
)


def _load_nas_smb_pass() -> str:
    """SMB mapping password — defaults to Buffalo admin, not a separate FTP override."""
    b64 = os.environ.get("NAS_SMB_PASS_B64", "").strip()
    raw = os.environ.get("NAS_SMB_PASS", "").strip()
    if b64:
        try:
            return base64.b64decode(b64).decode("utf-8")
        except Exception:
            pass
    if raw:
        return raw
    return BUFFALO_SSO_PASS


NAS_SMB_PASS = _load_nas_smb_pass()


def _smb_probe() -> dict:
    """Best-effort SMB login test via public forward (smbclient when available)."""
    if not NAS_SMB_PASS:
        return {"ok": False, "error": "NAS SMB password not configured"}
    user = FTP_USER
    share = NAS_SMB_SHARE
    host = NAS_SMB_PUBLIC_IP
    port = NAS_SMB_PUBLIC_PORT
    import shutil
    import subprocess

    smbclient = shutil.which("smbclient")
    if not smbclient:
        return {"ok": None, "error": "smbclient not installed on portal host"}
    cmd = [
        smbclient,
        f"//{host}/{share}",
        "-p",
        str(port),
        "-U",
        f"{user}%{NAS_SMB_PASS}",
        "-c",
        "ls",
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        if proc.returncode == 0:
            return {"ok": True, "detail": "SMB login ok"}
        if "LOGON_FAILURE" in out or "ACCESS_DENIED" in out:
            return {"ok": False, "error": "SMB login failed (bad password or user)"}
        return {"ok": False, "error": (out.strip() or f"smbclient exit {proc.returncode}")[:240]}
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:240]}


def _ps_single_quoted(value: str) -> str:
    return "'" + (value or "").replace("'", "''") + "'"


def build_nas_windows_status() -> dict:
    """SMB mapping info for Windows File Explorer (credentials for authenticated portal users)."""
    st = _FTP.status()
    smb = _smb_probe()
    if NAS_SMB_PUBLIC_PORT != 445:
        unc = f"\\\\{NAS_SMB_PUBLIC_HOST}@{NAS_SMB_PUBLIC_PORT}\\{NAS_SMB_SHARE}"
    else:
        unc = f"\\\\{NAS_SMB_PUBLIC_HOST}\\{NAS_SMB_SHARE}"
    return {
        "ok": bool(st.get("ok")),
        "host": NAS_SMB_PUBLIC_HOST,
        "public_ip": NAS_SMB_PUBLIC_IP,
        "lan_host": NAS_SMB_HOST,
        "share": NAS_SMB_SHARE,
        "netbios": NAS_SMB_NETBIOS,
        "username": FTP_USER,
        "ftp_username": NAS_FTP_PUBLIC_USER,
        "password": NAS_SMB_PASS,
        "smb_ok": smb.get("ok"),
        "smb_detail": smb.get("detail") or smb.get("error") or "",
        "drive": NAS_DRIVE_LETTER,
        "label": NAS_DRIVE_LABEL,
        "unc": unc,
        "smb_port": NAS_SMB_PUBLIC_PORT,
        "forward_pub": NAS_SMB_FORWARD_PUB,
        "ftp_host": NAS_SMB_PUBLIC_HOST,
        "ftp_ip": NAS_SMB_PUBLIC_IP,
        "ftp_port": NAS_FTP_PUBLIC_PORT,
        "ftp_pasv": f"{NAS_FTP_PASV_START}-{NAS_FTP_PASV_END}",
        "port": FTP_PORT,
        "ps1": "/api/nas/windows-ps1",
        "detail": st.get("error") or st.get("welcome") or "",
    }


def load_nas_windows_ps1() -> bytes:
    """PowerShell helper that maps the Buffalo NAS as a persistent drive letter."""
    if not NAS_SMB_PASS:
        raise RuntimeError("NAS password not configured (set BUFFALO_PASS_B64 on the VPS)")
    candidates = [
        Path(__file__).resolve().parent / "scripts" / "nas" / "Setup-ServerManagerNas.ps1",
    ]
    text = ""
    for path in candidates:
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="replace")
            break
    if not text:
        text = f"""# ServerManager NAS
$NasHost = "{NAS_SMB_HOST}"
$Share = "{NAS_SMB_SHARE}"
$Username = "{FTP_USER}"
$Password = {_ps_single_quoted(NAS_SMB_PASS)}
$DriveLetter = "{NAS_DRIVE_LETTER}"
$Label = "{NAS_DRIVE_LABEL}"
"""
    text = text.replace("192.168.8.159", NAS_SMB_PUBLIC_HOST)
    text = text.replace('NasHost = "192.168.8.159"', f'NasHost = "{NAS_SMB_PUBLIC_HOST}"')
    text = text.replace('NasIp = "74.208.76.213"', f'NasIp = "{NAS_SMB_PUBLIC_IP}"')
    text = text.replace('NasPort = 1445', f'NasPort = {NAS_SMB_PUBLIC_PORT}')
    text = text.replace('LocalListenIp = "10.255.255.1"', f'LocalListenIp = "10.255.255.1"')
    text = text.replace('LocalSmbPort = 445', f'LocalSmbPort = 445')
    text = text.replace('LocalSmbPort = 14450', f'LocalSmbPort = 445')
    text = text.replace('MapAlias = "sm-nas.vpstruelord.com"', f'MapAlias = "sm-nas.{NAS_SMB_PUBLIC_HOST}"')
    text = text.replace('Share = "share"', f'Share = "{NAS_SMB_SHARE}"')
    text = text.replace('NasNetbiosName = "741HOMECLOUDNET"', f'NasNetbiosName = "{NAS_SMB_NETBIOS}"')
    text = text.replace('NasLanIp = "192.168.8.159"', f'NasLanIp = "{NAS_SMB_HOST}"')
    text = text.replace('Username = "admin"', f'Username = "{FTP_USER}"')
    text = text.replace(
        "[string]$Password = '@@NAS_PASSWORD@@'",
        f"[string]$Password = {_ps_single_quoted(NAS_SMB_PASS)}",
    )
    text = text.replace('DriveLetter = "Z"', f'DriveLetter = "{NAS_DRIVE_LETTER}"')
    text = text.replace('Label = "ServerManager NAS"', f'Label = "{NAS_DRIVE_LABEL}"')
    if "[string]$Password = '@@NAS_PASSWORD@@'" in text:
        raise RuntimeError("password substitution failed")
    return b"\xef\xbb\xbf" + text.encode("utf-8")


def load_nas_windows_bundle_cmd() -> bytes:
    """Single self-extracting installer: writes PS1 next to itself, then runs elevated."""
    ps1_bytes = load_nas_windows_ps1()
    b64 = base64.b64encode(ps1_bytes).decode("ascii")
    pw_b64 = base64.b64encode(NAS_SMB_PASS.encode("utf-8")).decode("ascii")
    body = f"""@echo off
setlocal
cd /d "%~dp0"
set "SM_NAS_PASSWORD_B64={pw_b64}"
echo ServerManager NAS setup - preparing...
powershell -NoProfile -ExecutionPolicy Bypass -Command "& {{ $ErrorActionPreference='Stop'; $self='%~f0'; $raw=Get-Content -LiteralPath $self -Raw; if ($raw -notmatch '(?s)BEGIN_PS1\\r?\\n([A-Za-z0-9+/=]+)\\r?\\nEND_PS1') {{ Write-Host 'Installer corrupt - download again from the portal.' -ForegroundColor Red; pause; exit 1 }}; $dir=Split-Path -Parent $self; $out=Join-Path $dir 'Setup-ServerManagerNas.ps1'; $pw=Join-Path $dir 'Setup-ServerManagerNas.pw'; [IO.File]::WriteAllBytes($out, [Convert]::FromBase64String($Matches[1].Trim())); $pass=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:SM_NAS_PASSWORD_B64)); [IO.File]::WriteAllText($pw, $pass, [Text.UTF8Encoding]::new($false)); $admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); if ($admin) {{ & $out }} else {{ Start-Process powershell.exe -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File', $out) -Wait }} }}"
if errorlevel 1 (
  echo Setup failed. See %%TEMP%%\\ServerManagerNas-setup.log
  pause
)
exit /b 0
BEGIN_PS1
{b64}
END_PS1
"""
    return body.replace("\n", "\r\n").encode("ascii", errors="replace")


def load_nas_windows_cmd() -> bytes:
    """Backward-compatible alias for the single-file installer."""
    return load_nas_windows_bundle_cmd()


def ftp_norm_path(path: str) -> str:
    raw = (path or "/").replace("\\", "/")
    parts: list[str] = []
    for part in raw.split("/"):
        if not part or part == ".":
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        if any(ch in part for ch in ("\x00", "\n", "\r")):
            raise ValueError("invalid path")
        parts.append(part)
    return "/" + "/".join(parts) if parts else "/"


def ftp_parent(path: str) -> str:
    p = ftp_norm_path(path)
    if p == "/":
        return "/"
    return ftp_norm_path(str(Path(p).parent).replace("\\", "/"))


def ftp_guess_mime(name: str) -> str:
    ctype, _ = mimetypes.guess_type(name or "")
    if ctype:
        return ctype
    lower = (name or "").lower()
    if lower.endswith((".md", ".markdown", ".log", ".conf", ".cfg", ".ini", ".env")):
        return "text/plain; charset=utf-8"
    if lower.endswith((".ts", ".tsx", ".jsx", ".vue")):
        return "text/plain; charset=utf-8"
    return "application/octet-stream"


class _FtpPool:
    """Reuse one FTP control connection (locked) + short list cache."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._ftp: ftplib.FTP | None = None
        self._last_used = 0.0
        self._list_cache: dict[str, tuple[float, dict]] = {}

    def _drop(self) -> None:
        if self._ftp is not None:
            try:
                self._ftp.close()
            except Exception:
                pass
        self._ftp = None

    def _ensure(self) -> ftplib.FTP:
        if not FTP_PASS:
            raise RuntimeError("FTP_PASS / FTP_PASS_B64 / BUFFALO_PASS not configured")
        now = time.time()
        if self._ftp is not None:
            if now - self._last_used > FTP_POOL_MAX_IDLE:
                self._drop()
            else:
                try:
                    self._ftp.voidcmd("NOOP")
                    self._last_used = now
                    return self._ftp
                except Exception:
                    self._drop()
        ftp = ftplib.FTP()
        ftp.connect(FTP_HOST, FTP_PORT, timeout=FTP_TIMEOUT)
        ftp.login(FTP_USER, FTP_PASS)
        ftp.set_pasv(True)
        try:
            ftp.sendcmd("TYPE I")
        except Exception:
            pass
        self._ftp = ftp
        self._last_used = now
        return ftp

    def invalidate(self, path: str | None = None) -> None:
        with self._lock:
            if path is None:
                self._list_cache.clear()
                return
            target = ftp_norm_path(path)
            parent = ftp_parent(target)
            self._list_cache.pop(target, None)
            self._list_cache.pop(parent, None)

    def warm(self) -> dict:
        t0 = time.perf_counter()
        with self._lock:
            self._ensure()
            data = self.list("/disk1", use_cache=False)
        return {
            "ok": True,
            "host": FTP_HOST,
            "warmed_ms": round((time.perf_counter() - t0) * 1000),
            "path": data.get("path"),
            "entries": len(data.get("entries") or []),
        }

    def status(self) -> dict:
        try:
            with self._lock:
                ftp = self._ensure()
                pwd = ftp.pwd()
                welcome = (ftp.getwelcome() or "").strip()
            return {
                "ok": True,
                "host": FTP_HOST,
                "port": FTP_PORT,
                "user": FTP_USER,
                "pwd": pwd,
                "welcome": welcome[:120],
                "pooled": True,
            }
        except Exception as exc:
            with self._lock:
                self._drop()
            return {
                "ok": False,
                "host": FTP_HOST,
                "port": FTP_PORT,
                "user": FTP_USER,
                "error": str(exc),
            }

    def list(self, path: str, *, use_cache: bool = True) -> dict:
        target = ftp_norm_path(path)
        now = time.time()
        if use_cache:
            hit = self._list_cache.get(target)
            if hit and now - hit[0] <= FTP_LIST_CACHE_TTL:
                cached = dict(hit[1])
                cached["cached"] = True
                return cached

        with self._lock:
            if use_cache:
                hit = self._list_cache.get(target)
                if hit and time.time() - hit[0] <= FTP_LIST_CACHE_TTL:
                    cached = dict(hit[1])
                    cached["cached"] = True
                    return cached
            ftp = self._ensure()
            try:
                payload = self._list_unlocked(ftp, target)
            except Exception:
                self._drop()
                ftp = self._ensure()
                payload = self._list_unlocked(ftp, target)
            self._last_used = time.time()
            self._list_cache[target] = (self._last_used, payload)
            out = dict(payload)
            out["cached"] = False
            return out

    def _list_unlocked(self, ftp: ftplib.FTP, target: str) -> dict:
        entries: list[dict] = []
        ftp.cwd(target)
        try:
            for name, facts in ftp.mlsd():
                if name in (".", ".."):
                    continue
                typ = (facts.get("type") or "").lower()
                is_dir = typ in ("dir", "cdir", "pdir")
                size = int(facts.get("size") or 0) if not is_dir else 0
                modified = facts.get("modify") or ""
                entries.append(
                    {
                        "name": name,
                        "path": ftp_norm_path(target.rstrip("/") + "/" + name),
                        "type": "dir" if is_dir else "file",
                        "size": size,
                        "modified": modified,
                    }
                )
        except Exception:
            names = []
            try:
                names = ftp.nlst()
            except Exception:
                names = []
            for name in names:
                base = name.rsplit("/", 1)[-1]
                if base in (".", ".."):
                    continue
                full = ftp_norm_path(target.rstrip("/") + "/" + base)
                is_dir = False
                size = 0
                modified = ""
                try:
                    ftp.cwd(full)
                    is_dir = True
                    ftp.cwd(target)
                except Exception:
                    try:
                        size = int(ftp.size(full) or 0)
                    except Exception:
                        size = 0
                    try:
                        modified = ftp.voidcmd(f"MDTM {full}")[4:].strip()
                    except Exception:
                        modified = ""
                entries.append(
                    {
                        "name": base,
                        "path": full,
                        "type": "dir" if is_dir else "file",
                        "size": size,
                        "modified": modified,
                    }
                )
        entries.sort(key=lambda e: (0 if e["type"] == "dir" else 1, e["name"].lower()))
        crumbs = []
        acc = ""
        for part in target.strip("/").split("/"):
            if not part:
                continue
            acc += "/" + part
            crumbs.append({"name": part, "path": acc})
        return {
            "ok": True,
            "path": target,
            "parent": ftp_parent(target),
            "crumbs": crumbs,
            "entries": entries,
        }

    def mkdir(self, path: str) -> dict:
        target = ftp_norm_path(path)
        if target == "/":
            raise ValueError("cannot create root")
        with self._lock:
            ftp = self._ensure()
            try:
                ftp.mkd(target)
            except Exception:
                self._drop()
                ftp = self._ensure()
                ftp.mkd(target)
            self._last_used = time.time()
            self.invalidate(target)
        return {"ok": True, "path": target}

    def delete(self, path: str) -> dict:
        target = ftp_norm_path(path)
        if target == "/":
            raise ValueError("cannot delete root")

        def _rm_tree(ftp: ftplib.FTP, p: str) -> None:
            try:
                ftp.cwd(p)
                kids = []
                try:
                    for name, facts in ftp.mlsd():
                        if name in (".", ".."):
                            continue
                        typ = (facts.get("type") or "").lower()
                        kids.append((name, typ in ("dir", "cdir", "pdir")))
                except Exception:
                    for name in ftp.nlst():
                        base = name.rsplit("/", 1)[-1]
                        if base in (".", ".."):
                            continue
                        full = p.rstrip("/") + "/" + base
                        is_dir = False
                        cur = ftp.pwd()
                        try:
                            ftp.cwd(full)
                            is_dir = True
                            ftp.cwd(cur)
                        except Exception:
                            is_dir = False
                        kids.append((base, is_dir))
                for name, is_dir in kids:
                    full = ftp_norm_path(p.rstrip("/") + "/" + name)
                    if is_dir:
                        _rm_tree(ftp, full)
                    else:
                        ftp.delete(full)
                ftp.cwd(ftp_parent(p))
                ftp.rmd(p)
            except ftplib.error_perm:
                ftp.delete(p)

        with self._lock:
            ftp = self._ensure()
            try:
                _rm_tree(ftp, target)
            except Exception:
                self._drop()
                ftp = self._ensure()
                _rm_tree(ftp, target)
            self._last_used = time.time()
            self.invalidate(target)
        return {"ok": True, "path": target}

    def rename(self, src: str, dst: str) -> dict:
        a = ftp_norm_path(src)
        b = ftp_norm_path(dst)
        if a == "/" or b == "/":
            raise ValueError("invalid rename path")
        with self._lock:
            ftp = self._ensure()
            try:
                ftp.rename(a, b)
            except Exception:
                self._drop()
                ftp = self._ensure()
                ftp.rename(a, b)
            self._last_used = time.time()
            self.invalidate(a)
            self.invalidate(b)
        return {"ok": True, "path": b, "from": a}

    def upload_bytes(self, path: str, data: bytes) -> dict:
        """Dedicated connection so long uploads do not block list pool."""
        target = ftp_norm_path(path)
        if target == "/" or target.endswith("/"):
            raise ValueError("upload path must be a file path")
        parent = ftp_parent(target)
        ftp = ftp_connect()
        try:
            if parent != "/":
                try:
                    ftp.cwd(parent)
                except Exception:
                    acc = ""
                    for part in parent.strip("/").split("/"):
                        acc += "/" + part
                        try:
                            ftp.mkd(acc)
                        except Exception:
                            pass
                    ftp.cwd(parent)
            bio = io.BytesIO(data)
            ftp.storbinary(f"STOR {target}", bio)
        finally:
            try:
                ftp.quit()
            except Exception:
                try:
                    ftp.close()
                except Exception:
                    pass
        self.invalidate(target)
        return {"ok": True, "path": target, "size": len(data)}

    def download_to(self, path: str, write) -> tuple[str, str, int | None]:
        """Dedicated connection so media open does not stall browsing."""
        target = ftp_norm_path(path)
        if target == "/":
            raise ValueError("not a file")
        name = target.rsplit("/", 1)[-1] or "download"
        ctype = ftp_guess_mime(name)
        ftp = ftp_connect()
        size = None
        try:
            try:
                size = ftp.size(target)
            except Exception:
                size = None
            ftp.retrbinary(f"RETR {target}", write)
        finally:
            try:
                ftp.quit()
            except Exception:
                try:
                    ftp.close()
                except Exception:
                    pass
        return name, ctype, size


_FTP = _FtpPool()


def ftp_connect() -> "ftplib.FTP":
    # Legacy helper — prefer _FTP pool methods.
    if not FTP_PASS:
        raise RuntimeError("FTP_PASS / FTP_PASS_B64 / BUFFALO_PASS not configured")
    ftp = ftplib.FTP()
    ftp.connect(FTP_HOST, FTP_PORT, timeout=FTP_TIMEOUT)
    ftp.login(FTP_USER, FTP_PASS)
    ftp.set_pasv(True)
    return ftp


def ftp_status() -> dict:
    return _FTP.status()


def ftp_warm() -> dict:
    return _FTP.warm()


def ftp_list(path: str) -> dict:
    return _FTP.list(path)


def ftp_mkdir(path: str) -> dict:
    return _FTP.mkdir(path)


def ftp_delete(path: str) -> dict:
    return _FTP.delete(path)


def ftp_rename(src: str, dst: str) -> dict:
    return _FTP.rename(src, dst)


def ftp_upload_bytes(path: str, data: bytes) -> dict:
    return _FTP.upload_bytes(path, data)


def ftp_download_bytes(path: str) -> tuple[str, bytes]:
    buf = io.BytesIO()
    name, _ctype, _size = _FTP.download_to(path, buf.write)
    return name, buf.getvalue()


DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)

LINE_RE = re.compile(
    r"^(?P<pub>\d+)\s+(?P<proto>tcp|udp|TCP|UDP)\s+"
    r"(?P<dest_ip>\S+)\s+(?P<dest_port>\d+)\s+(?P<name>\S+)\s*$"
)
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
NAME_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,40}$")
UCI_OPT_RE = re.compile(r"^\s*option\s+(\w+)\s+'([^']*)'\s*$")

_apply_lock = threading.Lock()


def require_auth_configured() -> None:
    if not AUTH_PASS:
        raise SystemExit("PF_PASS env var is required")
    if not ROUTER_PASS:
        raise SystemExit("ROUTER_PASS env var is required")


def parse_conf(text: str) -> dict:
    comments: list[str] = []
    rules: list[dict] = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            comments.append(stripped)
            continue
        m = LINE_RE.match(stripped)
        if not m:
            raise ValueError(f"Invalid forward line: {stripped}")
        rules.append(
            {
                "pub": int(m.group("pub")),
                "proto": m.group("proto").lower(),
                "dest_ip": m.group("dest_ip"),
                "dest_port": int(m.group("dest_port")),
                "name": m.group("name"),
                "external": False,
            }
        )
    return {"comments": comments, "rules": rules}


def validate_vps_rules(rules: list[dict]) -> list[dict]:
    if not isinstance(rules, list):
        raise ValueError("vps rules must be a list")
    cleaned: list[dict] = []
    seen: set[tuple[str, int]] = set()
    # 8443/tcp is OpenVPN (sslh multiplex / direct) — never DNAT it to Flint HTTPS.
    reserved = {22, 25, 80, 443, 465, 587, 993, 5000, 5001, 5002, 8443, NAS_FTP_PUBLIC_PORT}
    protected_pubs = {8080, NAS_SMB_FORWARD_PUB}
    for i, rule in enumerate(rules):
        try:
            pub = int(rule["pub"])
            dest_port = int(rule["dest_port"])
            proto = str(rule["proto"]).lower().strip()
            dest_ip = str(rule["dest_ip"]).strip()
            name = str(rule["name"]).strip()
            external = bool(rule.get("external", False))
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"VPS rule {i + 1}: missing/invalid fields") from exc
        if proto not in ("tcp", "udp"):
            raise ValueError(f"VPS rule {i + 1}: proto must be tcp or udp")
        if not (1 <= pub <= 65535 and 1 <= dest_port <= 65535):
            raise ValueError(f"VPS rule {i + 1}: ports must be 1-65535")
        if pub in reserved and not external:
            raise ValueError(f"VPS rule {i + 1}: public port {pub} is reserved")
        if not IP_RE.match(dest_ip):
            raise ValueError(f"VPS rule {i + 1}: invalid dest_ip")
        if not NAME_RE.match(name):
            raise ValueError(f"VPS rule {i + 1}: invalid name")
        # Keep protected admin HTTP / NAS SMB public ports immutable
        if pub in protected_pubs and not external:
            expected = {
                8080: ("tcp", "192.168.8.1", 80, "flint-http"),
                NAS_SMB_FORWARD_PUB: ("tcp", NAS_SMB_HOST, 445, "nas-smb"),
            }[pub]
            proto, dest_ip, dest_port, name = expected
        key = (proto, pub)
        if key in seen:
            raise ValueError(f"VPS rule {i + 1}: duplicate {proto}/{pub}")
        seen.add(key)
        cleaned.append(
            {
                "pub": pub,
                "proto": proto,
                "dest_ip": dest_ip,
                "dest_port": dest_port,
                "name": name,
                "external": external,
            }
        )
    return cleaned


def serialize_vps_conf(comments: list[str], rules: list[dict]) -> str:
    lines = comments or [
        "# Do NOT forward 80/443 — Caddy uses them on this VPS",
        "# Edited by port-forward UI",
    ]
    out = "\n".join(lines).rstrip() + "\n"
    for r in rules:
        if r.get("external"):
            continue
        out += (
            f"{r['pub']:<5} {r['proto']:<3} {r['dest_ip']:<15} "
            f"{r['dest_port']:<5} {r['name']}\n"
        )
    return out


def parse_live_dnat() -> list[dict]:
    """Import current iptables DNAT PREROUTING rules into the VPS list."""
    proc = subprocess.run(
        ["iptables", "-t", "nat", "-S", "PREROUTING"],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    if proc.returncode != 0:
        return []
    dnat_re = re.compile(
        r"-A PREROUTING .*?-p (?P<proto>tcp|udp).*?--dport (?P<pub>\d+).*?"
        r"--to-destination (?P<dest_ip>[^:]+):(?P<dest_port>\d+)"
    )
    rules: list[dict] = []
    seen: set[tuple[str, int]] = set()
    for line in (proc.stdout or "").splitlines():
        if "DNAT" not in line:
            continue
        m = dnat_re.search(line)
        if not m:
            continue
        pub = int(m.group("pub"))
        proto = m.group("proto")
        key = (proto, pub)
        if key in seen:
            continue
        seen.add(key)
        rules.append(
            {
                "pub": pub,
                "proto": proto,
                "dest_ip": m.group("dest_ip"),
                "dest_port": int(m.group("dest_port")),
                "name": f"dnat-{pub}",
                "external": True,
            }
        )
    return rules


def parse_ufw_gl_forwards() -> list[dict]:
    """Import UFW 'GL forward*' allows that may not have DNAT yet."""
    proc = _run_ufw(["status"])
    if proc.returncode != 0:
        return []
    row_re = re.compile(
        r"^(?P<port>\d+)(?:/(?P<proto>tcp|udp))?\s+ALLOW\s+Anywhere.*?#\s*(?P<comment>.+)$",
        re.I,
    )
    rules: list[dict] = []
    seen: set[tuple[str, int]] = set()
    for line in (proc.stdout or "").splitlines():
        if "GL forward" not in line and "RDP via GL" not in line:
            continue
        m = row_re.match(line.strip())
        if not m:
            continue
        pub = int(m.group("port"))
        proto = (m.group("proto") or "tcp").lower()
        key = (proto, pub)
        if key in seen:
            continue
        seen.add(key)
        comment = m.group("comment").strip().replace(" ", "-")[:40]
        rules.append(
            {
                "pub": pub,
                "proto": proto,
                "dest_ip": "0.0.0.0",
                "dest_port": pub,
                "name": comment or f"ufw-{pub}",
                "external": True,
                "ufw_only": True,
            }
        )
    return rules


def merge_vps_lists(managed: list[dict], existing: list[dict]) -> list[dict]:
    by_key: dict[tuple[str, int], dict] = {}
    for r in existing:
        by_key[(r["proto"], int(r["pub"]))] = dict(r)
    for r in managed:
        key = (r["proto"], int(r["pub"]))
        prev = by_key.get(key, {})
        by_key[key] = {**prev, **r, "external": False}
        by_key[key].pop("ufw_only", None)
    ordered: list[dict] = []
    seen: set[tuple[str, int]] = set()
    for r in existing + managed:
        key = (r["proto"], int(r["pub"]))
        if key in seen:
            continue
        ordered.append(by_key[key])
        seen.add(key)
    return ordered


def _extract_ipv4(value) -> str:
    """Accept bare IPv4 or labels like 'PC — 192.168.8.10'."""
    text = str(value or "").strip()
    if not text:
        return ""
    if IP_RE.match(text):
        return text
    m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", text)
    return m.group(1) if m and IP_RE.match(m.group(1)) else ""


def validate_router(dmz_ip: str, rules: list[dict]) -> tuple[str, list[dict]]:
    dmz_ip = _extract_ipv4(dmz_ip) or str(dmz_ip or "").strip()
    if not IP_RE.match(dmz_ip):
        raise ValueError("Router DMZ IP is invalid — pick a LAN device or type an IPv4")
    if not isinstance(rules, list):
        raise ValueError("router rules must be a list")
    cleaned: list[dict] = []
    for i, rule in enumerate(rules):
        try:
            enabled = bool(rule.get("enabled", True))
            proto = str(rule.get("proto", "tcp")).lower().strip()
            src = str(rule.get("src", "wgclient1")).strip()
            src_dport = str(rule.get("src_dport", "")).strip()
            dest_ip = _extract_ipv4(rule.get("dest_ip"))
            dest_port = str(rule.get("dest_port", "")).strip()
            name = str(rule.get("name", f"rule{i+1}")).strip() or f"rule{i+1}"
            external = bool(rule.get("external", False))
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"Router rule {i + 1}: missing/invalid fields") from exc
        if name == "GL-DMZ" or external:
            # DMZ / foreign rows are not rewritten from this form
            continue
        # Skip blank draft rows from the UI
        if not dest_ip and not src_dport and not dest_port and name in ("", "rule", f"rule{i+1}", "new-rule"):
            continue
        if src not in ("wan", "wgclient1", "lan"):
            raise ValueError(f"Router rule {i + 1} ({name}): src must be wan or wgclient1")
        if proto not in ("tcp", "udp", "tcp udp", "all"):
            raise ValueError(f"Router rule {i + 1} ({name}): invalid proto")
        if not dest_ip:
            raise ValueError(
                f"Router rule {i + 1} ({name}): choose a LAN IP for Target "
                "(open LAN device and pick a computer, or type 192.168.8.x)"
            )
        if not NAME_RE.match(name):
            raise ValueError(f"Router rule {i + 1} ({name}): invalid name")
        if proto != "all":
            if not src_dport.isdigit() or not (1 <= int(src_dport) <= 65535):
                raise ValueError(f"Router rule {i + 1} ({name}): invalid listen port")
            if not dest_port.isdigit() or not (1 <= int(dest_port) <= 65535):
                raise ValueError(f"Router rule {i + 1} ({name}): invalid LAN port")
        cleaned.append(
            {
                "enabled": enabled,
                "proto": proto,
                "src": src,
                "src_dport": src_dport,
                "dest_ip": dest_ip,
                "dest_port": dest_port,
                "name": name,
                "external": external,
            }
        )
    return dmz_ip, cleaned


def serialize_router_conf(dmz_ip: str, rules: list[dict]) -> str:
    lines = [
        "config redirect",
        "\toption enabled '1'",
        "\toption src 'wan'",
        "\toption name 'GL-DMZ'",
        "\toption dest 'lan'",
        f"\toption dest_ip '{dmz_ip}'",
        "\toption proto 'all'",
        "",
    ]
    for r in rules:
        if r.get("external"):
            continue
        enabled = "1" if r.get("enabled", True) else "0"
        lines.extend(
            [
                "config redirect",
                f"\toption enabled '{enabled}'",
                f"\toption proto '{r['proto']}'",
                f"\toption src '{r['src']}'",
                f"\toption name '{r['name']}'",
                "\toption dest 'lan'",
                f"\toption dest_ip '{r['dest_ip']}'",
            ]
        )
        if r["proto"] != "all":
            lines.append(f"\toption src_dport '{r['src_dport']}'")
            lines.append(f"\toption dest_port '{r['dest_port']}'")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def parse_router_conf(text: str) -> dict:
    """Parse UCI redirects only (ignore firewall zones/rules/etc)."""
    blocks: list[dict] = []
    current: dict | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("config "):
            if current is not None:
                blocks.append(current)
            # Keep type so we can ignore non-redirect sections.
            parts = line.split(None, 2)
            cfg_type = parts[1] if len(parts) > 1 else ""
            current = {"__type": cfg_type}
            continue
        m = UCI_OPT_RE.match(raw)
        if m and current is not None:
            current[m.group(1)] = m.group(2)
    if current is not None:
        blocks.append(current)

    dmz_ip = "192.168.8.243"
    rules: list[dict] = []
    for b in blocks:
        if b.get("__type") and b.get("__type") != "redirect":
            continue
        name = b.get("name", "")
        if name == "GL-DMZ" or (
            b.get("src") == "wan" and b.get("proto") == "all" and "src_dport" not in b
        ):
            dmz_ip = b.get("dest_ip", dmz_ip) or dmz_ip
            rules.append(
                {
                    "enabled": b.get("enabled", "1") != "0",
                    "proto": "all",
                    "src": "wan",
                    "src_dport": "",
                    "dest_ip": dmz_ip,
                    "dest_port": "",
                    "name": "GL-DMZ",
                    "external": True,
                }
            )
            continue
        rules.append(
            {
                "enabled": b.get("enabled", "1") != "0",
                "proto": b.get("proto", "tcp"),
                "src": b.get("src", "wgclient1"),
                "src_dport": b.get("src_dport", ""),
                "dest_ip": b.get("dest_ip", ""),
                "dest_port": b.get("dest_port", ""),
                "name": name or "rule",
                "external": False,
            }
        )
    return {"dmz_ip": dmz_ip, "rules": rules}


def _router_host_in_use() -> str:
    return globals().get("_active_router_host") or ROUTER_HOSTS[0]


WG_EASY_CONTAINER = os.environ.get("WG_EASY_CONTAINER", "wg-easy").strip()
ROUTER_SSH_VIA = os.environ.get("ROUTER_SSH_VIA", "auto").strip().lower()


def _wg_easy_pid() -> str | None:
    if not WG_EASY_CONTAINER:
        return None
    proc = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Pid}}", WG_EASY_CONTAINER],
        capture_output=True,
        text=True,
        timeout=8,
        check=False,
    )
    if proc.returncode != 0:
        return None
    pid = (proc.stdout or "").strip()
    return pid if pid.isdigit() and pid != "0" else None


def _router_ssh_reachable(err: str) -> bool:
    err = err.lower()
    markers = (
        "connection timed out",
        "connection refused",
        "no route",
        "network is unreachable",
        "operation timed out",
    )
    return any(m in err for m in markers)


def _router_ssh_cmd(
    host: str,
    remote_cmd: str,
    connect_timeout: int,
    *,
    netns_pid: str | None = None,
) -> list[str]:
    ssh_cmd = [
        "sshpass",
        "-e",
        "ssh",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        f"UserKnownHostsFile={ROUTER_KNOWN_HOSTS}",
        "-o",
        "PreferredAuthentications=password",
        "-o",
        "PubkeyAuthentication=no",
        "-o",
        f"ConnectTimeout={connect_timeout}",
        f"{ROUTER_USER}@{host}",
        remote_cmd,
    ]
    if netns_pid:
        return ["nsenter", "-t", netns_pid, "-n", *ssh_cmd]
    return ssh_cmd


def router_ssh(
    remote_cmd: str,
    input_text: str | None = None,
    timeout: int = 45,
) -> subprocess.CompletedProcess:
    """Run a command on the Flint router via sshpass (tries ROUTER_HOSTS in order)."""
    global _active_router_host
    ROUTER_KNOWN_HOSTS.parent.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["SSHPASS"] = ROUTER_PASS
    hosts = _router_hosts_for_ssh()
    per_host = max(3, min(6, timeout // max(1, len(hosts))))
    last: subprocess.CompletedProcess | None = None
    netns_pid = _wg_easy_pid()
    if ROUTER_SSH_VIA == "host":
        paths: list[tuple[str, str | None]] = [("host", None)]
    elif ROUTER_SSH_VIA in {"netns", "wg-easy"}:
        paths = [("wg-easy", netns_pid)]
    else:
        paths = [("host", None), ("wg-easy", netns_pid)]

    for path_name, pid in paths:
        if path_name == "wg-easy" and not pid:
            continue
        for host in hosts:
            cmd = _router_ssh_cmd(
                host,
                remote_cmd,
                per_host,
                netns_pid=pid if path_name == "wg-easy" else None,
            )
            last = subprocess.run(
                cmd,
                input=input_text,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env=env,
            )
            if last.returncode == 0:
                _active_router_host = host
                return last
            err = (last.stderr or last.stdout or "").strip()
            if _router_ssh_reachable(err):
                continue
            _active_router_host = host
            detail = f"[{path_name}] {err}".strip()
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=last.returncode,
                stdout=last.stdout,
                stderr=detail,
            )
    if last:
        prefix = "router:"
        err = (last.stderr or last.stdout or "router ssh failed").strip()
        if not err.lower().startswith(prefix):
            err = f"{prefix} {err}"
        if _ovpn_flint_connected() and "timed out" in err.lower():
            err += (
                " — OpenVPN is up but Flint is blocking SSH from the tunnel. "
                "On Flint Wi‑Fi open 192.168.8.1 → Terminal and run: "
                "sh /tmp/flint-allow-vpn-ssh.sh "
                "(download from Portal → Settings → OpenVPN)"
            )
        return subprocess.CompletedProcess(
            args=last.args,
            returncode=last.returncode,
            stdout=last.stdout,
            stderr=err,
        )
    return subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="router ssh failed")


_active_router_host = ROUTER_HOSTS[0]


WANBOND_PORT = int(os.environ.get("WANBOND_PORT", "8443"))
WANBOND_PORTS = os.environ.get("WANBOND_PORTS", "8443,51820,4410")
WANBOND_SCRIPT = Path(
    os.environ.get("WANBOND_SCRIPT", "/opt/wireguard/scripts/wanbond.py")
)
WANBOND_KEY_FILE = Path(os.environ.get("WANBOND_KEY_FILE", "/opt/wireguard/wanbond.key"))
WANBOND_STATUS = Path("/tmp/wanbond-status.json")
_bond_lock = threading.Lock()

UNKILL_SH = r"""#!/bin/sh
# Undo leftover Tunnel 1 / DNS-leak firewall. Does not change WireGuard.
iptables -t mangle -D ROUTE_POLICY -m addrtype ! --dst-type LOCAL -j TUNNEL7267_ROUTE_POLICY 2>/dev/null || true
iptables -t mangle -F TUNNEL7267_ROUTE_POLICY 2>/dev/null || true
ip rule del prio 9920 2>/dev/null || true
ip rule del prio 9910 2>/dev/null || true
ip rule del prio 800 2>/dev/null || true
iptables -D zone_lan_input -p udp -m udp --dport 53 -m mark ! --mark 0x8000/0xf000 -m comment --comment "!fw3: lan_drop_leaked_dns" -j DROP 2>/dev/null || true
iptables -D zone_lan_input -p udp -m udp --dport 3053 -m mark --mark 0x0/0xf000 -m comment --comment "!fw3: lan_drop_leaked_adgdns" -j DROP 2>/dev/null || true
iptables -D zone_guest_input -p udp -m udp --dport 53 -m mark ! --mark 0x8000/0xf000 -m comment --comment "!fw3: guest_drop_leaked_dns" -j DROP 2>/dev/null || true
iptables -D zone_guest_input -p udp -m udp --dport 3053 -m mark --mark 0x0/0xf000 -m comment --comment "!fw3: guest_drop_leaked_adgdns" -j DROP 2>/dev/null || true
iptables -D OUTPUT -p tcp -m mark --mark 0x0/0xf000 -m owner --uid-owner 453 -m comment --comment "!fw3: tcp_dns_leak_drop" -j DROP 2>/dev/null || true
uci set firewall.lan_drop_leaked_dns.enabled='0' 2>/dev/null || true
uci set firewall.lan_drop_leaked_adgdns.enabled='0' 2>/dev/null || true
uci set firewall.guest_drop_leaked_dns.enabled='0' 2>/dev/null || true
uci set firewall.guest_drop_leaked_adgdns.enabled='0' 2>/dev/null || true
uci set firewall.tcp_dns_leak_drop.enabled='0' 2>/dev/null || true
uci commit firewall 2>/dev/null || true
"""


def _wanbond_script() -> Path:
    if WANBOND_SCRIPT.is_file():
        return WANBOND_SCRIPT
    alt = Path(__file__).resolve().parent.parent / "scripts" / "wanbond.py"
    if alt.is_file():
        return alt
    return WANBOND_SCRIPT


def wanbond_key() -> str:
    env_key = os.environ.get("WANBOND_KEY", "").strip()
    if env_key:
        return env_key
    WANBOND_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    if WANBOND_KEY_FILE.is_file():
        return WANBOND_KEY_FILE.read_text(encoding="utf-8").strip()
    key = secrets.token_hex(24)
    WANBOND_KEY_FILE.write_text(key + "\n", encoding="utf-8")
    try:
        os.chmod(WANBOND_KEY_FILE, 0o600)
    except OSError:
        pass
    return key


def _read_status_file(path: Path) -> dict:
    try:
        if path.is_file():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def read_bond_state() -> dict:
    return {
        "ok": True,
        "installed": False,
        "enabled": False,
        "removed": True,
        "message": "WAN bonding has been removed",
        "vps_active": False,
        "router_active": False,
        "port": None,
        "ports": [],
        "status": {},
        "wan_links": [],
    }

def _write_wanbond_unit() -> None:
    script = _wanbond_script()
    unit = f"""[Unit]
Description=ServerManager WAN bond server
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 {script} server --key {wanbond_key()} --port {WANBOND_PORT} --ports {WANBOND_PORTS} --mode speed --egress vps
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
"""
    Path("/etc/systemd/system/wanbond.service").write_text(unit, encoding="utf-8")
    subprocess.run(["systemctl", "daemon-reload"], capture_output=True)


def install_bond() -> dict:
    return {"ok": False, "error": "WAN bonding has been removed", **read_bond_state()}

def apply_bond_action(payload: dict) -> dict:
    return {"ok": False, "error": "WAN bonding has been removed", **read_bond_state()}

def _json_from_cli(text: str):
    raw = (text or "").strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    for start_ch, end_ch in (("{", "}"), ("[", "]")):
        start = raw.find(start_ch)
        end = raw.rfind(end_ch)
        if start >= 0 and end > start:
            try:
                return json.loads(raw[start : end + 1])
            except json.JSONDecodeError:
                continue
    return None


LEASE_LINE_RE = re.compile(
    r"^\d+\s+"
    r"(?P<mac>(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<hostname>\S+)"
)
ARP_LINE_RE = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+"
    r"(?P<mac>(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\s+"
)
NEIGH_LINE_RE = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+dev\s+\S+\s+lladdr\s+"
    r"(?P<mac>(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})"
)


def parse_lan_devices(text: str) -> list[dict]:
    """Parse Flint DHCP leases + ARP/neigh into a UI-friendly device list."""
    by_ip: dict[str, dict] = {}

    def upsert(ip: str, *, mac: str = "", hostname: str = "", source: str = "") -> None:
        if not IP_RE.match(ip):
            return
        # Skip broadcast / weird
        if ip.endswith(".255") or ip.endswith(".0"):
            return
        cur = by_ip.get(ip)
        if not cur:
            by_ip[ip] = {
                "ip": ip,
                "mac": (mac or "").lower(),
                "hostname": "" if hostname in ("*", "-", "") else hostname,
                "source": source,
            }
            return
        if mac and not cur.get("mac"):
            cur["mac"] = mac.lower()
        if hostname and hostname not in ("*", "-", "") and not cur.get("hostname"):
            cur["hostname"] = hostname
        if source and source not in (cur.get("source") or ""):
            cur["source"] = f"{cur.get('source')}+{source}" if cur.get("source") else source

    section = "leases"
    for raw in text.splitlines():
        line = raw.strip()
        if line == "---LEASES---":
            section = "leases"
            continue
        if line == "---NEIGH---":
            section = "neigh"
            continue
        if section == "leases":
            m = LEASE_LINE_RE.match(line)
            if m:
                upsert(
                    m.group("ip"),
                    mac=m.group("mac"),
                    hostname=m.group("hostname"),
                    source="dhcp",
                )
            continue
        m = NEIGH_LINE_RE.match(line) or ARP_LINE_RE.match(line)
        if m:
            upsert(m.group("ip"), mac=m.group("mac"), source="arp")

    devices = list(by_ip.values())
    devices.sort(
        key=lambda d: (
            0 if str(d.get("hostname") or "").upper().startswith("WIN-") else 1,
            [int(x) for x in d["ip"].split(".")],
            str(d.get("hostname") or "").lower(),
        )
    )
    return devices


LAN_ALIASES_PATH = Path(__file__).resolve().parent / "lan_aliases.json"

_BUILTIN_LAN_NAMES = {
    "192.168.8.1": "GL.iNet Flint",
    "192.168.8.243": "DMZ host",
}


def load_lan_aliases() -> dict[str, str]:
    try:
        data = json.loads(LAN_ALIASES_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in data.items():
        key = str(k or "").strip().lower()
        name = str(v or "").strip()
        if key and name:
            out[key] = name
    return out


def save_lan_aliases(aliases: dict[str, str]) -> dict[str, str]:
    cleaned: dict[str, str] = {}
    for k, v in (aliases or {}).items():
        key = str(k or "").strip().lower()
        name = str(v or "").strip()
        if not key or not name:
            continue
        if not (IP_RE.match(key) or re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", key)):
            continue
        cleaned[key] = name[:64]
    LAN_ALIASES_PATH.write_text(
        json.dumps(cleaned, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return cleaned


def _parse_gl_clients_json(text: str) -> dict[str, dict]:
    text = (text or "").strip()
    if not text:
        return {}
    try:
        payload = json.loads(text)
    except Exception:
        return {}
    clients = payload.get("clients") if isinstance(payload, dict) else None
    if not isinstance(clients, dict):
        return {}
    by_ip: dict[str, dict] = {}
    for mac, info in clients.items():
        if not isinstance(info, dict):
            continue
        ip = str(info.get("ip") or "").strip()
        if not IP_RE.match(ip):
            continue
        name = str(info.get("name") or "").strip()
        mac_s = str(info.get("mac") or mac or "").strip().lower()
        online = info.get("online")
        if online is None:
            online = info.get("is_online")
        if online is None:
            # Some firmwares use class/status strings.
            status = str(info.get("status") or info.get("class") or "").lower()
            if status in ("online", "up", "active", "connected"):
                online = True
            elif status in ("offline", "down", "inactive", "disconnected"):
                online = False
        by_ip[ip] = {"hostname": name, "mac": mac_s, "online": online}
    return by_ip


def _apply_lan_names(devices: list[dict]) -> list[dict]:
    aliases = load_lan_aliases()
    preferred = [d for d in devices if str(d.get("ip") or "").startswith("192.168.8.")]
    use = preferred or list(devices)
    for d in use:
        ip = str(d.get("ip") or "")
        mac = str(d.get("mac") or "").lower()
        alias = aliases.get(ip.lower()) or (aliases.get(mac) if mac else None)
        builtin = _BUILTIN_LAN_NAMES.get(ip)
        host = str(d.get("hostname") or "").strip()
        if alias:
            d["hostname"] = alias
            d["named_by"] = "alias"
        elif host:
            d["named_by"] = d.get("named_by") or "lease"
        elif builtin:
            d["hostname"] = builtin
            d["named_by"] = "builtin"
        elif mac and re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
            d["hostname"] = f"Device {mac[-5:].replace(':', '').upper()}"
            d["named_by"] = "mac"
    use.sort(
        key=lambda d: (
            0 if str(d.get("hostname") or "").upper().startswith("WIN-") else 1,
            0 if d.get("named_by") in ("alias", "lease", "gl", "builtin") else 1,
            [int(x) for x in str(d["ip"]).split(".")],
            str(d.get("hostname") or "").lower(),
        )
    )
    return use


def read_lan_devices() -> dict:
    """Return GL.iNet LAN clients with names from DHCP, gl-clients, and aliases."""
    if not ROUTER_PASS:
        return {
            "ok": False,
            "error": "Router password not configured",
            "host": ROUTER_HOST,
            "devices": [],
            "aliases": load_lan_aliases(),
        }
    proc = router_ssh(
        "echo '---LEASES---'; "
        "(cat /tmp/dhcp.leases 2>/dev/null || cat /var/dhcp.leases 2>/dev/null || true); "
        "echo '---NEIGH---'; "
        "(ip -4 neigh show 2>/dev/null || cat /proc/net/arp 2>/dev/null || true); "
        "echo '---GLCLIENTS---'; "
        "(ubus call gl-clients list 2>/dev/null || true)",
        timeout=18,
    )
    if proc.returncode != 0:
        return {
            "ok": False,
            "error": (proc.stderr or proc.stdout or "router ssh failed").strip()[-500:],
            "host": ROUTER_HOST,
            "devices": [],
            "aliases": load_lan_aliases(),
        }
    raw = proc.stdout or ""
    lease_part = raw
    gl_part = ""
    if "---GLCLIENTS---" in raw:
        lease_part, gl_part = raw.split("---GLCLIENTS---", 1)
    devices = parse_lan_devices(lease_part)
    by_ip = {d["ip"]: d for d in devices}
    for ip, info in _parse_gl_clients_json(gl_part).items():
        cur = by_ip.get(ip)
        name = str(info.get("hostname") or "").strip()
        mac = str(info.get("mac") or "").strip().lower()
        online_gl = info.get("online")
        if not cur:
            by_ip[ip] = {
                "ip": ip,
                "mac": mac,
                "hostname": name,
                "source": "gl",
                "named_by": "gl" if name else "",
                "online": bool(online_gl) if online_gl is not None else False,
            }
            continue
        if mac and not cur.get("mac"):
            cur["mac"] = mac
        if name and not cur.get("hostname"):
            cur["hostname"] = name
            cur["named_by"] = "gl"
        src = str(cur.get("source") or "")
        if "gl" not in src:
            cur["source"] = f"{src}+gl" if src else "gl"
        if online_gl is not None:
            cur["online"] = bool(online_gl) or bool(cur.get("online"))
    # ARP/neigh presence means currently plugged in / reachable on LAN.
    for d in by_ip.values():
        src_parts = {p for p in str(d.get("source") or "").split("+") if p}
        arp_live = "arp" in src_parts
        if d.get("online") is None:
            d["online"] = arp_live
        elif arp_live:
            d["online"] = True
    devices = _apply_lan_names(list(by_ip.values()))
    return {
        "ok": True,
        "host": ROUTER_HOST,
        "count": len(devices),
        "devices": devices,
        "aliases": load_lan_aliases(),
    }


def set_lan_alias(ip: str = "", mac: str = "", name: str = "") -> dict:
    """Create/update/delete a custom LAN display name."""
    ip = str(ip or "").strip()
    mac = str(mac or "").strip().lower()
    name = str(name or "").strip()
    aliases = load_lan_aliases()
    if ip and not IP_RE.match(ip):
        raise ValueError("invalid ip")
    if mac and not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
        raise ValueError("invalid mac")
    if not ip and not mac:
        raise ValueError("ip or mac required")
    if not name:
        if ip:
            aliases.pop(ip.lower(), None)
        if mac:
            aliases.pop(mac, None)
    else:
        if ip:
            aliases[ip.lower()] = name
        if mac:
            aliases[mac] = name
        if mac:
            safe_mac = mac.upper()
            safe_name = re.sub(r"[^A-Za-z0-9 ._\\-]", "", name)[:64]
            router_ssh(
                "sqlite3 /etc/oui-tertf/client.db "
                f"\"UPDATE client SET name='{safe_name}' WHERE upper(mac)='{safe_mac}';\" "
                "2>/dev/null || true; "
                "ubus call gl-clients sync 2>/dev/null || true",
                timeout=12,
            )
    saved = save_lan_aliases(aliases)
    devices = read_lan_devices()
    return {"ok": True, "aliases": saved, "devices": devices.get("devices") or []}


def read_router_state() -> dict:
    proc = router_ssh(f"cat {ROUTER_CONF}", timeout=14)
    host = _router_host_in_use()
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "router ssh failed").strip()
        return {
            "ok": False,
            "error": err[-500:],
            "host": host,
            "path": ROUTER_CONF,
            "dmz_ip": "",
            "rules": [],
        }
    parsed = parse_router_conf(proc.stdout)
    return {
        "ok": True,
        "host": host,
        "path": ROUTER_CONF,
        "dmz_ip": parsed["dmz_ip"],
        "rules": parsed["rules"],
    }


def write_router_state(dmz_ip: str, rules: list[dict]) -> dict:
    conf_path = str(ROUTER_CONF or "").rstrip("/")
    if conf_path.endswith("/firewall") or conf_path == "firewall":
        raise ValueError(
            "Refusing to write router redirects into /etc/config/firewall. "
            "Set ROUTER_CONF=/etc/config/port_forward"
        )
    dmz_ip, cleaned = validate_router(dmz_ip, rules)
    text = serialize_router_conf(dmz_ip, cleaned)
    # 1) Stream file over SSH stdin (GL.iNet ash has no base64)
    upload = router_ssh(f"cat > {ROUTER_CONF}.tmp", input_text=text)
    if upload.returncode != 0:
        return {
            "ok": False,
            "returncode": upload.returncode,
            "stdout": (upload.stdout or "")[-2000:],
            "stderr": (upload.stderr or "upload failed")[-2000:],
            "dmz_ip": dmz_ip,
            "rules": cleaned,
        }
    # 2) Activate config; reload firewall in background so SSH cannot hang
    remote = (
        f"mv {ROUTER_CONF}.tmp {ROUTER_CONF} && "
        f"( (/etc/init.d/firewall reload >/dev/null 2>&1 || fw3 reload >/dev/null 2>&1 || true) & ) && "
        f"(ubus call port_forward sync_config '{{}}' >/dev/null 2>&1 || true) && "
        f"echo OK && cat {ROUTER_CONF}"
    )
    proc = router_ssh(remote)
    ok = proc.returncode == 0 and "OK" in (proc.stdout or "")
    parsed = parse_router_conf(proc.stdout.split("OK\n", 1)[-1] if ok else text)
    return {
        "ok": ok,
        "returncode": proc.returncode,
        "stdout": ((upload.stdout or "") + "\n" + (proc.stdout or ""))[-4000:],
        "stderr": ((upload.stderr or "") + "\n" + (proc.stderr or ""))[-2000:],
        "dmz_ip": parsed["dmz_ip"],
        "rules": parsed["rules"],
    }


def read_vps_state() -> dict:
    text = CONF_PATH.read_text(encoding="utf-8") if CONF_PATH.exists() else ""
    parsed = parse_conf(text) if text.strip() else {"comments": [], "rules": []}
    managed = validate_vps_rules(parsed["rules"])
    existing = parse_live_dnat()
    # Add UFW GL allows that are not already covered by DNAT/managed
    covered = {(r["proto"], int(r["pub"])) for r in managed + existing}
    for r in parse_ufw_gl_forwards():
        key = (r["proto"], int(r["pub"]))
        if key not in covered:
            existing.append(r)
            covered.add(key)
    rules = merge_vps_lists(managed, existing)
    return {
        "path": str(CONF_PATH),
        "comments": parsed["comments"],
        "rules": rules,
    }


def write_vps_state(rules: list[dict], comments: list[str] | None = None) -> dict:
    cleaned = validate_vps_rules(rules)
    managed = [r for r in cleaned if not r.get("external")]
    # Always keep protected Flint admin HTTP/HTTPS forwards
    by_pub = {int(r["pub"]): r for r in managed}
    by_pub[8080] = {
        "pub": 8080,
        "proto": "tcp",
        "dest_ip": "192.168.8.1",
        "dest_port": 80,
        "name": "flint-http",
        "external": False,
    }
    # Never publish 8443→Flint HTTPS: OpenVPN owns TCP 8443 (and sslh→8443).
    by_pub.pop(8443, None)
    by_pub[NAS_SMB_FORWARD_PUB] = {
        "pub": NAS_SMB_FORWARD_PUB,
        "proto": "tcp",
        "dest_ip": NAS_SMB_HOST,
        "dest_port": 445,
        "name": "nas-smb",
        "external": False,
    }
    managed = list(by_pub.values())
    if comments is None:
        # Avoid recursion through live merge when reading comments only
        text = CONF_PATH.read_text(encoding="utf-8") if CONF_PATH.exists() else ""
        comments = parse_conf(text)["comments"] if text.strip() else []
    text = serialize_vps_conf(comments, managed)
    CONF_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = CONF_PATH.with_suffix(".conf.tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(CONF_PATH)
    proc = subprocess.run(
        ["bash", str(APPLY_SCRIPT)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    # Return merged live view again
    return {
        "ok": proc.returncode == 0,
        "returncode": proc.returncode,
        "stdout": (proc.stdout or "")[-4000:],
        "stderr": (proc.stderr or "")[-2000:],
        "rules": read_vps_state()["rules"] if proc.returncode == 0 else cleaned,
    }


def resolve_mail_hostname() -> str:
    candidates = []
    raw = os.environ.get("MAIL_ENV_PATH", "").strip()
    if raw:
        candidates.append(Path(raw))
    candidates.append(Path("/opt/truemail/.env"))
    for env_path in candidates:
        if not env_path.is_file():
            continue
        for line in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.startswith("MAIL_HOSTNAME="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return os.environ.get("MAIL_HOSTNAME", "mail.example.com")


def parse_caddy_existing_sites(caddy_text: str) -> list[dict]:
    """Parse non-managed site blocks into simple domain→proxy entries for the UI list."""
    # Strip managed hookups block so we only import "current" hand-written sites
    begin = caddy_text.find(HOOKUPS_BEGIN)
    end = caddy_text.find(HOOKUPS_END)
    if begin != -1 and end != -1 and end > begin:
        caddy_text = caddy_text[:begin] + caddy_text[end + len(HOOKUPS_END) :]

    sites: list[dict] = []
    # Match site openers like: domain {   or  domain1, domain2 {
    site_re = re.compile(
        r"(?m)^(?P<label>\{\$[A-Za-z0-9_]+\}|[A-Za-z0-9][A-Za-z0-9._*, -]*?)\s*\{\s*$"
    )
    proxy_re = re.compile(
        r"reverse_proxy\s+(?P<host>[^\s:]+)(?::(?P<port>\d+))?"
    )
    lines = caddy_text.splitlines()
    i = 0
    while i < len(lines):
        m = site_re.match(lines[i])
        if not m:
            i += 1
            continue
        label = m.group("label").strip()
        # skip snippets and raw IP listeners; keep {$ENV} site labels
        if label.startswith("(") or label.startswith("http://") or label.startswith("https://"):
            i += 1
            continue
        if label.startswith("{") and not label.startswith("{$"):
            i += 1
            continue
        # collect block body
        depth = 1
        body: list[str] = []
        i += 1
        while i < len(lines) and depth > 0:
            line = lines[i]
            depth += line.count("{") - line.count("}")
            if depth > 0:
                body.append(line)
            i += 1
        body_text = "\n".join(body)
        if "import " in body_text and "reverse_proxy" not in body_text:
            # e.g. portal.vpstruelord.com { import vpn_portal }
            target_host, target_port, name = DOCKER_HOST_GW, 5050, "vpn-portal"
        else:
            pm = proxy_re.search(body_text)
            if not pm:
                continue
            target_host = pm.group("host")
            target_port = int(pm.group("port") or "80")
            name = "existing"
        # support comma-separated site addresses
        for raw_domain in label.split(","):
            domain = raw_domain.strip()
            if domain.startswith("{$MAIL_HOSTNAME}"):
                domain = resolve_mail_hostname()
            domain = domain.lower()
            if not DOMAIN_RE.match(domain):
                continue
            if name == "existing":
                name = domain.split(".")[0][:40]
            vpn_only = bool(
                re.search(r"(?:client_ip|remote_ip)[^\n]*10\.8\.0\.0/24", body_text)
                or re.search(r"@vpn(?:_clients)?\s+(?:client_ip|remote_ip)", body_text)
            )
            sites.append(
                {
                    "enabled": True,
                    "domain": domain,
                    "target_host": target_host,
                    "target_port": target_port,
                    "name": name,
                    "external": True,
                    "vpn_only": vpn_only,
                }
            )
    return sites


def _router_hookup_targets() -> list[str]:
    """Flint admin reachable via OpenVPN, LAN, or WireGuard tunnel IP."""
    hosts: list[str] = []
    for h in (OVPN_FLINT_VPN_IP, ROUTER_HOST, "10.8.0.3"):
        h = str(h or "").strip()
        if h and h not in hosts:
            hosts.append(h)
    return hosts


def _normalize_hookup_rule(rule: dict) -> dict:
    """Apply opinionated defaults for known hookup domains."""
    out = dict(rule)
    domain = str(out.get("domain") or "").strip().lower()
    if domain == "router.vpstruelord.com":
        out["target_host"] = OVPN_FLINT_VPN_IP or ROUTER_ADMIN_HOST
        out["target_port"] = int(out.get("target_port") or 80)
        out["target_hosts"] = _router_hookup_targets()
        out["vpn_only"] = True if out.get("vpn_only") is None else out.get("vpn_only")
    elif domain == PROXMOX_PUBLIC_HOST.lower():
        out["target_host"] = PROXMOX_HOST
        out["target_port"] = int(out.get("target_port") or PROXMOX_PORT)
        out["target_hosts"] = [PROXMOX_HOST]
        out["upstream_https"] = True
        out["name"] = str(out.get("name") or "proxmox").strip() or "proxmox"
        # Hypervisor UI must never be public — force VPN-only.
        out["vpn_only"] = True
    elif domain == PLEX_PUBLIC_HOST.lower():
        out["target_host"] = PLEX_HOST
        out["target_port"] = int(out.get("target_port") or PLEX_PORT)
        out["target_hosts"] = [PLEX_HOST]
        out["name"] = str(out.get("name") or "plex-server").strip() or "plex-server"
        # Media server must not be public — force VPN-only.
        out["vpn_only"] = True
    elif domain == GRAFANA_PUBLIC_HOST.lower():
        out["target_host"] = GRAFANA_HOST
        out["target_port"] = int(out.get("target_port") or GRAFANA_PORT)
        out["name"] = str(out.get("name") or "grafana").strip() or "grafana"
    return out


def ensure_proxmox_hookup(rules: list[dict]) -> list[dict]:
    """Guarantee proxmox.vpstruelord.com is present in managed hookups (VPN-only)."""
    out = [dict(r) for r in (rules or [])]
    domain = PROXMOX_PUBLIC_HOST.lower()
    for i, rule in enumerate(out):
        if str(rule.get("domain") or "").strip().lower() == domain:
            out[i] = _normalize_hookup_rule(
                {**rule, "enabled": rule.get("enabled", True), "external": False, "vpn_only": True}
            )
            return out
    out.append(
        _normalize_hookup_rule(
            {
                "enabled": True,
                "domain": domain,
                "target_host": PROXMOX_HOST,
                "target_port": PROXMOX_PORT,
                "name": "proxmox",
                "external": False,
                "vpn_only": True,
            }
        )
    )
    return out


def ensure_plex_hookup(rules: list[dict]) -> list[dict]:
    """Guarantee plex.vpstruelord.com is present (Plex LXC on Proxmox, VPN-only)."""
    out = [dict(r) for r in (rules or [])]
    domain = PLEX_PUBLIC_HOST.lower()
    for i, rule in enumerate(out):
        if str(rule.get("domain") or "").strip().lower() == domain:
            out[i] = _normalize_hookup_rule(
                {**rule, "enabled": rule.get("enabled", True), "external": False, "vpn_only": True}
            )
            return out
    out.append(
        _normalize_hookup_rule(
            {
                "enabled": True,
                "domain": domain,
                "target_host": PLEX_HOST,
                "target_port": PLEX_PORT,
                "name": "plex-server",
                "external": False,
                "vpn_only": True,
            }
        )
    )
    return out


def ensure_grafana_hookup(rules: list[dict]) -> list[dict]:
    """Guarantee grafana.vpstruelord.com is present (Grafana on VPS)."""
    out = [dict(r) for r in (rules or [])]
    domain = GRAFANA_PUBLIC_HOST.lower()
    for i, rule in enumerate(out):
        if str(rule.get("domain") or "").strip().lower() == domain:
            out[i] = _normalize_hookup_rule(
                {
                    **rule,
                    "enabled": rule.get("enabled", True),
                    "external": False,
                    "target_host": GRAFANA_HOST,
                    "target_port": GRAFANA_PORT,
                    "name": rule.get("name") or "grafana",
                }
            )
            return out
    out.append(
        _normalize_hookup_rule(
            {
                "enabled": True,
                "domain": domain,
                "target_host": GRAFANA_HOST,
                "target_port": GRAFANA_PORT,
                "name": "grafana",
                "external": False,
                "vpn_only": False,
            }
        )
    )
    return out


def ensure_managed_hookups(rules: list[dict]) -> list[dict]:
    """Keep always-on portal services present in managed hookups."""
    # Drop retired Windows Guacamole hookup if present.
    out = [
        r
        for r in (rules or [])
        if str(r.get("domain") or "").strip().lower() != "windows.vpstruelord.com"
        and str(r.get("name") or "").strip().lower() != "windows-rdp"
    ]
    return ensure_grafana_hookup(ensure_plex_hookup(ensure_proxmox_hookup(out)))


def _hookup_proxy_upstream(rule: dict) -> str:
    port = int(rule["target_port"])
    raw_hosts = rule.get("target_hosts")
    hosts: list[str] = []
    if isinstance(raw_hosts, list):
        for item in raw_hosts:
            host = str(item or "").strip()
            if host and host not in hosts:
                hosts.append(host)
    if not hosts:
        host = str(rule.get("target_host") or "").strip()
        if host:
            hosts.append(host)
    return " ".join(f"{host}:{port}" for host in hosts)


def _router_hookup_site_lines(rule: dict) -> list[str]:
    """Caddy site block for Flint admin — must spoof LAN Host and rewrite redirects.

    Prefer the OpenVPN VIP (10.9.0.2) as upstream. That VIP is reserved for the
    flint CCD client — other profiles (e.g. windows) must not steal 10.9.0.2 or
    Caddy returns 502 while dialing the wrong peer. LAN 192.168.8.1 is a
    fallback only when OVPN iroute + metric prefer tun0 over WireGuard.
    """
    lan_host = ROUTER_ADMIN_HOST
    proxy_host = OVPN_FLINT_VPN_IP or lan_host
    port = int(rule.get("target_port") or 80)
    public = ROUTER_PUBLIC_HOST
    vpn_only = rule.get("vpn_only", True)
    if isinstance(vpn_only, str):
        vpn_only = vpn_only.strip().lower() in {"1", "true", "yes", "on"}
    else:
        vpn_only = bool(vpn_only)
    lines = [
        f"{public} {{",
        "\tencode gzip",
    ]
    if vpn_only:
        lines.append(f"\t@vpn_clients client_ip {VPN_CLIENT_CIDRS}")
        lines.append("\thandle @vpn_clients {")
        indent = "\t\t"
    else:
        indent = "\t"
    lines.extend(
        [
            f"{indent}reverse_proxy {proxy_host}:{port} {{",
            f"{indent}\theader_up Host {lan_host}",
            f"{indent}\theader_up X-Forwarded-Host {{host}}",
            f"{indent}\theader_up X-Forwarded-Proto https",
            f"{indent}\theader_down Location http://{lan_host} https://{public}",
            f"{indent}\theader_down Location http://{lan_host}/ https://{public}/",
            f"{indent}\theader_down Location http://{proxy_host} https://{public}",
            f"{indent}\theader_down Location http://{proxy_host}/ https://{public}/",
            f"{indent}\theader_down -X-Frame-Options",
            f"{indent}\theader_down -Content-Security-Policy",
            f"{indent}}}",
        ]
    )
    if vpn_only:
        lines.extend(
            [
                "\t}",
                "\thandle {",
                '\t\trespond "Forbidden" 403',
                "\t}",
            ]
        )
    lines.extend(
        [
            "\theader {",
            '\t\tStrict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
            "\t\tX-Content-Type-Options nosniff",
            "\t\tReferrer-Policy strict-origin-when-cross-origin",
            '\t\tContent-Security-Policy "frame-ancestors *"',
            "\t}",
            "}",
            "",
        ]
    )
    return lines


def _proxmox_hookup_site_lines(rule: dict) -> list[str]:
    """Caddy site for Proxmox VE — HTTPS upstream with self-signed cert."""
    host = PROXMOX_HOST
    port = int(rule.get("target_port") or PROXMOX_PORT)
    public = PROXMOX_PUBLIC_HOST
    vpn_only = rule.get("vpn_only", True)
    if isinstance(vpn_only, str):
        vpn_only = vpn_only.strip().lower() in {"1", "true", "yes", "on"}
    else:
        vpn_only = bool(vpn_only)
    lines = [
        f"{public} {{",
    ]
    if vpn_only:
        lines.append(f"\t@vpn_clients client_ip {VPN_CLIENT_CIDRS}")
        lines.append("\thandle @vpn_clients {")
        indent = "\t\t"
    else:
        indent = "\t"
    lines.extend(
        [
            f"{indent}reverse_proxy https://{host}:{port} {{",
            f"{indent}\ttransport http {{",
            f"{indent}\t\ttls_insecure_skip_verify",
            f"{indent}\t}}",
            f"{indent}\theader_up Host {{host}}",
            f"{indent}\theader_up X-Forwarded-Host {{host}}",
            f"{indent}\theader_up X-Forwarded-Proto https",
            f"{indent}\theader_up X-Forwarded-For {{remote_host}}",
            f"{indent}\theader_down Location https://{host}:{port} https://{public}",
            f"{indent}\theader_down Location https://{host}:{port}/ https://{public}/",
            f"{indent}\theader_down -X-Frame-Options",
            f"{indent}\theader_down -Content-Security-Policy",
            f"{indent}}}",
        ]
    )
    if vpn_only:
        lines.extend(
            [
                "\t}",
                "\thandle {",
                '\t\trespond "Forbidden" 403',
                "\t}",
            ]
        )
    lines.extend(
        [
            "\theader {",
            '\t\tStrict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
            "\t\tX-Content-Type-Options nosniff",
            "\t\tReferrer-Policy strict-origin-when-cross-origin",
            '\t\tContent-Security-Policy "frame-ancestors *"',
            "\t}",
            "}",
            "",
        ]
    )
    return lines


def _plex_identity_xml() -> str:
    """Fetch /identity over HTTP, then HTTPS (claimed PMS often requires TLS)."""
    import ssl
    import urllib.request

    ctx = ssl._create_unverified_context()
    attempts = (
        (f"http://{PLEX_HOST}:{PLEX_PORT}/identity", None),
        (f"https://{PLEX_HOST}:{PLEX_PORT}/identity", ctx),
    )
    for url, context in attempts:
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/xml"})
            kwargs = {"timeout": 4}
            if context is not None:
                kwargs["context"] = context
            with urllib.request.urlopen(req, **kwargs) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except Exception:
            continue
    return ""


def _plex_machine_identifier() -> str:
    """Best-effort machineIdentifier from the running PMS (for setup URL)."""
    import re

    xml = _plex_identity_xml()
    m = re.search(r'machineIdentifier="([^"]+)"', xml)
    return m.group(1).strip() if m else ""


def _plex_is_claimed() -> bool:
    return 'claimed="1"' in _plex_identity_xml()


def _plex_hookup_site_lines(rule: dict) -> list[str]:
    """Caddy site for the Proxmox Plex LXC at plex.vpstruelord.com (not a portal tab)."""
    host = PLEX_HOST
    port = int(rule.get("target_port") or PLEX_PORT)
    public = PLEX_PUBLIC_HOST
    vpn_only = rule.get("vpn_only", True)
    if isinstance(vpn_only, str):
        vpn_only = vpn_only.strip().lower() in {"1", "true", "yes", "on"}
    else:
        vpn_only = bool(vpn_only)
    machine = _plex_machine_identifier()
    admin = _plex_local_admin_token()
    claimed = _plex_is_claimed()
    # Unclaimed: force setup wizard + local admin token.
    # Claimed: send users to the normal web app (not #!/setup).
    if claimed:
        setup_path = "/web/index.html"
    elif machine and admin:
        from urllib.parse import quote

        setup_path = (
            f"/web/index.html?X-Plex-Token={quote(admin)}#!/setup/{machine}"
        )
    elif machine:
        setup_path = f"/web/index.html#!/setup/{machine}"
    else:
        setup_path = "/web/index.html"
    # After claim, PMS often requires TLS on :32400 ("secure connections required").
    upstream = f"https://{host}:{port}"
    # Indent: site → optional vpn handle → path handle → reverse_proxy options
    base = "\t\t" if vpn_only else "\t"
    opt = base + "\t\t"  # options inside reverse_proxy inside path handle
    # Pass through client headers (especially X-Plex-*). Do NOT rewrite
    # X-Plex-Client-Identifier to empty — that breaks PlayQueue ("loading items").
    proxy_common = [
        f"{opt}transport http {{",
        f"{opt}\ttls_insecure_skip_verify",
        f"{opt}}}",
        # Keep public Host so PMS/web client stay aligned with plex.vpstruelord.com
        f"{opt}header_up Host {{host}}",
        f"{opt}header_up X-Forwarded-Host {public}",
        f"{opt}header_up X-Forwarded-Proto {{scheme}}",
        f"{opt}header_up X-Real-IP {{remote_host}}",
        f"{opt}header_up X-Forwarded-For {{remote_host}}",
        f"{opt}header_down Location http://{public} https://{public}",
        f"{opt}header_down Location https://{public} https://{public}",
        f"{opt}header_down Location http://{host}:{port} https://{public}",
        f"{opt}header_down Location https://{host}:{port} https://{public}",
        f"{opt}header_down Location http://{host} https://{public}",
        f"{opt}header_down -X-Frame-Options",
        f"{opt}header_down -Content-Security-Policy",
    ]
    lines = [f"{public} {{"]
    if vpn_only:
        lines.append(f"\t@vpn_clients client_ip {VPN_CLIENT_CIDRS}")
        lines.append("\thandle @vpn_clients {")
    lines.extend(
        [
            # Claim helper (plex.tv claim code) — portal serves the form + API.
            f"{base}handle /claim* {{",
            f"{base}\treverse_proxy {DOCKER_HOST_GW}:5002",
            f"{base}}}",
            # Land on web UI (setup only while unclaimed).
            f"{base}@plexroot path / /web /web/",
            f"{base}redir @plexroot {setup_path} 302",
            # Media streams should not be gzip-buffered.
            f"{base}@plexmedia path *.mkv *.mp4 *.ts *.m3u8 *.m4s /video/* /library/parts/* /library/streams/*",
            f"{base}handle @plexmedia {{",
            f"{base}\treverse_proxy {upstream} {{",
            *proxy_common,
            f"{opt}flush_interval -1",
            f"{base}\t}}",
            f"{base}}}",
            f"{base}handle {{",
            f"{base}\treverse_proxy {upstream} {{",
            *proxy_common,
            f"{base}\t}}",
            f"{base}}}",
        ]
    )
    if vpn_only:
        lines.extend(
            [
                "\t}",
                "\thandle {",
                '\t\trespond "Forbidden" 403',
                "\t}",
            ]
        )
    lines.extend(
        [
            "\theader {",
            '\t\tStrict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
            "\t\tX-Content-Type-Options nosniff",
            "\t\tReferrer-Policy strict-origin-when-cross-origin",
            '\t\tContent-Security-Policy "frame-ancestors *"',
            "\t}",
            "}",
            "",
        ]
    )
    return lines


def _plex_local_admin_token() -> str:
    """LocalAdminToken for unclaimed PMS (authorizes setup through reverse proxy)."""
    for path in (
        os.environ.get("PLEX_LOCAL_ADMIN_TOKEN_FILE", "").strip(),
        "/opt/wireguard/plex-local-admin.token",
    ):
        if not path:
            continue
        try:
            raw = Path(path).read_text(encoding="utf-8").strip()
            if raw:
                return raw
        except Exception:
            pass
    env = os.environ.get("PLEX_LOCAL_ADMIN_TOKEN", "").strip()
    if env:
        return env
    # Live fetch from CT via Proxmox when portal has LAN/VPN route.
    try:
        import subprocess

        r = subprocess.run(
            [
                "ssh",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "ConnectTimeout=5",
                f"root@{os.environ.get('PROXMOX_HOST', '192.168.8.160').strip() or '192.168.8.160'}",
                "pct",
                "exec",
                PLEX_CTID,
                "--",
                "python3",
                "-c",
                "from pathlib import Path; print(Path('/var/lib/plexmediaserver/Library/Application Support/Plex Media Server/.LocalAdminToken').read_text().strip())",
            ],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        tok = (r.stdout or "").strip()
        if tok and r.returncode == 0:
            try:
                Path("/opt/wireguard/plex-local-admin.token").write_text(tok + "\n", encoding="utf-8")
                os.chmod("/opt/wireguard/plex-local-admin.token", 0o600)
            except Exception:
                pass
            return tok
    except Exception:
        pass
    return ""


def _plex_claim_via_token(claim_token: str) -> dict:
    """Claim unclaimed PMS with a plex.tv claim code (against LAN PMS)."""
    import subprocess
    import urllib.error
    import urllib.parse
    import urllib.request

    raw = str(claim_token or "").strip()
    if not raw:
        raise ValueError("missing plex.tv claim token")
    # plex.tv codes are claim-XXXXXXXX — keep the prefix.
    token = raw if raw.lower().startswith("claim-") else f"claim-{raw}"
    if len(token) < 12:
        raise ValueError("claim token looks too short")

    url = f"http://{PLEX_HOST}:{PLEX_PORT}/myplex/claim?token={urllib.parse.quote(token, safe='')}"
    # Prefer claiming from inside the CT (loopback), then fall back to LAN.
    body = ""
    http_status = 0
    via = "lan"
    try:
        prox = os.environ.get("PROXMOX_HOST", "192.168.8.160").strip() or "192.168.8.160"
        r = subprocess.run(
            [
                "ssh",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "ConnectTimeout=8",
                f"root@{prox}",
                "pct",
                "exec",
                PLEX_CTID,
                "--",
                "curl",
                "-sS",
                "-X",
                "POST",
                "-w",
                "\n__HTTP__:%{http_code}",
                f"http://127.0.0.1:{PLEX_PORT}/myplex/claim?token={token}",
            ],
            capture_output=True,
            text=True,
            timeout=45,
            check=False,
        )
        out = (r.stdout or "") + (r.stderr or "")
        if "__HTTP__:" in out:
            body, _, code_s = out.rpartition("__HTTP__:")
            http_status = int(code_s.strip() or "0")
            via = "ct-loopback"
        elif r.returncode == 0 and out.strip():
            body = out
            http_status = 200
            via = "ct-loopback"
    except Exception:
        body = ""
        http_status = 0

    if http_status == 0:
        via = "lan"
        try:
            req = urllib.request.Request(url, method="POST", data=b"")
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                http_status = int(getattr(resp, "status", 200) or 200)
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            http_status = int(exc.code)
        except (urllib.error.URLError, ConnectionError, TimeoutError, OSError) as exc:
            # PMS often closes the socket after a successful claim while restarting.
            body = str(exc)
            http_status = 0
            via = "lan-closed"

    # Confirm claim state (authoritative)
    claimed = False
    identity = ""
    try:
        import time

        for _ in range(8):
            try:
                with urllib.request.urlopen(
                    f"http://{PLEX_HOST}:{PLEX_PORT}/identity", timeout=5
                ) as resp:
                    identity = resp.read().decode("utf-8", errors="replace")
                claimed = 'claimed="1"' in identity
                if claimed or identity:
                    break
            except Exception:
                pass
            time.sleep(1)
    except Exception:
        pass
    if not claimed and body:
        claimed = "username=" in body and 'username=""' not in body

    if claimed:
        return {
            "ok": True,
            "http_status": http_status or 200,
            "claimed": True,
            "via": via,
            "identity": identity[:500],
            "body": body[:800],
            "next": "https://plex.vpstruelord.com/web/index.html",
            "note": "Server is claimed. Sign in at plex.vpstruelord.com with your plex.tv account.",
        }

    if http_status in (400, 401, 403, 500):
        raise ValueError(
            "Claim code rejected by plex.tv (expired or already used). "
            "Open https://www.plex.tv/claim/ for a fresh code and paste it within ~1 minute."
        )
    if http_status == 0:
        raise ValueError(
            "Plex closed the connection during claim and the server still looks unclaimed. "
            "Get a fresh code at https://www.plex.tv/claim/ and try again immediately."
        )
    if http_status >= 400:
        raise ValueError(
            f"claim failed (HTTP {http_status}). Get a fresh code at https://www.plex.tv/claim/"
        )

    return {
        "ok": True,
        "http_status": http_status,
        "claimed": claimed,
        "via": via,
        "identity": identity[:500],
        "body": body[:800],
        "next": "https://plex.vpstruelord.com/web/index.html",
    }


def _hookup_reverse_proxy_lines(rule: dict, *, indent: str) -> list[str]:
    upstream = _hookup_proxy_upstream(rule)
    https = bool(rule.get("upstream_https"))
    scheme = "https://" if https else ""
    multi = len(upstream.split()) > 1
    if https:
        lines = [f"{indent}reverse_proxy {scheme}{upstream} {{"]
        lines.extend(
            [
                f"{indent}\ttransport http {{",
                f"{indent}\t\ttls_insecure_skip_verify",
                f"{indent}\t}}",
            ]
        )
    else:
        lines = [f"{indent}reverse_proxy {upstream} {{"]
        if multi:
            lines.extend(
                [
                    f"{indent}\ttransport http {{",
                    f"{indent}\t\tdial_timeout 4s",
                    f"{indent}\t}}",
                    f"{indent}\tlb_try_duration 8s",
                    f"{indent}\tlb_try_interval 1s",
                ]
            )
    lines.extend(
        [
            f"{indent}\theader_up Host {{host}}",
            f"{indent}\theader_up X-Forwarded-Host {{host}}",
            f"{indent}\theader_up X-Forwarded-Proto {{scheme}}",
            f"{indent}\theader_down -X-Frame-Options",
            f"{indent}\theader_down -Content-Security-Policy",
            f"{indent}}}",
        ]
    )
    return lines


def default_hookups() -> list[dict]:
    return ensure_managed_hookups([])


def validate_hookups(rules: list[dict], *, allow_external: bool = True) -> list[dict]:
    if not isinstance(rules, list):
        raise ValueError("hookups must be a list")
    cleaned: list[dict] = []
    seen: set[str] = set()
    for i, rule in enumerate(rules):
        try:
            enabled = bool(rule.get("enabled", True))
            domain = str(rule["domain"]).strip().lower()
            target_host = str(rule["target_host"]).strip()
            target_port = int(rule["target_port"])
            name = str(rule.get("name", f"hook{i+1}")).strip() or f"hook{i+1}"
            external = bool(rule.get("external", False))
            vpn_only = _as_bool(rule.get("vpn_only", False))
            target_hosts_raw = rule.get("target_hosts")
            target_hosts: list[str] = []
            if isinstance(target_hosts_raw, list):
                for item in target_hosts_raw:
                    host = str(item or "").strip()
                    if not host:
                        continue
                    if (
                        not IP_RE.match(host)
                        and not DOMAIN_RE.match(host)
                        and not re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$", host)
                    ):
                        raise ValueError(f"Hookup {i + 1}: invalid target_hosts entry")
                    if host not in target_hosts:
                        target_hosts.append(host)
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"Hookup {i + 1}: missing/invalid fields") from exc
        if not DOMAIN_RE.match(domain):
            raise ValueError(f"Hookup {i + 1}: invalid domain")
        # docker service names like webmail / facesearch are allowed
        if not IP_RE.match(target_host) and not DOMAIN_RE.match(target_host) and not re.match(
            r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$", target_host
        ):
            raise ValueError(f"Hookup {i + 1}: invalid target_host")
        if not (1 <= target_port <= 65535):
            raise ValueError(f"Hookup {i + 1}: invalid target_port")
        if not NAME_RE.match(name):
            raise ValueError(f"Hookup {i + 1}: invalid name")
        if domain in seen:
            raise ValueError(f"Hookup {i + 1}: duplicate domain {domain}")
        seen.add(domain)
        if external and not allow_external:
            continue
        entry = {
            "enabled": enabled,
            "domain": domain,
            "target_host": target_host,
            "target_port": target_port,
            "name": name,
            "external": external,
            "vpn_only": vpn_only,
        }
        if target_hosts:
            entry["target_hosts"] = target_hosts
        cleaned.append(_normalize_hookup_rule(entry))
    return cleaned


def _as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def serialize_hookups_caddy(rules: list[dict]) -> str:
    lines = [
        HOOKUPS_BEGIN,
        "# managed by ServerManager — do not edit by hand",
        f"# vpn_only allows: {VPN_CLIENT_CIDRS}",
    ]
    # Never rewrite external/pre-existing Caddy sites into this block
    active = [r for r in rules if r.get("enabled", True) and not r.get("external")]
    if not active:
        lines.append("# (no managed domain hookups enabled)")
    for r in active:
        domain = r["domain"]
        if domain == ROUTER_PUBLIC_HOST.lower():
            lines.extend(_router_hookup_site_lines(r))
            continue
        if domain == PROXMOX_PUBLIC_HOST.lower():
            lines.extend(_proxmox_hookup_site_lines(r))
            continue
        if domain == PLEX_PUBLIC_HOST.lower():
            lines.extend(_plex_hookup_site_lines(r))
            continue
        lines.append(f"{domain} {{")
        # Portal proxies multi-GB NAS media under /nas-files/rpc/* — skip gzip
        # there so Caddy never buffers an entire movie to compress it.
        is_portal = domain == PORTAL_HOST or domain.startswith("portal.")
        if is_portal:
            # Public Windows OpenVPN profile download (token enforced in portal app)
            lines.append("\t@ovpn_windows_dl path /api/openvpn/windows /download/windows.ovpn")
            lines.append("\thandle @ovpn_windows_dl {")
            lines.append(f"\t\treverse_proxy {r['target_host']}:{r['target_port']} {{")
            lines.append("\t\t\theader_up Host {host}")
            lines.append("\t\t\theader_up X-Forwarded-Host {host}")
            lines.append("\t\t\theader_up X-Forwarded-Proto {scheme}")
            lines.append("\t\t}")
            lines.append("\t}")
            # Authenticator PWA + APIs stay reachable without VPN circle membership
            # so enrolled phones can manage pending while LAN pending is enforced.
            lines.append(
                "\t@auth_app path /auth-app.html /auth-app-iphone.html /api/auth-app/* "
                "/static/auth-app-sw.js /static/auth-app-iphone-sw.js "
                "/static/auth-app.html /static/auth-app-iphone.html"
            )
            lines.append("\thandle @auth_app {")
            lines.append(f"\t\treverse_proxy {r['target_host']}:{r['target_port']} {{")
            lines.append("\t\t\theader_up Host {host}")
            lines.append("\t\t\theader_up X-Forwarded-Host {host}")
            lines.append("\t\t\theader_up X-Forwarded-Proto {scheme}")
            lines.append("\t\t\theader_up X-Forwarded-For {remote_host}")
            lines.append("\t\t\theader_up X-Real-IP {remote_host}")
            lines.append("\t\t}")
            lines.append("\t}")
            # NAS media streams skip gzip, but must still honor vpn_only —
            # otherwise a stolen session cookie can cat/download off-VPN while
            # /login.html remains VPN-gated (403).
            lines.append("\t@nasmedia path /nas-files/rpc/cat* /nas-files/rpc/download* /nas-files/rpc/thumbnail*")
            lines.append("\thandle @nasmedia {")
            if r.get("vpn_only"):
                lines.append(f"\t\t@vpn_clients client_ip {VPN_CLIENT_CIDRS}")
                lines.append("\t\thandle @vpn_clients {")
                lines.append(f"\t\t\treverse_proxy {r['target_host']}:{r['target_port']} {{")
                lines.append("\t\t\t\theader_up Host {host}")
                lines.append("\t\t\t\theader_up X-Forwarded-Host {host}")
                lines.append("\t\t\t\theader_up X-Forwarded-Proto {scheme}")
                lines.append("\t\t\t\theader_down -X-Frame-Options")
                lines.append("\t\t\t\theader_down -Content-Security-Policy")
                lines.append("\t\t\t\tflush_interval -1")
                lines.append("\t\t\t}")
                lines.append("\t\t}")
                lines.append("\t\thandle {")
                lines.append('\t\t\trespond "Forbidden" 403')
                lines.append("\t\t}")
            else:
                lines.append(f"\t\treverse_proxy {r['target_host']}:{r['target_port']} {{")
                lines.append("\t\t\theader_up Host {host}")
                lines.append("\t\t\theader_up X-Forwarded-Host {host}")
                lines.append("\t\t\theader_up X-Forwarded-Proto {scheme}")
                lines.append("\t\t\theader_down -X-Frame-Options")
                lines.append("\t\t\theader_down -Content-Security-Policy")
                lines.append("\t\t\tflush_interval -1")
                lines.append("\t\t}")
            lines.append("\t}")
            lines.append("\thandle {")
            lines.append("\t\tencode gzip")
            if r.get("vpn_only"):
                lines.append(f"\t\t@vpn_clients client_ip {VPN_CLIENT_CIDRS}")
                lines.append("\t\thandle @vpn_clients {")
                lines.append(f"\t\t\treverse_proxy {r['target_host']}:{r['target_port']} {{")
                lines.append("\t\t\t\theader_up Host {host}")
                lines.append("\t\t\t\theader_up X-Forwarded-Host {host}")
                lines.append("\t\t\t\theader_up X-Forwarded-Proto {scheme}")
                lines.append("\t\t\t\theader_down -X-Frame-Options")
                lines.append("\t\t\t\theader_down -Content-Security-Policy")
                lines.append("\t\t\t}")
                lines.append("\t\t}")
                lines.append("\t\thandle {")
                lines.append('\t\t\trespond "Forbidden" 403')
                lines.append("\t\t}")
            else:
                lines.append(f"\t\treverse_proxy {r['target_host']}:{r['target_port']} {{")
                lines.append("\t\t\theader_up Host {host}")
                lines.append("\t\t\theader_up X-Forwarded-Host {host}")
                lines.append("\t\t\theader_up X-Forwarded-Proto {scheme}")
                lines.append("\t\t\theader_down -X-Frame-Options")
                lines.append("\t\t\theader_down -Content-Security-Policy")
                lines.append("\t\t}")
            lines.append("\t}")
        else:
            lines.append("\tencode gzip")
            if r.get("vpn_only"):
                # VPN hairpin: wg clients reach VPS:443 with source 10.8.x (requires CF DNS-only).
                lines.append(f"\t@vpn_clients client_ip {VPN_CLIENT_CIDRS}")
                lines.append("\thandle @vpn_clients {")
                lines.extend(_hookup_reverse_proxy_lines(r, indent="\t\t"))
                lines.append("\t}")
                lines.append("\thandle {")
                lines.append('\t\trespond "Forbidden" 403')
                lines.append("\t}")
            else:
                # Public: plain reverse_proxy only — no client_ip matcher residue.
                lines.extend(_hookup_reverse_proxy_lines(r, indent="\t"))
        lines.extend(
            [
                "\theader {",
                '\t\tStrict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
                "\t\tX-Content-Type-Options nosniff",
                "\t\tReferrer-Policy strict-origin-when-cross-origin",
                '\t\tContent-Security-Policy "frame-ancestors *"',
                "\t}",
                "}",
                "",
            ]
        )
    lines.append(HOOKUPS_END)
    return "\n".join(lines).rstrip() + "\n"


def upsert_caddy_hookups_block(caddy_text: str, block: str) -> str:
    begin = caddy_text.find(HOOKUPS_BEGIN)
    end = caddy_text.find(HOOKUPS_END)
    if begin != -1 and end != -1 and end > begin:
        end = end + len(HOOKUPS_END)
        return caddy_text[:begin].rstrip() + "\n\n" + block + "\n" + caddy_text[end:].lstrip("\n")
    return caddy_text.rstrip() + "\n\n" + block + "\n"


def merge_hookup_lists(managed: list[dict], existing: list[dict]) -> list[dict]:
    by_domain = {r["domain"]: dict(r) for r in existing}
    for r in managed:
        # managed entries win / overlay for same domain
        by_domain[r["domain"]] = {**by_domain.get(r["domain"], {}), **r, "external": False}
    # stable-ish order: existing first, then managed-only
    ordered: list[dict] = []
    seen: set[str] = set()
    for r in existing + managed:
        if r["domain"] in seen:
            continue
        ordered.append(by_domain[r["domain"]])
        seen.add(r["domain"])
    return ordered


def read_hookups_state() -> dict:
    managed: list[dict]
    if HOOKUPS_JSON.is_file():
        data = json.loads(HOOKUPS_JSON.read_text(encoding="utf-8"))
        managed = validate_hookups(data.get("rules", []))
    else:
        managed = default_hookups()
    managed = ensure_managed_hookups(managed)

    existing: list[dict] = []
    if str(CADDYFILE_PATH) and CADDYFILE_PATH.is_file():
        try:
            existing = parse_caddy_existing_sites(
                CADDYFILE_PATH.read_text(encoding="utf-8")
            )
        except Exception:
            existing = []

    rules = merge_hookup_lists(managed, existing)
    return {
        "path": str(HOOKUPS_JSON),
        "caddyfile": str(CADDYFILE_PATH),
        "dns_hint": "",
        "vpn_cidrs": VPN_CLIENT_CIDRS,
        "rules": rules,
    }


def _cf_api(method: str, path: str, body: dict | None = None) -> tuple[bool, dict, str]:
    if not CF_API_TOKEN:
        return False, {}, "CF_API_TOKEN not set"
    import urllib.error
    import urllib.request

    url = path if path.startswith("http") else f"https://api.cloudflare.com/client/v4{path}"
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {CF_API_TOKEN}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="ignore")
        try:
            payload = json.loads(raw or "{}")
        except Exception:
            payload = {"errors": [{"message": raw[:300]}]}
        msgs = "; ".join(
            str(e.get("message") or e) for e in (payload.get("errors") or [])
        ) or f"HTTP {exc.code}"
        return False, payload, msgs
    except Exception as exc:
        return False, {}, str(exc)
    if not payload.get("success", False):
        msgs = "; ".join(
            str(e.get("message") or e) for e in (payload.get("errors") or [])
        ) or "Cloudflare API error"
        return False, payload, msgs
    return True, payload, ""


def resolve_cloudflare_zone_id() -> tuple[str, str]:
    """Return (zone_id, zone_name). Uses env or looks up CF_ZONE_NAME / parent of domains."""
    global CF_ZONE_ID, CF_ZONE_NAME
    if CF_ZONE_ID:
        return CF_ZONE_ID, CF_ZONE_NAME
    name = CF_ZONE_NAME.strip()
    if not name:
        return "", ""
    ok, payload, err = _cf_api("GET", f"/zones?name={name}")
    if not ok:
        raise RuntimeError(f"Cloudflare zone lookup failed: {err}")
    results = payload.get("result") or []
    if not results:
        raise RuntimeError(f"Cloudflare zone not found: {name}")
    CF_ZONE_ID = str(results[0].get("id") or "")
    CF_ZONE_NAME = str(results[0].get("name") or name)
    return CF_ZONE_ID, CF_ZONE_NAME




def sync_coredns_hookups(rules: list[dict]) -> tuple[bool, str]:
    """Write VPN client DNS overrides for managed hookup domains."""
    if not COREDNS_COREFILE.is_file():
        return True, "CoreDNS Corefile not found (skipped)"
    vpn_domains = sorted(
        {
            str(r.get("domain", "")).strip().lower()
            for r in rules
            if r.get("enabled", True)
            and not r.get("external")
            and r.get("vpn_only")
            and str(r.get("domain", "")).strip()
        }
    )
    pub_domains = sorted(
        {
            str(r.get("domain", "")).strip().lower()
            for r in rules
            if r.get("enabled", True)
            and not r.get("external")
            and not r.get("vpn_only")
            and str(r.get("domain", "")).strip()
        }
    )
    domains = sorted(set(vpn_domains) | set(pub_domains))
    zone_list = ", ".join(domains) if domains else "_disabled_.invalid"
    # Resolve all managed names to the VPS public IP. VPN-only access is
    # enforced by Caddy remote_ip — not by answering 10.8.0.1 (that address
    # lives inside wg-easy and has no :443 listener).
    hosts_lines = (
        [f"        {VPS_PUBLIC_IP} {d}" for d in domains]
    ) or ["        # no domains"]
    block = (
        f"{COREDNS_BEGIN}\n"
        f"{zone_list}:53 {{\n"
        "    hosts {\n"
        + "\n".join(hosts_lines)
        + "\n        ttl 30\n        reload 15s\n    }\n}\n"
        f"{COREDNS_END}\n"
    )
    original = COREDNS_COREFILE.read_text(encoding="utf-8")
    begin = original.find(COREDNS_BEGIN)
    end = original.find(COREDNS_END)
    if begin != -1 and end != -1 and end > begin:
        end = end + len(COREDNS_END)
        updated = original[:begin].rstrip() + "\n\n" + block + "\n" + original[end:].lstrip("\n")
    else:
        updated = block + "\n" + original.lstrip("\n")
    if updated != original:
        COREDNS_COREFILE.write_text(updated, encoding="utf-8")
    msg = f"CoreDNS: {len(domains)} domain(s)"
    if not COREDNS_CONTAINER:
        return True, msg + " (container not set)"
    proc = subprocess.run(
        ["docker", "restart", COREDNS_CONTAINER],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if proc.returncode != 0:
        return False, msg + f" — restart failed: {(proc.stderr or proc.stdout)[:200]}"
    return True, msg + " — restarted"


def ensure_cloudflare_dns_records(
    want_domains: list[str],
    remove_domains: list[str] | None = None,
    domain_proxied: dict[str, bool] | None = None,
) -> tuple[bool, str, str]:
    """Create/update Cloudflare A records for active domains; delete removed/disabled ones.

    Only deletes A records that currently point at VPS_PUBLIC_IP (safe).
    """
    want_domains = [d.strip().lower() for d in want_domains if d and "." in d]
    remove_domains = [
        d.strip().lower()
        for d in (remove_domains or [])
        if d and "." in d and d.strip().lower() not in set(want_domains)
    ]
    if not want_domains and not remove_domains:
        return True, "Cloudflare DNS: nothing to do", ""
    if not CF_API_TOKEN:
        return True, "Cloudflare DNS skipped (no CF_API_TOKEN)", ""
    try:
        zone_id, zone_name = resolve_cloudflare_zone_id()
    except Exception as exc:
        return False, "", str(exc)
    if not zone_id:
        # Infer zone from longest matching domain suffix by listing zones
        ok, payload, err = _cf_api("GET", "/zones?per_page=50")
        if not ok:
            return False, "", f"Cloudflare zones list failed: {err}"
        zones = payload.get("result") or []
        probe = (want_domains or remove_domains)[0]
        for z in zones:
            zname = str(z.get("name") or "").lower()
            if probe == zname or probe.endswith("." + zname):
                zone_id = str(z.get("id") or "")
                zone_name = zname
                break
        if not zone_id:
            return False, "", "Could not resolve Cloudflare zone for domains"

    def in_zone(domain: str) -> bool:
        if not zone_name:
            return True
        return domain == zone_name or domain.endswith("." + zone_name)

    logs: list[str] = []
    warnings: list[str] = []
    ok_all = True

    for domain in remove_domains:
        if not in_zone(domain):
            warnings.append(f"{domain}: outside zone {zone_name} (delete skipped)")
            continue
        ok, listed, err = _cf_api(
            "GET",
            f"/zones/{zone_id}/dns_records?type=A&name={domain}",
        )
        if not ok:
            ok_all = False
            warnings.append(f"{domain}: delete list failed ({err})")
            continue
        records = listed.get("result") or []
        if not records:
            logs.append(f"{domain}: no A record to delete")
            continue
        deleted_any = False
        for rec in records:
            if str(rec.get("content") or "") != VPS_PUBLIC_IP:
                warnings.append(
                    f"{domain}: left A {rec.get('content')} (not our VPS IP)"
                )
                continue
            rid = rec.get("id")
            if not rid:
                continue
            ok, _, err = _cf_api("DELETE", f"/zones/{zone_id}/dns_records/{rid}")
            if ok:
                deleted_any = True
                logs.append(f"{domain}: deleted A {VPS_PUBLIC_IP}")
            else:
                ok_all = False
                warnings.append(f"{domain}: delete failed ({err})")
        if not deleted_any and records:
            logs.append(f"{domain}: nothing deleted")

    for domain in want_domains:
        if not in_zone(domain):
            warnings.append(f"{domain}: outside zone {zone_name} (skipped)")
            continue
        ok, listed, err = _cf_api(
            "GET",
            f"/zones/{zone_id}/dns_records?type=A&name={domain}",
        )
        if not ok:
            ok_all = False
            warnings.append(f"{domain}: list failed ({err})")
            continue
        records = listed.get("result") or []
        use_proxied = CF_PROXIED
        if domain_proxied is not None:
            use_proxied = bool(domain_proxied.get(domain, CF_PROXIED))
        payload = {
            "type": "A",
            "name": domain,
            "content": VPS_PUBLIC_IP,
            "ttl": 120,
            "proxied": use_proxied,
        }
        if records:
            rid = records[0]["id"]
            same = (
                str(records[0].get("content") or "") == VPS_PUBLIC_IP
                and bool(records[0].get("proxied")) == use_proxied
            )
            if same:
                logs.append(f"{domain}: A {VPS_PUBLIC_IP} already OK")
                continue
            ok, _, err = _cf_api(
                "PUT", f"/zones/{zone_id}/dns_records/{rid}", payload
            )
            if ok:
                mode = "proxied" if use_proxied else "DNS-only"
                logs.append(f"{domain}: updated A → {VPS_PUBLIC_IP} ({mode})")
            else:
                ok_all = False
                warnings.append(f"{domain}: update failed ({err})")
        else:
            ok, _, err = _cf_api(
                "POST", f"/zones/{zone_id}/dns_records", payload
            )
            if ok:
                mode = "proxied" if use_proxied else "DNS-only"
                logs.append(f"{domain}: created A → {VPS_PUBLIC_IP} ({mode})")
            else:
                ok_all = False
                warnings.append(f"{domain}: create failed ({err})")
    msg = "Cloudflare DNS: " + ("; ".join(logs) if logs else "no changes")
    if warnings:
        msg += " | WARN: " + "; ".join(warnings)
    return ok_all, msg, "\n".join(warnings)


def _dns_a_records(domain: str) -> list[str]:
    ips: list[str] = []
    queries = [
        ["getent", "ahostsv4", domain],
        ["dig", "+short", "A", domain],
        ["dig", "+short", "A", domain, "@1.1.1.1"],
        ["dig", "+short", "A", domain, "@8.8.8.8"],
    ]
    for cmd in queries:
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10, check=False
            )
        except Exception:
            continue
        for line in (proc.stdout or "").splitlines():
            parts = line.split()
            cand = (parts[0] if parts else "").strip()
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", cand):
                ips.append(cand)
        if ips:
            break
    return sorted(set(ips))


def _caddy_domain_has_cert(domain: str) -> bool:
    if not CADDY_CONTAINER:
        return False
    proc = subprocess.run(
        [
            "docker",
            "exec",
            CADDY_CONTAINER,
            "sh",
            "-c",
            f"find /data/caddy/certificates -type d -name '{domain}' 2>/dev/null | head -n 1",
        ],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    return bool((proc.stdout or "").strip())


def _https_probe_ok(domain: str) -> bool:
    proc = subprocess.run(
        [
            "curl",
            "-sS",
            "-m",
            "12",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            f"https://{domain}/",
        ],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    code = (proc.stdout or "").strip()
    return code.isdigit() and code != "000"


def ensure_hookup_certificates(domains: list[str]) -> tuple[bool, str, str]:
    """Make sure Caddy has issued TLS certs for managed domains (DNS must already point here)."""
    domains = [d.strip().lower() for d in domains if d and "." in d]
    if not domains or not CADDY_CONTAINER:
        return True, "No domains needing certs", ""

    logs: list[str] = []
    warnings: list[str] = []
    need: list[str] = []
    for domain in domains:
        ips = _dns_a_records(domain)
        if VPS_PUBLIC_IP not in ips:
            warnings.append(
                f"{domain}: DNS A record missing/incorrect (have {ips or ['none']}; need {VPS_PUBLIC_IP})"
            )
            continue
        if _caddy_domain_has_cert(domain) and _https_probe_ok(domain):
            logs.append(f"{domain}: certificate ready")
            continue
        need.append(domain)

    if not need:
        msg = "TLS: " + ("; ".join(logs) if logs else "nothing to do")
        if warnings:
            msg += " | WARN: " + "; ".join(warnings)
        return True, msg, "\n".join(warnings)

    logs.append(f"Requesting certificates for: {', '.join(need)}")
    # Reload only — never docker-restart Caddy here. A container restart drops the
    # portal HTTPS session mid-Save (BrokenPipe), which makes Add domain look broken.
    subprocess.run(
        [
            "docker",
            "exec",
            CADDY_CONTAINER,
            "caddy",
            "reload",
            "--config",
            "/etc/caddy/Caddyfile",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    time.sleep(2)

    # Short wait for ACME; incomplete certs are warnings, not hard failures.
    deadline = time.time() + 25
    pending = list(need)
    while pending and time.time() < deadline:
        pending = [d for d in pending if not _caddy_domain_has_cert(d)]
        if not pending:
            break
        time.sleep(2)

    for domain in need:
        if _caddy_domain_has_cert(domain):
            probe = "https ok" if _https_probe_ok(domain) else "cert present (https still warming)"
            logs.append(f"{domain}: {probe}")
        else:
            warnings.append(
                f"{domain}: certificate not issued yet — check DNS and Caddy logs"
            )
            logs.append(f"{domain}: certificate pending")

    if warnings:
        logs.extend(f"WARN: {w}" for w in warnings)
    # Always ok=True once Caddy accepted the site block; cert lag should not fail Save.
    return True, "\n".join(logs), "\n".join(warnings)


def _write_text_inplace(path: Path, text: str) -> None:
    """Overwrite file bytes without replacing the inode.

    Docker bind-mounts pin the inode at container start. Atomic replace
    (tempfile + rename) leaves the container reading a stale Caddyfile, so
    disabling a domain in the panel would not take effect until restart.
    """
    data = text.encode("utf-8")
    if not path.exists():
        path.write_bytes(data)
        return
    with path.open("r+b") as fh:
        fh.seek(0)
        fh.write(data)
        fh.truncate(len(data))


def write_hookups_state(rules: list[dict]) -> dict:
    cleaned = ensure_managed_hookups(validate_hookups(rules))
    # Persist only managed (non-external) rules; external stay in main Caddyfile
    managed = [r for r in cleaned if not r.get("external")]
    prev_domains: set[str] = set()
    if HOOKUPS_JSON.is_file():
        try:
            prev_data = json.loads(HOOKUPS_JSON.read_text(encoding="utf-8"))
            for r in validate_hookups(prev_data.get("rules", [])):
                if not r.get("external"):
                    prev_domains.add(r["domain"])
        except Exception:
            prev_domains = set()
    dns_hint = ""
    if not str(CADDYFILE_PATH) or not CADDYFILE_PATH.is_file():
        HOOKUPS_JSON.parent.mkdir(parents=True, exist_ok=True)
        HOOKUPS_JSON.write_text(
            json.dumps({"rules": managed}, indent=2) + "\n", encoding="utf-8"
        )
        return {
            "ok": True,
            "returncode": 0,
            "stdout": "Saved hookups.json (Caddy not configured — skipped reload)",
            "stderr": "",
            "rules": cleaned,
            "dns_hint": dns_hint,
        }
    if not CADDY_CONTAINER:
        return {
            "ok": False,
            "returncode": 1,
            "stdout": "",
            "stderr": "CADDY_CONTAINER env var required when CADDYFILE_PATH is set",
            "rules": cleaned,
            "dns_hint": dns_hint,
        }
    original = CADDYFILE_PATH.read_text(encoding="utf-8")
    new_block = serialize_hookups_caddy(managed)
    updated = upsert_caddy_hookups_block(original, new_block)
    block_changed = original != updated
    _write_text_inplace(CADDYFILE_PATH, updated)
    validate = subprocess.run(
        [
            "docker",
            "exec",
            CADDY_CONTAINER,
            "caddy",
            "validate",
            "--config",
            "/etc/caddy/Caddyfile",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if validate.returncode != 0:
        _write_text_inplace(CADDYFILE_PATH, original)
        return {
            "ok": False,
            "returncode": validate.returncode,
            "stdout": (validate.stdout or "")[-4000:],
            "stderr": (validate.stderr or "")[-2000:] or "Caddy validate failed; rolled back",
            "rules": cleaned,
            "dns_hint": dns_hint,
        }

    reload = subprocess.run(
        [
            "docker",
            "exec",
            CADDY_CONTAINER,
            "caddy",
            "reload",
            "--config",
            "/etc/caddy/Caddyfile",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    restart_out = ""
    # Prefer reload. A full `docker restart` of the Caddy container drops the
    # portal HTTPS connection mid-request (BrokenPipe), so Add domain / Save
    # looked broken even when hookups.json was written successfully.
    # Restart only when reload fails — config is already on the bind-mounted file.
    if reload.returncode != 0:
        rst = subprocess.run(
            ["docker", "restart", CADDY_CONTAINER],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        restart_out = (rst.stdout or "") + (rst.stderr or "")
        time.sleep(3)
        alive = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", CADDY_CONTAINER],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if (alive.stdout or "").strip().lower() == "true":
            reload = subprocess.CompletedProcess(
                args=reload.args,
                returncode=0,
                stdout=(reload.stdout or "")
                + "\nCaddy restarted after reload failed\n"
                + restart_out,
                stderr=reload.stderr or "",
            )
        else:
            reload = subprocess.CompletedProcess(
                args=reload.args,
                returncode=1,
                stdout=reload.stdout or "",
                stderr=(reload.stderr or "") + "\nCaddy restart failed\n" + restart_out,
            )
    elif block_changed:
        reload = subprocess.CompletedProcess(
            args=reload.args,
            returncode=0,
            stdout=(reload.stdout or "") + "\nCaddy reloaded (no container restart)\n",
            stderr=reload.stderr or "",
        )

    # Persist JSON as soon as Caddy accepted the config (before DNS/TLS waits).
    if reload.returncode == 0:
        HOOKUPS_JSON.parent.mkdir(parents=True, exist_ok=True)
        HOOKUPS_JSON.write_text(
            json.dumps({"rules": managed}, indent=2) + "\n", encoding="utf-8"
        )

    cert_ok = True
    cert_out = ""
    cert_err = ""
    dns_ok = True
    dns_out = ""
    dns_err = ""
    coredns_ok = True
    coredns_out = ""
    if reload.returncode == 0:
        active_domains = [
            r["domain"] for r in managed if r.get("enabled", True) and not r.get("vpn_only")
        ]
        # Also issue certs for VPN-only domains (needed so TLS works for VPN clients)
        active_domains += [
            r["domain"] for r in managed if r.get("enabled", True) and r.get("vpn_only")
        ]
        # unique preserve order
        seen: set[str] = set()
        ordered: list[str] = []
        for d in active_domains:
            if d not in seen:
                seen.add(d)
                ordered.append(d)
        remove_domains = sorted(prev_domains - set(ordered))
        domain_proxied = {
            r["domain"]: False if r.get("vpn_only") else CF_PROXIED
            for r in managed
            if r.get("enabled", True)
        }
        dns_ok, dns_out, dns_err = ensure_cloudflare_dns_records(
            ordered, remove_domains=remove_domains, domain_proxied=domain_proxied
        )
        coredns_ok, coredns_out = sync_coredns_hookups(managed)
        dns_out = (dns_out or "") + "\n" + (coredns_out or "")
        cert_ok, cert_out, cert_err = ensure_hookup_certificates(ordered)

    merged = merge_hookup_lists(managed, parse_caddy_existing_sites(updated if reload.returncode == 0 else original))
    # Caddy + JSON persistence is the hard requirement. DNS/CoreDNS/TLS issues are
    # surfaced in stderr but must not undo a successful domain add.
    ok = reload.returncode == 0
    warn_bits = []
    if not dns_ok:
        warn_bits.append("cloudflare DNS")
    if not coredns_ok:
        warn_bits.append("CoreDNS")
    if not cert_ok:
        warn_bits.append("TLS certs")
    if warn_bits and ok:
        cert_err = (
            (cert_err or "")
            + ("\n" if cert_err else "")
            + "Applied with warnings: "
            + ", ".join(warn_bits)
        )
    return {
        "ok": ok,
        "returncode": 0 if ok else (reload.returncode or 1),
        "stdout": (
            (
                (validate.stdout or "")
                + "\n"
                + (reload.stdout or "")
                + "\n"
                + dns_out
                + "\n"
                + cert_out
            )
        )[-4000:],
        "stderr": ((reload.stderr or "") + "\n" + dns_err + "\n" + cert_err)[-2000:],
        "rules": merged,
        "dns_hint": dns_hint,
        "warnings": warn_bits,
    }


def read_state() -> dict:
    lan = {"ok": False, "devices": [], "error": "skipped"}
    try:
        lan = read_lan_devices()
    except Exception as exc:
        lan = {"ok": False, "devices": [], "error": str(exc), "host": ROUTER_HOST}
    return {
        "vps": read_vps_state(),
        "router": read_router_state(),
        "hookups": read_hookups_state(),
        "firewall": read_firewall_state(),
        "lan_devices": lan,
    }


def write_and_apply(payload: dict) -> dict:
    vps_in = payload.get("vps") or {}
    router_in = payload.get("router") or {}
    hookups_in = payload.get("hookups") or {}
    firewall_in = payload.get("firewall") or {}
    with _apply_lock:
        vps_result = write_vps_state(vps_in.get("rules", []), vps_in.get("comments"))
        router_result = write_router_state(
            router_in.get("dmz_ip", ""), router_in.get("rules", [])
        )
        if "rules" in hookups_in:
            hookups_result = write_hookups_state(hookups_in.get("rules", []))
        else:
            hookups_result = {"ok": True, "skipped": True, **read_hookups_state()}
        if "rules" in firewall_in:
            firewall_result = write_firewall_state(firewall_in.get("rules", []))
        else:
            firewall_result = {"ok": True, "skipped": True, **read_firewall_state()}
    return {
        "ok": bool(
            vps_result.get("ok")
            and router_result.get("ok")
            and hookups_result.get("ok")
            and firewall_result.get("ok")
        ),
        "vps": vps_result,
        "router": router_result,
        "hookups": hookups_result,
        "firewall": firewall_result,
    }


# Always-public ports the Firewall tab must never delete or VPN-restrict.
UFW_PROTECTED = {
    (22, "tcp"),  # SSH
    (5000, "udp"),  # WireGuard tunnel
}
# Ports that must keep a UFW allow (never mass-deleted) but MAY be vpn_only.
UFW_REQUIRED = {
    (5002, "tcp"),  # portal cleartext HTTP — VPN/LAN only by default
    (2121, "tcp"),  # NAS FTP gateway
    (1445, "tcp"),  # NAS SMB gateway forward
    (5001, "tcp"),  # WireGuard Easy UI (not the :5000/udp tunnel)
}

UFW_ROW_RE = re.compile(
    r"^\[\s*(?P<num>\d+)\]\s+(?P<to>.+?)\s{2,}(?P<action>ALLOW IN|DENY IN|REJECT IN|LIMIT IN)\s{2,}"
    r"(?P<frm>.+?)(?:\s+#\s*(?P<comment>.*))?$"
)

# Protected ports that stay public but use UFW "limit" (rate-cap) instead of bare allow.
UFW_RATE_LIMITED = {
    (22, "tcp"),  # SSH — complements fail2ban + MaxAuthTries 3
}


def _parse_ufw_to(to_field: str) -> tuple[int | None, str, str]:
    """Return (port, proto, display_to)."""
    raw = to_field.strip()
    ipv6 = "(v6)" in raw
    cleaned = raw.replace("(v6)", "").strip()
    # OpenSSH app profile
    if cleaned.lower().startswith("openssh"):
        return 22, "tcp", cleaned
    m = re.match(r"^(\d+)(?:/(tcp|udp))?$", cleaned, re.I)
    if m:
        return int(m.group(1)), (m.group(2) or "tcp").lower(), cleaned
    return None, "tcp", cleaned


def _vpn_ufw_sources() -> list[str]:
    """CIDRs used for vpn_only UFW allow-from rules."""
    parts = [
        p.strip()
        for p in VPN_UFW_FROM.replace(",", " ").split()
        if p.strip()
    ]
    return parts or ["10.8.0.0/24"]


def _is_vpn_ufw_from(frm: str) -> bool:
    f = (frm or "").lower().replace(" ", "")
    if not f or f.startswith("anywhere"):
        return False
    for src in _vpn_ufw_sources():
        if src.lower().replace(" ", "") in f:
            return True
    return f.startswith("10.8.0.") or f.startswith("10.9.0.") or f.startswith("100.64.")


def _run_ufw(args: list[str], timeout: int = 20) -> subprocess.CompletedProcess:
    """Run ufw; missing binary returns rc=127 instead of raising."""
    bin_path = shutil.which("ufw")
    if not bin_path:
        return subprocess.CompletedProcess(
            args=["ufw", *args], returncode=127, stdout="", stderr="ufw not installed"
        )
    try:
        return subprocess.run(
            [bin_path, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(
            args=["ufw", *args], returncode=1, stdout="", stderr=str(exc)
        )


def read_firewall_state() -> dict:
    verbose = _run_ufw(["status", "verbose"])
    numbered = _run_ufw(["status", "numbered"])
    if verbose.returncode == 127:
        return {
            "active": False,
            "default_incoming": "deny",
            "default_outgoing": "allow",
            "default_routed": "deny",
            "vpn_from": VPN_UFW_FROM,
            "rules": [],
            "error": "ufw not installed",
        }
    active = False
    default_in = "deny"
    default_out = "allow"
    default_routed = "deny"
    for line in (verbose.stdout or "").splitlines():
        if line.startswith("Status:"):
            active = "active" in line.lower()
        if line.startswith("Default:"):
            # Default: deny (incoming), allow (outgoing), deny (routed)
            parts = line.lower()
            if "allow (incoming)" in parts:
                default_in = "allow"
            if "deny (incoming)" in parts:
                default_in = "deny"
            if "allow (outgoing)" in parts:
                default_out = "allow"
            if "deny (outgoing)" in parts:
                default_out = "deny"
            if "allow (routed)" in parts:
                default_routed = "allow"
            if "deny (routed)" in parts:
                default_routed = "deny"

    rules: list[dict] = []
    seen: set[tuple[int, str]] = set()
    for line in (numbered.stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("["):
            continue
        m = UFW_ROW_RE.match(line)
        if not m:
            continue
        frm = m.group("frm").strip()
        to_raw = m.group("to")
        if "(v6)" in to_raw or "(v6)" in frm.lower():
            continue  # manage IPv4 rules; ufw allow adds v6 twin
        action = m.group("action")
        if "ALLOW" not in action and "LIMIT" not in action:
            continue
        port, proto, to_disp = _parse_ufw_to(to_raw)
        if port is None:
            continue
        key = (port, proto)
        if key in seen:
            continue
        seen.add(key)
        comment = (m.group("comment") or "").strip() or f"port-{port}"
        locked = key in UFW_PROTECTED
        vpn_only = (not locked) and _is_vpn_ufw_from(frm)
        rate_limited = "LIMIT" in action or key in UFW_RATE_LIMITED
        rules.append(
            {
                "id": int(m.group("num")),
                "port": port,
                "proto": proto,
                "action": "limit" if rate_limited else "allow",
                "from": "Anywhere" if frm.lower().startswith("anywhere") else frm,
                "comment": comment,
                "to": to_disp,
                "locked": locked,
                "vpn_only": vpn_only,
                "rate_limited": rate_limited,
            }
        )
    return {
        "active": active,
        "default_incoming": default_in,
        "default_outgoing": default_out,
        "default_routed": default_routed,
        "vpn_from": VPN_UFW_FROM,
        "rules": rules,
    }


def validate_firewall_rules(rules: list[dict]) -> list[dict]:
    if not isinstance(rules, list):
        raise ValueError("firewall rules must be a list")
    cleaned: list[dict] = []
    seen: set[tuple[int, str]] = set()
    for i, rule in enumerate(rules):
        try:
            port = int(rule["port"])
            proto = str(rule.get("proto", "tcp")).lower().strip()
            action = str(rule.get("action", "allow")).lower().strip()
            comment = str(rule.get("comment", f"port-{port}")).strip() or f"port-{port}"
            vpn_only = bool(rule.get("vpn_only", False))
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"Firewall rule {i + 1}: invalid fields") from exc
        if proto not in ("tcp", "udp"):
            raise ValueError(f"Firewall rule {i + 1}: proto must be tcp or udp")
        if action not in ("allow", "limit"):
            raise ValueError(f"Firewall rule {i + 1}: only allow/limit rules are supported")
        if not (1 <= port <= 65535):
            raise ValueError(f"Firewall rule {i + 1}: invalid port")
        if not re.match(r"^[A-Za-z0-9 _.:/-]{1,60}$", comment):
            raise ValueError(f"Firewall rule {i + 1}: invalid comment")
        key = (port, proto)
        if key in seen:
            raise ValueError(f"Firewall rule {i + 1}: duplicate {port}/{proto}")
        seen.add(key)
        locked = key in UFW_PROTECTED
        if locked:
            vpn_only = False  # never VPN-restrict SSH / WG listen
        rate_limited = key in UFW_RATE_LIMITED or str(rule.get("action", "")).lower() == "limit"
        if rate_limited:
            action = "limit"
        cleaned.append(
            {
                "port": port,
                "proto": proto,
                "action": action,
                "comment": "SSH-ratecap" if key == (22, "tcp") else comment,
                "locked": locked,
                "vpn_only": vpn_only,
                "rate_limited": rate_limited,
            }
        )
    # Ensure protected rules always remain (public)
    for port, proto in UFW_PROTECTED:
        if (port, proto) not in seen:
            labels = {
                (22, "tcp"): "SSH-ratecap",
                (5000, "udp"): "WireGuard VPN tunnel",
            }
            cleaned.append(
                {
                    "port": port,
                    "proto": proto,
                    "action": "limit" if (port, proto) in UFW_RATE_LIMITED else "allow",
                    "comment": labels.get((port, proto), f"protected-{port}"),
                    "locked": True,
                    "vpn_only": False,
                    "rate_limited": (port, proto) in UFW_RATE_LIMITED,
                }
            )
    # Ensure required admin ports remain (VPN-only by default)
    for port, proto in UFW_REQUIRED:
        if (port, proto) not in seen:
            labels = {
                (5002, "tcp"): "portal-http-vpn",
                (2121, "tcp"): "nas-ftp-vpn",
                (1445, "tcp"): "nas-smb-vpn",
                (5001, "tcp"): "wg-easy-ui-vpn",
            }
            cleaned.append(
                {
                    "port": port,
                    "proto": proto,
                    "action": "allow",
                    "comment": labels.get((port, proto), f"required-{port}"),
                    "locked": False,
                    "vpn_only": True,
                }
            )
    return cleaned


def _ufw_allow_cmds(rule: dict) -> list[list[str]]:
    """One or more `ufw allow|limit …` argv lists (without the leading binary)."""
    port = rule["port"]
    proto = rule["proto"]
    comment = rule["comment"]
    if rule.get("vpn_only") and (port, proto) not in UFW_PROTECTED:
        cmds: list[list[str]] = []
        for src in _vpn_ufw_sources():
            cmds.append(
                [
                    "allow",
                    "from",
                    src,
                    "to",
                    "any",
                    "port",
                    str(port),
                    "proto",
                    proto,
                    "comment",
                    comment,
                ]
            )
        return cmds
    verb = "limit" if (
        rule.get("rate_limited")
        or str(rule.get("action", "")).lower() == "limit"
        or (port, proto) in UFW_RATE_LIMITED
    ) else "allow"
    return [[verb, f"{port}/{proto}", "comment", comment]]


def _ufw_allow_cmd(rule: dict) -> list[str]:
    """Back-compat single command (first VPN source only)."""
    cmds = _ufw_allow_cmds(rule)
    return ["ufw", *cmds[0]] if cmds else ["ufw", "allow", "22/tcp"]


def write_firewall_state(rules: list[dict]) -> dict:
    if not shutil.which("ufw"):
        return {
            "ok": False,
            "stdout": "",
            "stderr": "ufw not installed",
            "active": False,
            "default_incoming": "deny",
            "default_outgoing": "allow",
            "default_routed": "deny",
            "vpn_from": VPN_UFW_FROM,
            "rules": [],
        }
    desired = validate_firewall_rules(rules)
    desired_keys = {(r["port"], r["proto"]): r for r in desired}
    logs: list[str] = []

    # Delete current IPv4/v6 rules that are unwanted or need recreate (vpn_only change)
    numbered = _run_ufw(["status", "numbered"])
    rows: list[tuple[int, int, str, bool, bool]] = []
    for line in (numbered.stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("["):
            continue
        m = UFW_ROW_RE.match(line)
        if not m:
            continue
        port, proto, _ = _parse_ufw_to(m.group("to"))
        if port is None:
            continue
        frm = m.group("frm").strip()
        ipv6 = "v6" in frm.lower() or "(v6)" in m.group("to")
        vpn_only = _is_vpn_ufw_from(frm)
        rows.append((int(m.group("num")), port, proto, ipv6, vpn_only))

    # Candidates to delete (unmanaged / vpn_only flip). Skip protected/required
    # ports unless we are intentionally recreating them from desired state.
    # Exception: SSH ALLOW → LIMIT upgrade (UFW_RATE_LIMITED).
    delete_nums: list[tuple[int, int, str]] = []
    for num, port, proto, _ipv6, cur_vpn in rows:
        key = (port, proto)
        if key in UFW_PROTECTED:
            if key in UFW_RATE_LIMITED:
                # Recreate bare ALLOW as LIMIT when rate-cap is required.
                # Detect via raw numbered status line action.
                continue  # handled below via rate-limit upgrade pass
            continue
        want = desired_keys.get(key)
        if want is None and key in UFW_REQUIRED:
            continue  # never wipe portal HTTP allow during partial saves
        if want is None or bool(want.get("vpn_only")) != bool(cur_vpn):
            delete_nums.append((num, port, proto))

    # Upgrade SSH (and other UFW_RATE_LIMITED) from unlimited ALLOW → LIMIT.
    numbered_raw = numbered.stdout or ""
    for line in numbered_raw.splitlines():
        line_s = line.strip()
        if not line_s.startswith("["):
            continue
        m = UFW_ROW_RE.match(line_s)
        if not m:
            continue
        port, proto, _ = _parse_ufw_to(m.group("to"))
        if port is None:
            continue
        if (port, proto) not in UFW_RATE_LIMITED:
            continue
        if "ALLOW" in m.group("action") and "LIMIT" not in m.group("action"):
            delete_nums.append((int(m.group("num")), port, proto))

    # Guard: never mass-delete when the portal only knows a tiny rule set
    # (e.g. after a partial load). That previously wiped HTTP/HTTPS/forwards.
    unique_current = {(p, pr) for _n, p, pr, _i, _v in rows}
    if len(delete_nums) >= 4 and len(desired_keys) < max(4, len(unique_current) // 2):
        logs.append(
            f"refusing mass firewall delete ({len(delete_nums)} rules); "
            f"desired={len(desired_keys)} current={len(unique_current)}. "
            "Only adding missing rules."
        )
        delete_nums = []

    # Delete from highest number so indices stay stable
    for num, port, proto in sorted(delete_nums, key=lambda x: x[0], reverse=True):
        proc = _run_ufw(["--force", "delete", str(num)])
        logs.append(
            f"delete {num} {port}/{proto}: rc={proc.returncode} {(proc.stdout or proc.stderr or '').strip()}"
        )

    # Refresh and add missing / recreated
    after = read_firewall_state()
    have = {
        (r["port"], r["proto"]): (
            bool(r.get("vpn_only")),
            str(r.get("action") or "allow").lower(),
        )
        for r in after["rules"]
    }
    for key, rule in desired_keys.items():
        want_action = "limit" if (
            rule.get("rate_limited")
            or str(rule.get("action", "")).lower() == "limit"
            or key in UFW_RATE_LIMITED
        ) else "allow"
        if key in have:
            cur_vpn, cur_action = have[key]
            if cur_vpn == bool(rule.get("vpn_only")) and cur_action == want_action:
                continue
        scope = "vpn" if rule.get("vpn_only") else ("limit" if want_action == "limit" else "public")
        for cmd in _ufw_allow_cmds(rule):
            proc = _run_ufw(cmd)
            src = ""
            if "from" in cmd:
                try:
                    src = " from " + cmd[cmd.index("from") + 1]
                except Exception:
                    src = ""
            logs.append(
                f"{cmd[0]} {rule['port']}/{rule['proto']} ({scope}{src}): "
                f"rc={proc.returncode} {(proc.stdout or proc.stderr or '').strip()}"
            )

    # Ensure ufw enabled with deny incoming
    _run_ufw(["--force", "enable"])
    final = read_firewall_state()
    return {
        "ok": True,
        "stdout": "\n".join(logs)[-4000:],
        "stderr": "",
        **final,
    }


def _cookie_clear_header() -> str:
    return (
        f"{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; "
        "Expires=Thu, 01 Jan 1970 00:00:00 GMT"
    )


def _cookie_set_header(token: str) -> str:
    return (
        f"{COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Lax; "
        f"Max-Age={int(SESSION_HOURS * 3600)}"
    )






TS_PORTAL_STATE = Path("/opt/dns/tailscale-portal.json")


def load_ts_portal_state() -> dict:
    if TS_PORTAL_STATE.is_file():
        try:
            data = json.loads(TS_PORTAL_STATE.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    return {"auto_disable_exit": True}


def save_ts_portal_state(data: dict) -> None:
    cur = load_ts_portal_state()
    cur.update(data)
    TS_PORTAL_STATE.write_text(json.dumps(cur, indent=2) + "\n", encoding="utf-8")


def _probe_dns(server: str, name: str = "example.com") -> bool:
    try:
        proc = subprocess.run(
            ["dig", "+time=2", "+tries=1", "+short", f"@{server}", name, "A"],
            capture_output=True,
            text=True,
            timeout=6,
        )
        return proc.returncode == 0 and bool((proc.stdout or "").strip())
    except Exception:
        return False


def build_dns_map() -> dict:
    ts = tailscale_status()
    ss = surfshark_status()
    ag = _probe_dns("127.0.0.1")
    pi = _probe_dns("172.30.0.4")
    un = _probe_dns("172.30.0.2")
    coredns = _probe_dns("10.42.42.42") or _probe_dns("10.8.0.1")
    exit_filter = bool(ts.get("exit_dns_filter"))
    run_exit = bool(ts.get("run_exit_node"))
    ss_exit = bool(ss.get("exit_dns_filter"))
    ss_vpn = bool(ss.get("custom_exit_node"))
    paths = [
        {
            "title": "WireGuard / portal DNS",
            "nodes": [
                {"label": "Client", "detail": "DNS 10.8.0.1", "ok": None},
                {"label": "CoreDNS", "detail": "portal names", "ok": coredns},
                {"label": "AdGuard", "detail": "10.42.42.44", "ok": ag},
                {"label": "Pi-hole", "detail": "172.30.0.4", "ok": pi},
                {"label": "Unbound", "detail": "recursive", "ok": un},
                {"label": "Internet", "ok": None},
            ],
            "note": "Used by WireGuard peers (phone / Flint tunnel DNS).",
        },
        {
            "title": "Surfshark exit DNS (pass 2)",
            "nodes": [
                {"label": "WG / Flint client", "detail": "leaked :53", "ok": None},
                {"label": "DNS redirect", "detail": "→ AdGuard", "ok": ss_exit if ss_vpn else None},
                {"label": "AdGuard", "ok": ag if ss_vpn else None},
                {"label": "Pi-hole", "ok": pi if ss_vpn else None},
                {"label": "Unbound", "ok": un if ss_vpn else None},
                {"label": "Surfshark tunnel", "detail": ss.get("server") or "—", "ok": ss_vpn},
            ],
            "note": (
                "Second AdGuard → Pi-hole pass for DNS that would bypass CoreDNS or leave via Surfshark."
                if ss_vpn and ss_exit
                else "Inactive — enable Surfshark VPN Exit + DNS filter."
            ),
        },
        {
            "title": "Tailscale exit-node DNS",
            "nodes": [
                {"label": "Tailscale client", "detail": "via exit node", "ok": None},
                {"label": "DNS redirect", "detail": "tailscale0 → :53", "ok": exit_filter if run_exit else None},
                {"label": "AdGuard", "ok": ag if run_exit else None},
                {"label": "Pi-hole", "ok": pi if run_exit else None},
                {"label": "Unbound", "ok": un if run_exit else None},
                {"label": "Internet", "ok": None},
            ],
            "note": (
                "Active while Run Exit Node is on."
                if run_exit
                else "Inactive — enable Run Exit Node to filter Tailscale exit traffic."
            ),
        },
    ]
    return {
        "ok": True,
        "paths": paths,
        "auto_disable_exit": load_ts_portal_state().get("auto_disable_exit", True),
        "tailscale": {
            "enabled": ts.get("enabled"),
            "run_exit_node": run_exit,
            "exit_dns_filter": exit_filter,
            "custom_exit_node": ts.get("custom_exit_node"),
            "exit_node_ip": ts.get("exit_node_ip"),
        },
        "surfshark": {
            "enabled": ss.get("enabled"),
            "custom_exit_node": ss_vpn,
            "exit_dns_filter": ss_exit,
            "server": ss.get("server"),
        },
    }


TS_EXIT_DNS_SCRIPT = Path("/opt/dns/ts-exit-dns.sh")
TS_EXIT_DNS_FLAG = Path("/opt/dns/ts-exit-dns.enabled")
TS_VPN_EXIT_SCRIPT = Path("/opt/dns/ts-vpn-exit.sh")
TS_VPN_EXIT_STATE = Path("/opt/dns/ts-vpn-exit.state")
TS_HOST_PROTECT_SCRIPT = Path("/opt/dns/ts-host-protect.sh")


def _read_vpn_exit_state() -> dict:
    out = {"enabled": False, "exit_ip": "", "public_ip": ""}
    if not TS_VPN_EXIT_STATE.is_file():
        return out
    try:
        for line in TS_VPN_EXIT_STATE.read_text(encoding="utf-8").splitlines():
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip()
            if k == "ENABLED":
                out["enabled"] = v in ("1", "true", "True", "yes")
            elif k == "EXIT_IP":
                out["exit_ip"] = v
            elif k == "PUBLIC_IP":
                out["public_ip"] = v
    except Exception:
        pass
    return out


def set_vpn_only_exit(enabled: bool, exit_ip: str = "") -> tuple[bool, str]:
    """Route WireGuard + OpenVPN via Tailscale exit; keep VPS public IP on main table."""
    if not TS_VPN_EXIT_SCRIPT.is_file():
        return False, "ts-vpn-exit.sh missing"
    if enabled:
        ip = (exit_ip or "").strip()
        if not ip:
            return False, "exit node IP required for VPN exit"
        proc = subprocess.run(
            [str(TS_VPN_EXIT_SCRIPT), "enable", ip],
            capture_output=True,
            text=True,
            timeout=60,
        )
    else:
        proc = subprocess.run(
            [str(TS_VPN_EXIT_SCRIPT), "disable"],
            capture_output=True,
            text=True,
            timeout=60,
        )
    msg = ((proc.stdout or "") + (proc.stderr or "")).strip()
    return proc.returncode == 0, msg or ("ok" if proc.returncode == 0 else "vpn-exit failed")


def set_ts_host_protect(enabled: bool) -> tuple[bool, str]:
    """Keep VPS→Flint router SSH working while Tailscale is up."""
    if not TS_HOST_PROTECT_SCRIPT.is_file():
        return True, "ts-host-protect.sh missing (skipped)"
    action = "enable" if enabled else "disable"
    proc = subprocess.run(
        [str(TS_HOST_PROTECT_SCRIPT), action],
        capture_output=True,
        text=True,
        timeout=20,
    )
    msg = ((proc.stdout or "") + (proc.stderr or "")).strip()
    if enabled and proc.returncode != 0:
        proc = subprocess.run(
            [str(TS_HOST_PROTECT_SCRIPT), "protect-only"],
            capture_output=True,
            text=True,
            timeout=20,
        )
        msg = ((proc.stdout or "") + (proc.stderr or "")).strip()
    ok = proc.returncode == 0 if enabled else True
    return ok, msg or ("ok" if ok else "ts-host-protect failed")



def ts_exit_dns_status() -> bool:
    if not TS_EXIT_DNS_SCRIPT.is_file():
        return False
    proc = subprocess.run(
        [str(TS_EXIT_DNS_SCRIPT), "status"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return "enabled" in (proc.stdout or "")


def set_ts_exit_dns(enabled: bool) -> tuple[bool, str]:
    if not TS_EXIT_DNS_SCRIPT.is_file():
        return False, "ts-exit-dns.sh missing"
    if enabled:
        TS_EXIT_DNS_FLAG.write_text("1\n", encoding="utf-8")
        subprocess.run(["systemctl", "enable", "sm-ts-exit-dns.service"], capture_output=True, text=True)
        proc = subprocess.run(
            [str(TS_EXIT_DNS_SCRIPT), "enable"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    else:
        if TS_EXIT_DNS_FLAG.exists():
            TS_EXIT_DNS_FLAG.unlink()
        subprocess.run(["systemctl", "disable", "sm-ts-exit-dns.service"], capture_output=True, text=True)
        proc = subprocess.run(
            [str(TS_EXIT_DNS_SCRIPT), "disable"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    out = ((proc.stdout or "") + (proc.stderr or "")).strip()
    return proc.returncode == 0, out


def _tailscale_prefs() -> dict:
    try:
        proc = subprocess.run(
            ["tailscale", "debug", "prefs"],
            capture_output=True,
            text=True,
            timeout=8,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return json.loads(proc.stdout)
    except Exception:
        pass
    return {}


def _tailscale_status_json() -> dict:
    try:
        proc = subprocess.run(
            ["tailscale", "status", "--json"],
            capture_output=True,
            text=True,
            timeout=8,
        )
        if proc.stdout.strip():
            return json.loads(proc.stdout)
    except Exception:
        pass
    return {}


def _tailscale_text() -> str:
    try:
        proc = subprocess.run(
            ["tailscale", "status"],
            capture_output=True,
            text=True,
            timeout=8,
        )
        return (proc.stdout or proc.stderr or "").strip()
    except Exception as exc:
        return str(exc)


def tailscale_status() -> dict:
    prefs = _tailscale_prefs()
    st = _tailscale_status_json()
    state = str(st.get("BackendState") or "")
    auth_url = str(st.get("AuthURL") or "")
    ips = st.get("TailscaleIPs") or []
    self = st.get("Self") or {}
    needs_login = state in ("", "NeedsLogin", "NoState") or bool(st.get("LoggedOut"))
    enabled = bool(prefs.get("WantRunning", state == "Running")) and not needs_login

    advertised = prefs.get("AdvertiseRoutes") or []
    if isinstance(advertised, str):
        advertised = [advertised] if advertised else []
    lan_set = {"192.168.8.0/24", "10.8.0.0/24"}
    adv_set = {str(x).strip() for x in advertised if str(x).strip()}
    advertise_lan = bool(lan_set & adv_set)

    vpn_exit = _read_vpn_exit_state()
    exit_ip = str(vpn_exit.get("exit_ip") or "").strip()
    custom_exit = bool(vpn_exit.get("enabled"))
    if custom_exit and not exit_ip:
        exit_ip = str(prefs.get("ExitNodeIP") or "").strip()
    # advertise-exit-node shows up as default routes in prefs; ExitNodeOption needs admin approval
    run_exit = (
        "0.0.0.0/0" in adv_set
        or "::/0" in adv_set
        or bool(self.get("ExitNodeOption"))
        or bool(prefs.get("AdvertiseExitNode"))
    )

    # NoSNAT false => masquerading enabled
    ip_masq = not bool(prefs.get("NoSNAT", False))

    exit_nodes = []
    peers = st.get("Peer") or {}
    if isinstance(peers, dict):
        for peer in peers.values():
            if not isinstance(peer, dict):
                continue
            if not (peer.get("ExitNodeOption") or peer.get("ExitNode")):
                # still list online peers as possible exit targets? Only those offering exit
                if not peer.get("ExitNodeOption"):
                    continue
            addrs = peer.get("TailscaleIPs") or []
            ip = addrs[0] if addrs else ""
            if not ip:
                continue
            dns = str(peer.get("DNSName") or peer.get("HostName") or ip).rstrip(".")
            exit_nodes.append(
                {
                    "ip": ip,
                    "name": dns.split(".")[0] if dns else ip,
                    "online": bool(peer.get("Online")),
                }
            )
    exit_nodes.sort(key=lambda n: (not n["online"], n["name"]))

    hostname = str(prefs.get("Hostname") or self.get("HostName") or "vpstruelord-vps")
    text = _tailscale_text()
    if ips:
        text = f"IPs: {', '.join(ips)}\nState: {state}\n\n" + text
    if auth_url:
        text += f"\n\nLogin URL:\n{auth_url}"

    return {
        "ok": True,
        "needs_login": needs_login,
        "auth_url": auth_url,
        "state": state,
        "ips": ips,
        "hostname": hostname,
        "enabled": enabled,
        "run_exit_node": run_exit,
        "custom_exit_node": custom_exit,
        "custom_exit_blocked": False,
        "vpn_only_exit": True,
        "exit_node_ip": exit_ip if custom_exit else "",
        "exit_nodes": exit_nodes,
        "advertise_lan": advertise_lan,
        "advertise_wan": False,
        "ip_masquerading": ip_masq,
        "advertise_routes": sorted(adv_set),
        "exit_dns_filter": ts_exit_dns_status(),
        "auto_disable_exit": load_ts_portal_state().get("auto_disable_exit", True),
        "text": text,
    }


def tailscale_start_login() -> dict:
    subprocess.Popen(
        [
            "tailscale",
            "up",
            "--accept-dns=false",
            "--accept-routes=false",
            "--hostname=vpstruelord-vps",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    auth_url = ""
    for _ in range(12):
        time.sleep(0.5)
        st = tailscale_status()
        auth_url = st.get("auth_url") or ""
        if auth_url or st.get("ips"):
            set_ts_host_protect(True)
            break
    return {"ok": True, "auth_url": auth_url, **tailscale_status()}


def _ensure_ip_forward() -> None:
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True, text=True)
    subprocess.run(
        ["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"],
        capture_output=True,
        text=True,
    )




def pihole_sso_token() -> str:
    if not PIHOLE_SSO_SECRET:
        raise RuntimeError("PIHOLE_SSO_SECRET not configured")
    ts = str(int(time.time()))
    sig = hmac.new(PIHOLE_SSO_SECRET.encode(), ts.encode(), hashlib.sha256).hexdigest()
    return f"{ts}.{sig}"


def pihole_sso_url() -> dict:
    token = pihole_sso_token()
    base = PIHOLE_SSO_URL.split("?")[0].rstrip("/")
    return {"ok": True, "url": f"{base}?t={token}"}


def _buffalo_http_json(url: str, payload: dict | None = None, *, form: dict | None = None) -> tuple[int, dict | str, list[str]]:
    """POST JSON or form to Buffalo; return status, body, Set-Cookie values."""
    headers = {"User-Agent": "ServerManager-BuffaloSSO/1.0", "Accept-Encoding": "identity"}
    data = None
    if form is not None:
        from urllib.parse import urlencode

        data = urlencode(form).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = Request(url, data=data, headers=headers, method="POST")
    try:
        with urlopen(req, timeout=20) as resp:
            raw = resp.read()
            status = int(getattr(resp, "status", 200) or 200)
            cookies = []
            if hasattr(resp.headers, "get_all"):
                cookies = resp.headers.get_all("Set-Cookie") or []
            elif resp.headers.get("Set-Cookie"):
                cookies = [resp.headers.get("Set-Cookie")]
            text = raw.decode("utf-8", errors="replace")
            try:
                return status, json.loads(text), cookies
            except Exception:
                return status, text, cookies
    except HTTPError as exc:
        raw = exc.read() if hasattr(exc, "read") else b""
        text = raw.decode("utf-8", errors="replace") if raw else str(exc)
        try:
            body: dict | str = json.loads(text)
        except Exception:
            body = text
        return int(getattr(exc, "code", 502) or 502), body, []
    except (URLError, TimeoutError, OSError) as exc:
        return 502, str(exc), []


_buffalo_sso_cache = {
    "admin_sid": "",
    "admin_ts": 0.0,
    "files_session": "",
    "files_ts": 0.0,
}
_buffalo_sso_cache_lock = threading.Lock()
BUFFALO_SSO_CACHE_TTL = int(os.environ.get("BUFFALO_SSO_CACHE_TTL", "1800"))


def _buffalo_prepare_routes_async() -> None:
    """Fix VPS routes / Flint firewall without blocking SSO."""

    def _work() -> None:
        try:
            ensure_flint_ovpn_lan_access(force=False)
        except Exception:
            try:
                ensure_ovpn_home_lan_routes()
            except Exception:
                pass

    threading.Thread(target=_work, name="buffalo-route-prep", daemon=True).start()


def _buffalo_admin_login() -> str:
    admin_url = f"{BUFFALO_UPSTREAM}/nasapi/"
    admin_payload = {
        "jsonrpc": "2.0",
        "method": "auth.login",
        "params": {"username": BUFFALO_SSO_USER, "password": BUFFALO_SSO_PASS},
        "id": str(int(time.time() * 1000)),
    }
    a_status, a_body, _a_cookies = _buffalo_http_json(admin_url, admin_payload)
    admin_sid = ""
    if isinstance(a_body, dict):
        result = a_body.get("result") or {}
        if isinstance(result, dict):
            admin_sid = str(result.get("sid") or "").strip()
        if not admin_sid and a_body.get("error"):
            raise RuntimeError(f"Buffalo admin login failed: {a_body.get('error')}")
    if a_status >= 400 or not admin_sid:
        raise RuntimeError(f"Buffalo admin login failed ({a_status}): {a_body}")
    return admin_sid


def _buffalo_files_login() -> str:
    files_url = f"{NAS_FILES_UPSTREAM}/rpc/login"
    f_status, f_body, _f_cookies = _buffalo_http_json(
        files_url,
        form={"user": BUFFALO_SSO_USER, "password": BUFFALO_SSO_PASS},
    )
    webaxs = ""
    if isinstance(f_body, dict):
        webaxs = str(f_body.get("webaxs_session") or "").strip()
    if f_status >= 400 or not webaxs:
        raise RuntimeError(f"Buffalo WebAccess login failed ({f_status}): {f_body}")
    return webaxs


def buffalo_sso_login(*, scope: str = "all") -> dict:
    """Log into Buffalo admin (:80) and/or WebAccess (:9000); return session tokens."""
    if not BUFFALO_SSO_PASS:
        raise RuntimeError("BUFFALO_PASS / BUFFALO_PASS_B64 not configured")

    scope = (scope or "all").strip().lower()
    if scope not in ("admin", "files", "all"):
        scope = "all"
    need_admin = scope in ("admin", "all")
    need_files = scope in ("files", "all")

    # Don't block the UI on router SSH / route fixes — run in background.
    _buffalo_prepare_routes_async()

    now = time.time()
    admin_sid = ""
    webaxs = ""
    with _buffalo_sso_cache_lock:
        if (
            need_admin
            and _buffalo_sso_cache["admin_sid"]
            and (now - float(_buffalo_sso_cache["admin_ts"] or 0)) < BUFFALO_SSO_CACHE_TTL
        ):
            admin_sid = _buffalo_sso_cache["admin_sid"]
        if (
            need_files
            and _buffalo_sso_cache["files_session"]
            and (now - float(_buffalo_sso_cache["files_ts"] or 0)) < BUFFALO_SSO_CACHE_TTL
        ):
            webaxs = _buffalo_sso_cache["files_session"]

    jobs: dict[str, object] = {}
    with ThreadPoolExecutor(max_workers=2) as pool:
        if need_admin and not admin_sid:
            jobs["admin"] = pool.submit(_buffalo_admin_login)
        if need_files and not webaxs:
            jobs["files"] = pool.submit(_buffalo_files_login)
        for key, fut in jobs.items():
            result = fut.result()
            if key == "admin":
                admin_sid = str(result)
                with _buffalo_sso_cache_lock:
                    _buffalo_sso_cache["admin_sid"] = admin_sid
                    _buffalo_sso_cache["admin_ts"] = now
            elif key == "files":
                webaxs = str(result)
                with _buffalo_sso_cache_lock:
                    _buffalo_sso_cache["files_session"] = webaxs
                    _buffalo_sso_cache["files_ts"] = now

    out: dict = {"ok": True, "user": BUFFALO_SSO_USER}
    if need_admin:
        if not admin_sid:
            raise RuntimeError("Buffalo admin login failed: no session")
        out["admin"] = {"sid": admin_sid, "url": f"{BUFFALO_PREFIX}/root.html"}
    if need_files:
        if not webaxs:
            raise RuntimeError("Buffalo WebAccess login failed: no session")
        out["files"] = {"session": webaxs, "url": f"{NAS_FILES_PREFIX}/ui/"}
    return out


def _webaxs_cookie_header(session: str) -> str:
    """Single canonical webaxs_session cookie for portal HTTPS."""
    # Path=/ so /nas-files/rpc/cat opens in a new tab still send the session.
    # Always Secure+SameSite=Lax — must match proxied Set-Cookie rewrites or the
    # browser keeps a stale duplicate and WebAccess loops on "Session timeout".
    return f"webaxs_session={session}; Path=/; SameSite=Lax; Secure"


def _webaxs_clear_cookie_headers() -> list[str]:
    """Expire every historical webaxs_session path/secure variant."""
    # Older builds used Path=/nas-files/ and/or non-Secure cookies.
    return [
        "webaxs_session=; Path=/; SameSite=Lax; Secure; Max-Age=0",
        "webaxs_session=; Path=/; SameSite=Lax; Max-Age=0",
        f"webaxs_session=; Path={NAS_FILES_PREFIX}/; SameSite=Lax; Secure; Max-Age=0",
        f"webaxs_session=; Path={NAS_FILES_PREFIX}/; SameSite=Lax; Max-Age=0",
        "webaxs_session=; Path=/nas-files; SameSite=Lax; Max-Age=0",
    ]


def _buffalo_sso_cookie_headers(data: dict) -> list[str]:
    """Build Set-Cookie headers for Buffalo admin / WebAccess sessions."""
    out: list[str] = []
    admin = data.get("admin") or {}
    files = data.get("files") or {}
    sid = str(admin.get("sid") or "").strip()
    sess = str(files.get("session") or "").strip()
    if sid:
        out.append(f"sid={sid}; Path={BUFFALO_PREFIX}/; SameSite=Lax; Secure")
    if sess:
        # Drop stale duplicates first, then set the fresh session.
        out.extend(_webaxs_clear_cookie_headers())
        out.append(_webaxs_cookie_header(sess))
    return out


_router_sso_cache = {"sid": "", "ts": 0.0}
_router_sso_cache_lock = threading.Lock()
ROUTER_SSO_CACHE_TTL = int(os.environ.get("ROUTER_SSO_CACHE_TTL", "1800"))


def _router_rpc(method: str, params: dict) -> dict:
    """Call GL.iNet /rpc via OpenVPN VIP (LAN Host header required by oui-access)."""
    proxy_host = (OVPN_FLINT_VPN_IP or ROUTER_ADMIN_HOST).strip() or ROUTER_ADMIN_HOST
    url = f"http://{proxy_host}/rpc"
    body = {
        "jsonrpc": "2.0",
        "id": int(time.time() * 1000),
        "method": method,
        "params": params,
    }
    req = Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "Host": ROUTER_ADMIN_HOST},
        method="POST",
    )
    with urlopen(req, timeout=20) as resp:
        text = resp.read().decode("utf-8", errors="replace")
    try:
        parsed = json.loads(text)
    except Exception as exc:
        raise RuntimeError(f"Router RPC invalid JSON: {text[:200]}") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError(f"Router RPC unexpected body: {text[:200]}")
    return parsed


def _router_login_hash(
    username: str,
    password: str,
    alg: int,
    salt: str,
    nonce: str,
    hash_method: str = "sha256",
) -> str:
    """GL.iNet SDK 4.x login digest.

    Firmware 4.11+ returns hash-method=sha256 (older builds used md5):
    unix crypt(password, $<alg>$<salt>$) then H(user:cipher:nonce).
    """
    alg = int(alg)
    if alg == 1:
        cipher = crypt.crypt(password, f"$1${salt}$")
    elif alg == 5:
        # Match /etc/shadow ($5$salt$...); do not force rounds=5000 prefix.
        cipher = crypt.crypt(password, f"$5${salt}$")
    elif alg == 6:
        cipher = crypt.crypt(password, f"$6${salt}$")
    else:
        raise RuntimeError(f"Unsupported router login alg: {alg}")
    if not cipher:
        raise RuntimeError("Router login hash generation failed (crypt unavailable)")
    material = f"{username}:{cipher}:{nonce}".encode()
    method = (hash_method or "sha256").strip().lower()
    if method == "md5":
        return hashlib.md5(material).hexdigest()
    if method in {"sha256", "sha-256"}:
        return hashlib.sha256(material).hexdigest()
    raise RuntimeError(f"Unsupported router hash-method: {hash_method}")


def router_sso_login() -> dict:
    """Log into GL.iNet admin and return a session for router.vpstruelord.com."""
    if not ROUTER_PASS:
        raise RuntimeError("ROUTER_PASS / ROUTER_PASS_B64 not configured")

    try:
        ensure_ovpn_home_lan_routes()
    except Exception:
        pass

    now = time.time()
    with _router_sso_cache_lock:
        sid = str(_router_sso_cache.get("sid") or "").strip()
        if sid and (now - float(_router_sso_cache.get("ts") or 0)) < ROUTER_SSO_CACHE_TTL:
            return {
                "ok": True,
                "user": "root",
                "url": f"https://{ROUTER_PUBLIC_HOST}/",
                "sid": sid,
            }

    ch = _router_rpc("challenge", {"username": "root"})
    if ch.get("error"):
        raise RuntimeError(f"Router challenge failed: {ch.get('error')}")
    result = ch.get("result") or {}
    nonce = str(result.get("nonce") or "").strip()
    salt = str(result.get("salt") or "").strip()
    alg = result.get("alg", 5)
    if not nonce:
        raise RuntimeError(f"Router challenge failed: {ch}")

    digest = _router_login_hash(
        "root",
        ROUTER_PASS,
        alg,
        salt,
        nonce,
        str(result.get("hash-method") or "sha256"),
    )
    login = _router_rpc(
        "login",
        {"username": "root", "hash": digest, "alg": alg, "salt": salt},
    )
    if login.get("error"):
        err = login.get("error") or {}
        msg = str(err.get("message") or err)
        if "over limit" in msg.lower():
            raise RuntimeError(
                "Router login is temporarily locked after too many attempts. "
                "Wait a few minutes or log in from home Wi‑Fi at http://192.168.8.1"
            )
        raise RuntimeError(f"Router login failed: {err}")
    sid = str((login.get("result") or {}).get("sid") or "").strip()
    if not sid:
        raise RuntimeError("Router login failed: no session id")

    with _router_sso_cache_lock:
        _router_sso_cache["sid"] = sid
        _router_sso_cache["ts"] = now

    return {
        "ok": True,
        "user": "root",
        "url": f"https://{ROUTER_PUBLIC_HOST}/",
        "sid": sid,
    }


def _router_sso_cookie_headers(data: dict) -> list[str]:
    sid = str(data.get("sid") or "").strip()
    if not sid:
        return []
    domain = ""
    if ROUTER_PUBLIC_HOST.count(".") >= 2:
        domain = "." + ".".join(ROUTER_PUBLIC_HOST.split(".")[-2:])
    domain_attr = f"; Domain={domain}" if domain else ""
    return [
        f"Admin-Token={sid}; Path=/{domain_attr}; SameSite=Lax; Secure; HttpOnly",
    ]


def wg_easy_sso_login() -> dict:
    """Log into wg-easy and return the session cookie for /wg-ui/ SSO."""
    user = (WG_EASY_SSO_USER or "admin").strip() or "admin"
    password = WG_EASY_SSO_PASS
    if not password:
        raise RuntimeError("WG_EASY_PASS / WG_EASY_PASS_B64 (or container INIT_PASSWORD) not configured")

    url = f"{WG_UI_UPSTREAM}/api/auth/password"
    payload = {"username": user, "password": password, "remember": True}
    headers = {
        "User-Agent": "ServerManager-WgSso/1.0",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Accept-Encoding": "identity",
    }
    req = Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
    try:
        with urlopen(req, timeout=20) as resp:
            raw = resp.read()
            status = int(getattr(resp, "status", 200) or 200)
            set_cookies: list[str] = []
            if hasattr(resp.headers, "get_all"):
                set_cookies = resp.headers.get_all("Set-Cookie") or []
            elif resp.headers.get("Set-Cookie"):
                set_cookies = [resp.headers.get("Set-Cookie")]
    except HTTPError as exc:
        raw = exc.read() if hasattr(exc, "read") else b""
        text = raw.decode("utf-8", errors="replace") if raw else str(exc)
        raise RuntimeError(f"wg-easy login failed ({getattr(exc, 'code', '?')}): {text[:300]}") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"wg-easy login failed: {exc}") from exc

    text = raw.decode("utf-8", errors="replace") if raw else ""
    try:
        body = json.loads(text) if text else {}
    except Exception:
        body = {}
    if status >= 400 or (isinstance(body, dict) and body.get("status") not in (None, "success") and body.get("error")):
        raise RuntimeError(f"wg-easy login failed ({status}): {text[:300]}")
    if isinstance(body, dict) and body.get("status") and body.get("status") != "success":
        raise RuntimeError(f"wg-easy login failed: {body}")

    cookie_val = ""
    max_age = "604800"
    for raw_c in set_cookies:
        if not raw_c:
            continue
        # First segment is name=value
        first = raw_c.split(";", 1)[0].strip()
        if first.lower().startswith(WG_EASY_COOKIE.lower() + "="):
            cookie_val = first.split("=", 1)[1]
            for part in raw_c.split(";")[1:]:
                low = part.strip().lower()
                if low.startswith("max-age="):
                    max_age = part.strip().split("=", 1)[1].strip() or max_age
            break
    if not cookie_val:
        raise RuntimeError("wg-easy login succeeded but no session cookie returned")

    return {
        "ok": True,
        "user": user,
        "cookie": cookie_val,
        "max_age": max_age,
        "url": f"{WG_UI_PREFIX}/",
    }


def _wg_easy_sso_cookie_headers(data: dict) -> list[str]:
    """Set wg-easy session cookie under /wg-ui/ for the portal embed."""
    val = str(data.get("cookie") or "").strip()
    if not val:
        return []
    max_age = str(data.get("max_age") or "604800").strip() or "604800"
    # Clear any stale Path=/ copy first, then set the prefix-scoped session.
    return [
        f"{WG_EASY_COOKIE}=; Path=/; SameSite=Lax; Secure; Max-Age=0",
        f"{WG_EASY_COOKIE}=; Path={WG_UI_PREFIX}/; SameSite=Lax; Secure; Max-Age=0",
        f"{WG_EASY_COOKIE}={val}; Path={WG_UI_PREFIX}/; Max-Age={max_age}; HttpOnly; SameSite=Lax; Secure",
    ]


def _grafana_cookie_domain() -> str:
    """Parent domain for sharing Grafana session with grafana.<domain> iframe."""
    host = (GRAFANA_PUBLIC_HOST or "").strip().lower()
    parts = [p for p in host.split(".") if p]
    if len(parts) >= 2:
        return "." + ".".join(parts[-2:])
    return ""


def grafana_sso_login() -> dict:
    """Log into Grafana and return session cookies for the portal iframe SSO."""
    global GRAFANA_SSO_USER, GRAFANA_SSO_PASS
    # Reload in case install-grafana.sh rotated the password after panel start.
    GRAFANA_SSO_USER, GRAFANA_SSO_PASS = _load_grafana_admin()
    user = (GRAFANA_SSO_USER or "admin").strip() or "admin"
    password = (GRAFANA_SSO_PASS or "").strip()
    if not password:
        raise RuntimeError("Grafana admin password missing (/opt/grafana/.env)")

    url = f"{GRAFANA_UPSTREAM}/login"
    payload = {"user": user, "password": password}
    headers = {
        "User-Agent": "ServerManager-GrafanaSso/1.0",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Accept-Encoding": "identity",
    }
    req = Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
    try:
        with urlopen(req, timeout=20) as resp:
            raw = resp.read()
            status = int(getattr(resp, "status", 200) or 200)
            set_cookies: list[str] = []
            if hasattr(resp.headers, "get_all"):
                set_cookies = resp.headers.get_all("Set-Cookie") or []
            elif resp.headers.get("Set-Cookie"):
                set_cookies = [resp.headers.get("Set-Cookie")]
    except HTTPError as exc:
        raw = exc.read() if hasattr(exc, "read") else b""
        text = raw.decode("utf-8", errors="replace") if raw else str(exc)
        raise RuntimeError(
            f"Grafana login failed ({getattr(exc, 'code', '?')}): {text[:300]}"
        ) from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"Grafana login failed: {exc}") from exc

    text = raw.decode("utf-8", errors="replace") if raw else ""
    try:
        body = json.loads(text) if text else {}
    except Exception:
        body = {}
    if status >= 400:
        raise RuntimeError(f"Grafana login failed ({status}): {text[:300]}")
    if isinstance(body, dict) and body.get("message") and "Logged in" not in str(body.get("message")):
        # Some versions return messageId on failure with 200 — treat unknown as error if no cookie.
        pass

    session = ""
    expiry = ""
    max_age = "2592000"
    for raw_c in set_cookies:
        if not raw_c:
            continue
        first = raw_c.split(";", 1)[0].strip()
        name, _, val = first.partition("=")
        lname = name.strip().lower()
        if lname == GRAFANA_COOKIE.lower():
            session = val
            for part in raw_c.split(";")[1:]:
                low = part.strip().lower()
                if low.startswith("max-age="):
                    max_age = part.strip().split("=", 1)[1].strip() or max_age
        elif lname == GRAFANA_COOKIE_EXPIRY.lower():
            expiry = val
    if not session:
        raise RuntimeError("Grafana login succeeded but no grafana_session cookie returned")

    return {
        "ok": True,
        "user": user,
        "cookie": session,
        "expiry": expiry,
        "max_age": max_age,
        "url": f"https://{GRAFANA_PUBLIC_HOST}/",
    }


def _grafana_sso_cookie_headers(data: dict) -> list[str]:
    """Set Grafana session cookies on .vpstruelord.com for the iframe embed."""
    val = str(data.get("cookie") or "").strip()
    if not val:
        return []
    max_age = str(data.get("max_age") or "2592000").strip() or "2592000"
    expiry = str(data.get("expiry") or "").strip()
    domain = _grafana_cookie_domain()
    dom = f"; Domain={domain}" if domain else ""
    # SameSite=None; Secure required for cross-subdomain iframe embeds.
    out = [
        f"{GRAFANA_COOKIE}={val}; Path=/{dom}; Max-Age={max_age}; HttpOnly; Secure; SameSite=None",
    ]
    if expiry:
        out.append(
            f"{GRAFANA_COOKIE_EXPIRY}={expiry}; Path=/{dom}; Max-Age={max_age}; Secure; SameSite=None"
        )
    return out


def _read_text(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _sh_out(args: list[str], timeout: float = 6) -> str:
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return ((proc.stdout or "") + (proc.stderr or "")).strip()
    except Exception as exc:
        return str(exc)


def _svc_active(name: str) -> bool:
    out = _sh_out(["systemctl", "is-active", name], timeout=4)
    return out.strip() == "active"


def _docker_running(name: str) -> bool:
    out = _sh_out(
        ["docker", "inspect", "-f", "{{.State.Running}}", name],
        timeout=6,
    )
    return out.strip().lower() == "true"


def _security_run(cmd: list[str], timeout: float = 8) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(
            args=cmd, returncode=1, stdout="", stderr=str(exc)
        )


SSH_LOGIN_DROPIN = Path("/etc/ssh/sshd_config.d/00-servermanager-login.conf")
SSH_LOGIN_DROPIN_LEGACY = Path("/etc/ssh/sshd_config.d/99-servermanager-login.conf")
SSH_ROOT_AUTHORIZED_KEYS = Path("/root/.ssh/authorized_keys")
SSH_LOGIN_METHODS = ("password_and_keys", "keys_only")
SSH_ROOT_LOGIN_MODES = ("yes", "prohibit-password", "no")
_SSH_PUBKEY_TYPES = (
    "ssh-ed25519",
    "ssh-rsa",
    "ssh-dss",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
)


def _security_is_authorized_key_line(line: str) -> bool:
    s = (line or "").strip()
    if not s or s.startswith("#"):
        return False
    return any(
        s.startswith(t + " ") or f" {t} " in f" {s} " for t in _SSH_PUBKEY_TYPES
    )


def _security_list_authorized_keys(path: Path = SSH_ROOT_AUTHORIZED_KEYS) -> list[dict]:
    """Parse root authorized_keys into fingerprint rows for the Security panel."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return []
    rows: list[dict] = []
    idx = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not _security_is_authorized_key_line(line):
            continue
        idx += 1
        fp = ""
        bits = ""
        key_type = ""
        comment = ""
        # ssh-keygen -lf reads a file; use a temp line file for accurate fingerprint.
        try:
            import tempfile

            with tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", prefix="sm-sshkey-", suffix=".pub", delete=False
            ) as tmp:
                tmp.write(line + "\n")
                tmp_path = tmp.name
            try:
                proc = _security_run(["ssh-keygen", "-lf", tmp_path], timeout=6)
            finally:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            if proc.returncode == 0 and (proc.stdout or "").strip():
                # format: "256 SHA256:... comment (ED25519)"
                parts = (proc.stdout or "").strip().split()
                if len(parts) >= 2:
                    bits = parts[0]
                    fp = parts[1]
                if parts:
                    maybe_type = parts[-1].strip("()")
                    if maybe_type and maybe_type.upper() == maybe_type:
                        key_type = maybe_type
                if len(parts) >= 4:
                    comment = " ".join(parts[2:-1]).strip()
        except Exception:
            pass
        if not key_type:
            for t in _SSH_PUBKEY_TYPES:
                if line.startswith(t + " ") or f" {t} " in f" {line} ":
                    key_type = t
                    break
        if not comment:
            toks = line.split()
            if len(toks) >= 3 and not toks[0].startswith("ssh-") and "ssh-" not in toks[0]:
                # options prefix — comment usually last token
                comment = toks[-1] if not toks[-1].startswith("AAAA") else ""
            elif len(toks) >= 3:
                comment = toks[-1]
        rows.append(
            {
                "index": idx,
                "type": key_type or "unknown",
                "fingerprint": fp or "—",
                "bits": bits or "",
                "comment": comment or "",
                "line_preview": (line[:48] + "…") if len(line) > 48 else line,
            }
        )
    return rows


def _security_authorized_key_count(path: Path = SSH_ROOT_AUTHORIZED_KEYS) -> int:
    return len(_security_list_authorized_keys(path))


def _security_login_method_from_sshd(ssh: dict) -> str:
    pw = str(ssh.get("password_authentication") or "").lower()
    pub = str(ssh.get("pubkey_authentication") or "").lower()
    pw_on = pw in ("yes", "true")
    pub_on = pub in ("yes", "true")
    if pw_on and pub_on:
        return "password_and_keys"
    if (not pw_on) and pub_on:
        return "keys_only"
    if pw_on and not pub_on:
        return "password_only"
    return "unknown"


def _security_root_login_meta(permit: str | None) -> dict:
    val = str(permit or "").strip().lower()
    if val == "yes":
        return {
            "root_login_mode": "yes",
            "root_login_label": "Root password + keys",
            "root_login_risk": "high",
            "root_login_detail": "permitrootlogin=yes — root can use a password.",
        }
    if val in ("prohibit-password", "without-password"):
        return {
            "root_login_mode": "prohibit-password",
            "root_login_label": "Root SSH keys only",
            "root_login_risk": "medium",
            "root_login_detail": (
                f"permitrootlogin={val} — root login allowed with SSH keys "
                "(medium finding)."
            ),
        }
    if val in ("no", "off", "false"):
        return {
            "root_login_mode": "no",
            "root_login_label": "Root SSH disabled",
            "root_login_risk": "ok",
            "root_login_detail": "permitrootlogin=no — root cannot SSH in.",
        }
    return {
        "root_login_mode": val or "unknown",
        "root_login_label": f"Root login: {val or 'unknown'}",
        "root_login_risk": "medium",
        "root_login_detail": f"permitrootlogin={val or 'unknown'}",
    }


def _normalize_root_login_mode(value: str) -> str:
    chosen = str(value or "").strip().lower().replace("_", "-")
    aliases = {
        "password": "yes",
        "password-and-keys": "yes",
        "allow": "yes",
        "keys": "prohibit-password",
        "keys-only": "prohibit-password",
        "keysonly": "prohibit-password",
        "pubkey": "prohibit-password",
        "without-password": "prohibit-password",
        "withoutpassword": "prohibit-password",
        "prohibitpassword": "prohibit-password",
        "deny": "no",
        "disabled": "no",
        "disable": "no",
        "off": "no",
        "false": "no",
    }
    chosen = aliases.get(chosen, chosen)
    if chosen not in SSH_ROOT_LOGIN_MODES:
        raise ValueError(
            "permit_root_login must be yes, prohibit-password, or no"
        )
    return chosen


def _security_sshd_config() -> dict:
    proc = _security_run(["sshd", "-T"], timeout=6)
    keys = _security_list_authorized_keys()
    login_users = _security_list_login_users()
    out = {
        "ok": proc.returncode == 0,
        "permit_root_login": None,
        "password_authentication": None,
        "pubkey_authentication": None,
        "kbd_interactive_authentication": None,
        "permit_empty_passwords": None,
        "login_method": "unknown",
        "login_method_label": "Unknown",
        "root_authorized_keys": len(keys),
        "authorized_keys": keys,
        "login_users": login_users,
        "keys_only_ready": len(keys) > 0,
        "dropin_path": str(SSH_LOGIN_DROPIN),
        "dropin_present": SSH_LOGIN_DROPIN.is_file(),
    }
    out.update(_security_root_login_meta(None))
    if proc.returncode != 0:
        out["error"] = (proc.stderr or proc.stdout or "sshd -T failed")[:240]
        return out
    for line in (proc.stdout or "").splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) != 2:
            continue
        key, val = parts[0].lower(), parts[1].strip().lower()
        if key == "permitrootlogin":
            out["permit_root_login"] = val
        elif key == "passwordauthentication":
            out["password_authentication"] = val
        elif key == "pubkeyauthentication":
            out["pubkey_authentication"] = val
        elif key in ("kbdinteractiveauthentication", "challengeresponseauthentication"):
            out["kbd_interactive_authentication"] = val
        elif key == "permitemptypasswords":
            out["permit_empty_passwords"] = val
    method = _security_login_method_from_sshd(out)
    out["login_method"] = method
    out["login_method_label"] = {
        "password_and_keys": "Password + SSH keys",
        "keys_only": "SSH keys only",
        "password_only": "Password only",
        "unknown": "Unknown / custom",
    }.get(method, "Unknown / custom")
    out.update(_security_root_login_meta(out.get("permit_root_login")))
    # Default locked until the request handler attaches session unlock status.
    two_factor = ssh_panel_2fa_enabled()
    method = ssh_panel_2fa_method() if two_factor else "email"
    required = ["portal_password"]
    if two_factor:
        required.append("app_code" if method == "app" else "email_code")
    out["panel_lock"] = {
        "unlocked": False,
        "expires_at": None,
        "expires_in": 0,
        "unlock_seconds": SSH_PANEL_UNLOCK_SECONDS,
        "two_factor_enabled": two_factor,
        "two_factor_method": method,
        "auth_app_path": "/auth-app-iphone.html",
        "email_to": EMAIL_CODE_TO,
        "required": required,
    }
    return out


def _ssh_login_dropin_body(*, password_auth: bool, permit_root: str) -> str:
    root = _normalize_root_login_mode(permit_root)
    if password_auth:
        return (
            "# Managed by ServerManager Security tab — VPS login method\n"
            "# Do not edit by hand; change via the portal Security tab.\n"
            "PasswordAuthentication yes\n"
            "KbdInteractiveAuthentication yes\n"
            "PubkeyAuthentication yes\n"
            f"PermitRootLogin {root}\n"
            "PermitEmptyPasswords no\n"
        )
    return (
        "# Managed by ServerManager Security tab — VPS login method\n"
        "# Do not edit by hand; change via the portal Security tab.\n"
        "PasswordAuthentication no\n"
        "KbdInteractiveAuthentication no\n"
        "PubkeyAuthentication yes\n"
        f"PermitRootLogin {root}\n"
        "PermitEmptyPasswords no\n"
    )


def _apply_ssh_login_dropin(*, password_auth: bool, permit_root: str) -> dict:
    """Write 00-servermanager-login.conf, validate, reload, verify password flag."""
    root = _normalize_root_login_mode(permit_root)
    body = _ssh_login_dropin_body(password_auth=password_auth, permit_root=root)
    SSH_LOGIN_DROPIN.parent.mkdir(parents=True, exist_ok=True)
    previous = ""
    if SSH_LOGIN_DROPIN.is_file():
        try:
            previous = SSH_LOGIN_DROPIN.read_text(encoding="utf-8", errors="replace")
        except OSError:
            previous = ""
    SSH_LOGIN_DROPIN.write_text(body, encoding="utf-8")
    try:
        os.chmod(SSH_LOGIN_DROPIN, 0o644)
    except OSError:
        pass
    try:
        if SSH_LOGIN_DROPIN_LEGACY.is_file():
            SSH_LOGIN_DROPIN_LEGACY.unlink()
    except OSError:
        pass

    test = _security_run(["sshd", "-t"], timeout=8)
    if test.returncode != 0:
        try:
            if previous:
                SSH_LOGIN_DROPIN.write_text(previous, encoding="utf-8")
            else:
                SSH_LOGIN_DROPIN.unlink(missing_ok=True)
        except OSError:
            pass
        err = (test.stderr or test.stdout or "sshd -t failed")[:400]
        raise ValueError(f"sshd config invalid; not applied: {err}")

    reload_proc = _security_run(["systemctl", "reload", "ssh"], timeout=15)
    if reload_proc.returncode != 0:
        reload_proc = _security_run(["systemctl", "reload", "sshd"], timeout=15)
    if reload_proc.returncode != 0:
        err = (reload_proc.stderr or reload_proc.stdout or "reload failed")[:400]
        raise ValueError(f"sshd config written but reload failed: {err}")

    after = _security_sshd_config()
    expected_pw = "yes" if password_auth else "no"
    actual_pw = str(after.get("password_authentication") or "").lower()
    if actual_pw != expected_pw:
        try:
            if previous:
                SSH_LOGIN_DROPIN.write_text(previous, encoding="utf-8")
            else:
                SSH_LOGIN_DROPIN.unlink(missing_ok=True)
            _security_run(["systemctl", "reload", "ssh"], timeout=15)
        except OSError:
            pass
        raise ValueError(
            "sshd reload succeeded but PasswordAuthentication is still "
            f"{actual_pw!r} (expected {expected_pw!r}). "
            "Another sshd_config drop-in may be overriding ServerManager; "
            "change was rolled back."
        )
    return after


def apply_ssh_login_method(method: str, permit_root_login: str | None = None) -> dict:
    """Apply VPS SSH login method via sshd drop-in and reload sshd."""
    chosen = str(method or "").strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "password": "password_and_keys",
        "password_keys": "password_and_keys",
        "passwordandkeys": "password_and_keys",
        "keys": "keys_only",
        "keysonly": "keys_only",
        "pubkey": "keys_only",
        "pubkey_only": "keys_only",
    }
    chosen = aliases.get(chosen, chosen)
    if chosen not in SSH_LOGIN_METHODS:
        raise ValueError("method must be password_and_keys or keys_only")

    before = _security_sshd_config()
    key_count = int(before.get("root_authorized_keys") or 0)
    if chosen == "keys_only" and key_count < 1:
        raise ValueError(
            "Cannot switch to keys only: /root/.ssh/authorized_keys has no keys. "
            "Add an SSH public key first to avoid lockout."
        )

    if permit_root_login:
        root = _normalize_root_login_mode(permit_root_login)
    elif chosen == "keys_only":
        # Keep existing keys-only root mode if already prohibit-password/no.
        cur = str(before.get("root_login_mode") or "")
        root = cur if cur in ("prohibit-password", "no") else "prohibit-password"
    else:
        root = "yes"

    if chosen == "keys_only" and root == "yes":
        # Password auth is off; root "yes" still allows keys — normalize to keys-only root.
        root = "prohibit-password"

    after = _apply_ssh_login_dropin(
        password_auth=(chosen == "password_and_keys"),
        permit_root=root,
    )
    return {
        "ok": True,
        "applied": chosen,
        "dropin_path": str(SSH_LOGIN_DROPIN),
        "before": {
            "login_method": before.get("login_method"),
            "password_authentication": before.get("password_authentication"),
            "permit_root_login": before.get("permit_root_login"),
        },
        "ssh": after,
        "message": (
            "SSH keys only — password login disabled."
            if chosen == "keys_only"
            else "Password + SSH keys enabled for VPS login."
        ),
    }


def apply_ssh_root_login(permit_root_login: str) -> dict:
    """Change PermitRootLogin while preserving current password-auth mode."""
    root = _normalize_root_login_mode(permit_root_login)
    before = _security_sshd_config()
    method = before.get("login_method") or "unknown"
    password_auth = method == "password_and_keys" or (
        str(before.get("password_authentication") or "").lower() in ("yes", "true")
    )
    if root == "yes" and not password_auth:
        # With password auth off, "yes" is equivalent to keys-only root.
        root = "prohibit-password"
    if root in ("prohibit-password", "yes") and int(before.get("root_authorized_keys") or 0) < 1:
        raise ValueError(
            "Cannot allow root SSH: /root/.ssh/authorized_keys has no keys."
        )
    after = _apply_ssh_login_dropin(password_auth=password_auth, permit_root=root)
    labels = {
        "yes": "Root password + keys enabled.",
        "prohibit-password": "Root SSH limited to keys only (permitrootlogin=prohibit-password).",
        "no": "Root SSH login disabled (permitrootlogin=no).",
    }
    return {
        "ok": True,
        "applied": root,
        "ssh": after,
        "message": labels.get(root, f"PermitRootLogin set to {root}."),
    }


def add_ssh_authorized_key(public_key: str) -> dict:
    """Append a public key to root authorized_keys."""
    raw = str(public_key or "").strip()
    if not raw:
        raise ValueError("public_key is required")
    # Allow pasting multi-line; keep first key-looking line.
    line = ""
    for candidate in raw.splitlines():
        s = candidate.strip()
        if _security_is_authorized_key_line(s):
            line = s
            break
    if not line:
        raise ValueError("Not a valid SSH public key line")
    if len(line) > 8192:
        raise ValueError("public key too long")

    SSH_ROOT_AUTHORIZED_KEYS.parent.mkdir(parents=True, exist_ok=True)
    existing = ""
    if SSH_ROOT_AUTHORIZED_KEYS.is_file():
        existing = SSH_ROOT_AUTHORIZED_KEYS.read_text(encoding="utf-8", errors="replace")
    for raw_line in existing.splitlines():
        if raw_line.strip() == line:
            return {
                "ok": True,
                "added": False,
                "message": "Key already present.",
                "ssh": _security_sshd_config(),
            }
    with SSH_ROOT_AUTHORIZED_KEYS.open("a", encoding="utf-8") as fh:
        if existing and not existing.endswith("\n"):
            fh.write("\n")
        fh.write(line + "\n")
    try:
        os.chmod(SSH_ROOT_AUTHORIZED_KEYS, 0o600)
        os.chmod(SSH_ROOT_AUTHORIZED_KEYS.parent, 0o700)
    except OSError:
        pass
    return {
        "ok": True,
        "added": True,
        "message": "SSH public key added for root.",
        "ssh": _security_sshd_config(),
    }


def remove_ssh_authorized_key(*, index: int | None = None, fingerprint: str | None = None) -> dict:
    """Remove one root authorized key by 1-based index or fingerprint."""
    keys = _security_list_authorized_keys()
    if not keys:
        raise ValueError("No authorized keys to remove")
    target_idx = None
    if index is not None:
        try:
            target_idx = int(index)
        except (TypeError, ValueError) as exc:
            raise ValueError("index must be an integer") from exc
    elif fingerprint:
        fp = str(fingerprint).strip()
        for row in keys:
            if row.get("fingerprint") == fp or fp in str(row.get("fingerprint") or ""):
                target_idx = int(row["index"])
                break
        if target_idx is None:
            raise ValueError("fingerprint not found")
    else:
        raise ValueError("index or fingerprint is required")

    if target_idx < 1 or target_idx > len(keys):
        raise ValueError(f"index out of range (1..{len(keys)})")

    ssh = _security_sshd_config()
    if (
        ssh.get("login_method") == "keys_only"
        and str(ssh.get("root_login_mode") or "") != "no"
        and len(keys) <= 1
    ):
        raise ValueError(
            "Refusing to remove the last root key while keys-only root login is enabled."
        )

    try:
        text = SSH_ROOT_AUTHORIZED_KEYS.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ValueError(f"cannot read authorized_keys: {exc}") from exc
    out_lines: list[str] = []
    seen = 0
    removed_line = ""
    for raw in text.splitlines():
        if _security_is_authorized_key_line(raw):
            seen += 1
            if seen == target_idx:
                removed_line = raw.strip()
                continue
        out_lines.append(raw.rstrip("\n"))
    if not removed_line:
        raise ValueError("key not found")
    new_text = "\n".join(out_lines)
    if new_text and not new_text.endswith("\n"):
        new_text += "\n"
    SSH_ROOT_AUTHORIZED_KEYS.write_text(new_text, encoding="utf-8")
    try:
        os.chmod(SSH_ROOT_AUTHORIZED_KEYS, 0o600)
    except OSError:
        pass
    return {
        "ok": True,
        "removed": True,
        "index": target_idx,
        "message": f"Removed key #{target_idx}.",
        "ssh": _security_sshd_config(),
    }


def _security_list_login_users() -> list[dict]:
    """Human login-capable local users (uid >= 1000) for the Security panel."""
    out: list[dict] = []
    try:
        text = Path("/etc/passwd").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    skip_shells = {
        "/usr/sbin/nologin",
        "/sbin/nologin",
        "/bin/false",
        "/usr/bin/false",
        "/bin/sync",
    }
    for raw in text.splitlines():
        parts = raw.split(":")
        if len(parts) < 7:
            continue
        name, _pw, uid_s, _gid, gecos, home, shell = parts[:7]
        try:
            uid = int(uid_s)
        except ValueError:
            continue
        if uid < 1000 or uid >= 65534:
            continue
        shell_n = (shell or "").strip() or "/bin/sh"
        login_ok = shell_n not in skip_shells
        groups: list[str] = []
        gproc = _security_run(["id", "-nG", name], timeout=4)
        if gproc.returncode == 0:
            groups = [g for g in (gproc.stdout or "").split() if g]
        key_path = Path(home) / ".ssh" / "authorized_keys"
        key_count = _security_authorized_key_count(key_path) if key_path.is_file() else 0
        out.append(
            {
                "username": name,
                "uid": uid,
                "home": home,
                "shell": shell_n,
                "login_enabled": login_ok,
                # Only real privilege groups — not a primary group that happens to be named admin.
                "sudo": any(g in {"sudo", "wheel"} for g in groups),
                "groups": groups[:12],
                "authorized_keys": key_count,
            }
        )
    out.sort(key=lambda r: (0 if r.get("login_enabled") else 1, r.get("username") or ""))
    return out


def _validate_linux_username(username: str) -> str:
    name = str(username or "").strip().lower()
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", name):
        raise ValueError(
            "username must be 1–32 chars: start with a-z/_, then a-z 0-9 _ -"
        )
    reserved = {
        "root",
        "daemon",
        "bin",
        "sys",
        "sync",
        "games",
        "man",
        "mail",
        "news",
        "www-data",
        "nobody",
        "systemd-network",
        "messagebus",
        "sshd",
        "ubuntu",
    }
    if name in reserved:
        raise ValueError(f"username {name!r} is reserved")
    # Reject if already in passwd
    try:
        for raw in Path("/etc/passwd").read_text(encoding="utf-8", errors="replace").splitlines():
            if raw.split(":", 1)[0] == name:
                raise ValueError(f"user {name!r} already exists")
    except ValueError:
        raise
    except OSError:
        pass
    return name


def _authorized_keys_path_for_user(username: str) -> Path:
    if username == "root":
        return SSH_ROOT_AUTHORIZED_KEYS
    try:
        import pwd

        home = pwd.getpwnam(username).pw_dir
    except (KeyError, ImportError) as exc:
        raise ValueError(f"user {username!r} not found") from exc
    return Path(home) / ".ssh" / "authorized_keys"


def _install_authorized_key_line(path: Path, line: str, *, owner: str | None = None) -> bool:
    """Append pubkey line; return True if newly added."""
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = ""
    if path.is_file():
        existing = path.read_text(encoding="utf-8", errors="replace")
        for raw in existing.splitlines():
            if raw.strip() == line:
                return False
    with path.open("a", encoding="utf-8") as fh:
        if existing and not existing.endswith("\n"):
            fh.write("\n")
        fh.write(line + "\n")
    try:
        os.chmod(path.parent, 0o700)
        os.chmod(path, 0o600)
    except OSError:
        pass
    if owner and owner != "root":
        _security_run(["chown", "-R", f"{owner}:{owner}", str(path.parent)], timeout=8)
    return True


def _generate_ed25519_keypair(comment: str) -> dict:
    """Create a temporary ed25519 keypair; private key is returned and temp files removed."""
    import tempfile

    comment = (comment or "servermanager").strip()[:80] or "servermanager"
    tmp_dir = tempfile.mkdtemp(prefix="sm-sshkey-")
    priv_path = Path(tmp_dir) / "id_ed25519"
    pub_path = Path(str(priv_path) + ".pub")
    try:
        proc = _security_run(
            [
                "ssh-keygen",
                "-t",
                "ed25519",
                "-f",
                str(priv_path),
                "-N",
                "",
                "-C",
                comment,
                "-q",
            ],
            timeout=15,
        )
        if proc.returncode != 0 or not priv_path.is_file() or not pub_path.is_file():
            err = (proc.stderr or proc.stdout or "ssh-keygen failed")[:300]
            raise ValueError(err)
        private_key = priv_path.read_text(encoding="utf-8")
        public_key = pub_path.read_text(encoding="utf-8").strip()
        fp_proc = _security_run(["ssh-keygen", "-lf", str(pub_path)], timeout=6)
        fingerprint = ""
        if fp_proc.returncode == 0 and (fp_proc.stdout or "").strip():
            parts = (fp_proc.stdout or "").split()
            if len(parts) >= 2:
                fingerprint = parts[1]
        return {
            "private_key": private_key,
            "public_key": public_key,
            "fingerprint": fingerprint,
            "comment": comment,
            "type": "ed25519",
            "filename": "id_ed25519",
        }
    finally:
        for p in (priv_path, pub_path):
            try:
                p.unlink(missing_ok=True)
            except OSError:
                pass
        try:
            os.rmdir(tmp_dir)
        except OSError:
            pass


def generate_ssh_authorized_key(
    *,
    comment: str = "",
    username: str = "root",
    also_root: bool = False,
) -> dict:
    """Auto-create an SSH keypair, install the public key, return private key once."""
    user = str(username or "root").strip() or "root"
    if user != "root":
        if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user):
            raise ValueError("invalid username")
        try:
            import pwd

            pwd.getpwnam(user)
        except KeyError as exc:
            raise ValueError(f"user {user!r} not found") from exc
    cmt = (comment or f"servermanager-{user}-{int(time.time())}").strip()
    keypair = _generate_ed25519_keypair(cmt)
    path = _authorized_keys_path_for_user(user)
    added = _install_authorized_key_line(
        path, keypair["public_key"], owner=None if user == "root" else user
    )
    if also_root and user != "root":
        _install_authorized_key_line(SSH_ROOT_AUTHORIZED_KEYS, keypair["public_key"])
    return {
        "ok": True,
        "generated": True,
        "added": added,
        "username": user,
        "private_key": keypair["private_key"],
        "public_key": keypair["public_key"],
        "fingerprint": keypair["fingerprint"],
        "comment": keypair["comment"],
        "filename": f"id_ed25519_{user}",
        "message": (
            f"Created ed25519 key for {user}. Download the private key now — "
            "it is not stored on the VPS."
        ),
        "ssh": _security_sshd_config(),
    }


def create_ssh_login_user(
    username: str,
    *,
    sudo: bool = True,
    generate_key: bool = True,
    public_key: str = "",
    comment: str = "",
    also_root: bool = False,
) -> dict:
    """Create a login-capable Linux user, optionally with sudo and an SSH key."""
    name = _validate_linux_username(username)
    # Prefer adduser on Debian/Ubuntu when available.
    if Path("/usr/sbin/adduser").is_file():
        proc = _security_run(
            [
                "adduser",
                "--disabled-password",
                "--gecos",
                name,
                "--shell",
                "/bin/bash",
                name,
            ],
            timeout=60,
        )
    else:
        proc = _security_run(
            ["useradd", "-m", "-s", "/bin/bash", name],
            timeout=60,
        )
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "user create failed")[:400]
        raise ValueError(err)

    if sudo:
        for grp in ("sudo", "admin"):
            g = _security_run(["getent", "group", grp], timeout=4)
            if g.returncode == 0:
                _security_run(["usermod", "-aG", grp, name], timeout=10)
                break

    key_info = None
    pub = str(public_key or "").strip()
    if generate_key:
        key_info = generate_ssh_authorized_key(
            comment=comment or f"{name}@vps",
            username=name,
            also_root=also_root,
        )
    elif pub:
        line = ""
        for candidate in pub.splitlines():
            s = candidate.strip()
            if _security_is_authorized_key_line(s):
                line = s
                break
        if not line:
            raise ValueError("Not a valid SSH public key line")
        path = _authorized_keys_path_for_user(name)
        _install_authorized_key_line(path, line, owner=name)
        if also_root:
            _install_authorized_key_line(SSH_ROOT_AUTHORIZED_KEYS, line)

    users = _security_list_login_users()
    created = next((u for u in users if u.get("username") == name), None)
    result = {
        "ok": True,
        "created": True,
        "username": name,
        "sudo": bool(sudo),
        "user": created,
        "login_users": users,
        "ssh": _security_sshd_config(),
        "message": f"Created user {name}"
        + (" with sudo" if sudo else "")
        + (" and SSH key" if key_info else "")
        + ".",
    }
    if key_info:
        result.update(
            {
                "private_key": key_info.get("private_key"),
                "public_key": key_info.get("public_key"),
                "fingerprint": key_info.get("fingerprint"),
                "filename": key_info.get("filename") or f"id_ed25519_{name}",
                "key_message": key_info.get("message"),
            }
        )
    return result


def _security_fail2ban() -> dict:
    status = _security_run(["fail2ban-client", "status"], timeout=6)
    sshd = _security_run(["fail2ban-client", "status", "sshd"], timeout=6)
    banip = _security_run(["fail2ban-client", "get", "sshd", "banip"], timeout=6)
    active = status.returncode == 0
    jails: list[str] = []
    if active:
        for line in (status.stdout or "").splitlines():
            if "Jail list:" in line:
                jails = [j.strip() for j in line.split(":", 1)[-1].split(",") if j.strip()]
    banned: list[str] = []
    if banip.returncode == 0 and (banip.stdout or "").strip():
        banned = [x.strip() for x in (banip.stdout or "").split() if x.strip()]
    currently_banned = 0
    total_banned = 0
    total_failed = 0
    currently_failed = 0
    if sshd.returncode == 0:
        for line in (sshd.stdout or "").splitlines():
            s = line.strip()
            if s.startswith("Currently banned:"):
                try:
                    currently_banned = int(s.split(":", 1)[1].strip())
                except ValueError:
                    pass
            elif s.startswith("Total banned:"):
                try:
                    total_banned = int(s.split(":", 1)[1].strip())
                except ValueError:
                    pass
            elif s.startswith("Currently failed:"):
                try:
                    currently_failed = int(s.split(":", 1)[1].strip())
                except ValueError:
                    pass
            elif s.startswith("Total failed:"):
                try:
                    total_failed = int(s.split(":", 1)[1].strip())
                except ValueError:
                    pass
            elif "Banned IP list:" in s and not banned:
                banned = [x.strip() for x in s.split(":", 1)[-1].split() if x.strip()]
    return {
        "ok": active,
        "active": active,
        "jails": jails,
        "sshd": {
            "currently_banned": currently_banned or len(banned),
            "total_banned": total_banned,
            "currently_failed": currently_failed,
            "total_failed": total_failed,
            "banned_ips": banned,
        },
        "error": None
        if active
        else ((status.stderr or status.stdout or "fail2ban inactive")[:240]),
    }


def _security_attacker_stats(banned_ips: list[str]) -> dict:
    """One journal pass: top attackers + per-banned-IP attempt breakdown."""
    banned_set = {ip.strip() for ip in banned_ips if ip.strip()}
    proc = _security_run(
        [
            "journalctl",
            "-u",
            "ssh",
            "--since",
            "7 days ago",
            "--no-pager",
            "-o",
            "cat",
        ],
        timeout=25,
    )
    top: dict[str, int] = {}
    by_banned: dict[str, dict] = {
        ip: {
            "ip": ip,
            "failed_password": 0,
            "invalid_user": 0,
            "users": {},
            "last_seen": "",
        }
        for ip in banned_set
    }
    if proc.returncode != 0:
        return {
            "ok": False,
            "error": (proc.stderr or "journalctl failed")[:240],
            "top_attackers": [],
            "banned_details": list(by_banned.values()),
            "window": "7d",
        }

    failed_re = re.compile(
        r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"
    )
    invalid_re = re.compile(r"Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)")
    for line in (proc.stdout or "").splitlines():
        m = failed_re.search(line)
        if m:
            user, ip = m.group(1), m.group(2)
            top[ip] = top.get(ip, 0) + 1
            if ip in by_banned:
                row = by_banned[ip]
                row["failed_password"] += 1
                row["users"][user] = row["users"].get(user, 0) + 1
                row["last_seen"] = line[:80]
            continue
        m = invalid_re.search(line)
        if m:
            user, ip = m.group(1), m.group(2)
            top[ip] = top.get(ip, 0) + 1
            if ip in by_banned:
                row = by_banned[ip]
                row["invalid_user"] += 1
                row["users"][user] = row["users"].get(user, 0) + 1
                row["last_seen"] = line[:80]

    top_list = [
        {"ip": ip, "attempts": n}
        for ip, n in sorted(top.items(), key=lambda kv: kv[1], reverse=True)[:20]
    ]
    banned_details = []
    for ip in banned_ips:
        row = by_banned.get(ip) or {
            "ip": ip,
            "failed_password": 0,
            "invalid_user": 0,
            "users": {},
            "last_seen": "",
        }
        users_sorted = sorted(
            [{"user": u, "count": c} for u, c in row["users"].items()],
            key=lambda x: x["count"],
            reverse=True,
        )[:15]
        banned_details.append(
            {
                "ip": ip,
                "failed_password": row["failed_password"],
                "invalid_user": row["invalid_user"],
                "attempts": int(row["failed_password"]) + int(row["invalid_user"]),
                "users": users_sorted,
                "last_seen": row.get("last_seen") or "",
            }
        )
    return {
        "ok": True,
        "window": "7d",
        "top_attackers": top_list,
        "banned_details": banned_details,
    }


def _security_listeners_and_ufw() -> tuple[list[dict], dict]:
    """Return public listeners of interest + UFW risk rules."""
    watch = {
        22,
        80,
        443,
        445,
        139,
        2121,
        1445,
        3016,
        5000,
        5001,
        5002,
        3389,
        4000,
        8080,
        2222,
        8443,
        25,
        465,
        587,
        993,
    }
    ss = _security_run(["ss", "-lntH"], timeout=6)
    listeners: list[dict] = []
    seen: set[tuple[str, int]] = set()
    for line in (ss.stdout or "").splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[3]
        if local.count(":") < 1:
            continue
        host, _, port_s = local.rpartition(":")
        try:
            port = int(port_s)
        except ValueError:
            continue
        if port not in watch:
            continue
        public = host in ("0.0.0.0", "*", "[::]", "::")
        key = (host, port)
        if key in seen:
            continue
        seen.add(key)
        listeners.append(
            {
                "addr": host,
                "port": port,
                "public_bind": public,
            }
        )

    fw = read_firewall_state()
    risky_allows: list[dict] = []
    vpn_only_ports: set[int] = set()
    for r in fw.get("rules") or []:
        try:
            port_i = int(r.get("port") or 0)
        except (TypeError, ValueError):
            port_i = 0
        if r.get("vpn_only") and port_i:
            vpn_only_ports.add(port_i)
        if r.get("locked"):
            continue
        if r.get("vpn_only"):
            continue
        if str(r.get("from") or "").lower().startswith("anywhere"):
            risky_allows.append(
                {
                    "port": r.get("port"),
                    "proto": r.get("proto"),
                    "comment": r.get("comment") or "",
                    "id": r.get("id"),
                }
            )
    return listeners, {
        "active": bool(fw.get("active")),
        "default_incoming": fw.get("default_incoming"),
        "risky_public_allows": risky_allows,
        "vpn_only_ports": sorted(vpn_only_ports),
        "rule_count": len(fw.get("rules") or []),
        "error": fw.get("error"),
    }


def _security_probe_ports(ports: list[int]) -> list[dict]:
    """Best-effort connect to VPS public IP (external reachability approx)."""
    import socket

    host = (os.environ.get("VPS_PUBLIC_IP") or "").strip() or "127.0.0.1"
    out: list[dict] = []
    for port in ports:
        open_ = False
        err = ""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.2)
            open_ = s.connect_ex((host, int(port))) == 0
            s.close()
        except Exception as exc:
            err = str(exc)[:120]
        out.append({"host": host, "port": int(port), "open": open_, "error": err})
    return out


def _security_file_checks() -> list[dict]:
    checks: list[dict] = []
    targets = [
        ("/opt/wireguard/port-forward-ui.env", 0o600, True),
        ("/opt/grafana/.env", 0o600, False),
        ("/opt/wireguard/.env", 0o600, False),
        ("/opt/truemail/config/ssl/key.pem", 0o600, False),
        ("/opt/truemail/.env", 0o600, False),
        ("/opt/wireguard/nas-smb-gateway/credentials", 0o600, False),
    ]
    for path, want_mode, required in targets:
        p = Path(path)
        if not p.exists():
            if required:
                checks.append(
                    {
                        "path": path,
                        "ok": False,
                        "severity": "medium",
                        "detail": "missing",
                    }
                )
            continue
        try:
            mode = p.stat().st_mode & 0o777
        except OSError as exc:
            checks.append(
                {
                    "path": path,
                    "ok": False,
                    "severity": "medium",
                    "detail": str(exc)[:120],
                }
            )
            continue
        world_w = bool(mode & 0o002)
        world_r = bool(mode & 0o004)
        group_r = bool(mode & 0o040)
        ok = mode <= want_mode and not world_w and not world_r
        sev = "ok"
        detail = f"mode {mode:03o}"
        if world_w:
            sev = "high"
            detail += " (world-writable)"
        elif world_r or (group_r and want_mode <= 0o600):
            sev = "medium"
            detail += " (overly readable)"
        elif not ok:
            sev = "low"
        checks.append(
            {
                "path": path,
                "ok": ok and sev == "ok",
                "severity": sev if not ok or sev != "ok" else "ok",
                "mode": f"{mode:03o}",
                "detail": detail,
            }
        )
    return checks


def _security_domain_exposure() -> list[dict]:
    sensitive = {
        "router.vpstruelord.com",
        "buffalo.vpstruelord.com",
        "files.vpstruelord.com",
        "proxmox.vpstruelord.com",
        "plex.vpstruelord.com",
        "grafana.vpstruelord.com",
        "pihole.vpstruelord.com",
        "dns.vpstruelord.com",
    }
    try:
        state = read_hookups_state()
        rules = state.get("rules") or []
    except Exception:
        rules = []
    out: list[dict] = []
    for r in rules:
        domain = str(r.get("domain") or "").strip().lower()
        if not domain:
            continue
        if domain not in sensitive and not r.get("enabled", True):
            continue
        if domain not in sensitive:
            continue
        out.append(
            {
                "domain": domain,
                "name": r.get("name") or "",
                "enabled": bool(r.get("enabled", True)),
                "vpn_only": bool(r.get("vpn_only")),
                "target": f"{r.get('target_host')}:{r.get('target_port')}",
                "risk": "ok" if r.get("vpn_only") else "high",
            }
        )
    return out


def build_security_status() -> dict:
    """Live security dashboard for the portal Security tab."""
    findings: list[dict] = []
    f2b = _security_fail2ban()
    ssh = _security_sshd_config()
    listeners, ufw = _security_listeners_and_ufw()
    files = _security_file_checks()
    domains = _security_domain_exposure()
    banned = list((f2b.get("sshd") or {}).get("banned_ips") or [])
    attackers = _security_attacker_stats(banned)

    # WAN probes for high-interest ports
    probe_ports = [22, 2121, 3016, 5000, 5001, 5002, 1445, 445, 3389, 4000, 8080, 2222, 8084]
    probes = _security_probe_ports(probe_ports)
    open_map = {p["port"]: p["open"] for p in probes}

    if not f2b.get("active"):
        findings.append(
            {
                "severity": "high",
                "title": "fail2ban not active",
                "detail": f2b.get("error") or "sshd jail missing",
            }
        )
    if ssh.get("password_authentication") in ("yes", "true"):
        findings.append(
            {
                "severity": "high",
                "title": "SSH password login enabled",
                "detail": "Switch VPS login method to SSH keys only in the Security tab.",
            }
        )
    if ssh.get("permit_root_login") in ("yes", "prohibit-password", "without-password"):
        if ssh.get("permit_root_login") == "yes":
            findings.append(
                {
                    "severity": "high",
                    "title": "SSH root login with password allowed",
                    "detail": (
                        f"permitrootlogin={ssh.get('permit_root_login')}. "
                        "Use Security → VPS login method → SSH keys only."
                    ),
                }
            )
        else:
            findings.append(
                {
                    "severity": "medium",
                    "title": "SSH root login allowed",
                    "detail": (
                        f"permitrootlogin={ssh.get('permit_root_login')}. "
                        "Manage under Security → VPS login method "
                        "(root keys only, or disable root SSH)."
                    ),
                }
            )
    if (
        ssh.get("login_method") == "keys_only"
        and int(ssh.get("root_authorized_keys") or 0) < 1
    ):
        findings.append(
            {
                "severity": "high",
                "title": "Keys-only login with no root authorized_keys",
                "detail": "Add a key to /root/.ssh/authorized_keys or re-enable password login.",
            }
        )

    exposure_labels = {
        2121: "NAS FTP gateway",
        3016: "Grafana (should be 127.0.0.1 only)",
        5000: "remote-desktop HTTP (TCP; WG tunnel is UDP)",
        5001: "WireGuard Easy UI",
        5002: "Portal cleartext HTTP",
        1445: "NAS SMB gateway",
        445: "Samba/SMB",
        3389: "RDP forward",
        4000: "Windows RDP forward",
        8080: "Flint HTTP forward",
        2222: "Flint SSH forward",
        8084: "LAN HTTP forward",
    }
    vpn_only_ports: set[int] = set()
    for p in ufw.get("vpn_only_ports") or []:
        try:
            vpn_only_ports.add(int(p))
        except (TypeError, ValueError):
            continue
    exposures: list[dict] = []
    for port, label in exposure_labels.items():
        listening_public = any(
            L.get("port") == port and L.get("public_bind") for L in listeners
        )
        ufw_open = any(int(r.get("port") or 0) == port for r in ufw.get("risky_public_allows") or [])
        wan_open = bool(open_map.get(port))
        vpn_scoped = port in vpn_only_ports and not ufw_open
        # Prefer UFW+listener as authority; raw connect can false-positive via hairpin.
        severity = "ok"
        if vpn_scoped:
            # Explicit LAN/VPN UFW allows — public Internet denied by default deny.
            severity = "ok"
        elif ufw_open and (listening_public or wan_open):
            severity = "high"
        elif listening_public and wan_open and port in (3016,):
            # Exclude VPN-scoped admin ports: hairpin to public IP looks "open".
            severity = "high"
        elif listening_public and port in (3016,):
            severity = "high"
        elif listening_public or ufw_open or wan_open:
            severity = "medium"
        exposures.append(
            {
                "port": port,
                "label": label,
                "listening_public": listening_public,
                "ufw_anywhere": ufw_open,
                "wan_open": wan_open,
                "vpn_only": vpn_scoped,
                "severity": severity,
            }
        )
        if severity == "high":
            findings.append(
                {
                    "severity": "high",
                    "title": f"{label} exposed on :{port}",
                    "detail": "Close UFW or bind localhost / VPN-only.",
                }
            )
        elif severity == "medium":
            findings.append(
                {
                    "severity": "medium",
                    "title": f"{label} partially exposed (:{port})",
                    "detail": "Listener or UFW allow present; confirm WAN path.",
                }
            )

    for d in domains:
        if d.get("risk") == "high" and d.get("enabled"):
            findings.append(
                {
                    "severity": "medium",
                    "title": f"{d['domain']} is public (not VPN-only)",
                    "detail": f"Upstream {d.get('target')}",
                }
            )

    for f in files:
        if f.get("severity") in ("high", "medium"):
            findings.append(
                {
                    "severity": f["severity"],
                    "title": f"Weak permissions: {f['path']}",
                    "detail": f.get("detail") or "",
                }
            )

    # Kernel reboot pending (needrestart), best-effort
    kernel = {"ok": True, "detail": ""}
    nr = _security_run(["needrestart", "-b"], timeout=8)
    if nr.returncode == 0 and "NEEDRESTART-KSTA: 3" in (nr.stdout or ""):
        kernel = {"ok": False, "detail": "Kernel update pending reboot"}
        findings.append(
            {
                "severity": "low",
                "title": "Kernel update pending reboot",
                "detail": "needrestart reports a newer kernel is installed",
            }
        )

    sev_rank = {"high": 0, "medium": 1, "low": 2, "ok": 3}
    findings.sort(key=lambda x: sev_rank.get(str(x.get("severity")), 9))
    counts = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        k = str(f.get("severity") or "")
        if k in counts:
            counts[k] += 1

    score = 100
    score -= counts["high"] * 18
    score -= counts["medium"] * 8
    score -= counts["low"] * 3
    if score < 0:
        score = 0
    if counts["high"]:
        grade = "at risk"
    elif counts["medium"]:
        grade = "needs attention"
    else:
        grade = "good"

    return {
        "ok": True,
        "score": score,
        "grade": grade,
        "counts": counts,
        "findings": findings[:40],
        "fail2ban": f2b,
        "attackers": attackers,
        "ssh": ssh,
        "firewall": ufw,
        "listeners": listeners,
        "exposures": exposures,
        "domains": domains,
        "files": files,
        "kernel": kernel,
        "probes": probes,
        "vpn_allowlist": build_vpn_allowlist_status(),
        "generated_at": int(time.time()),
    }



BACKUP_ROOT = Path("/opt/servermanager-backup")
BACKUP_SCRIPT = BACKUP_ROOT / "sm-backup.sh"
BACKUP_SECRETS = BACKUP_ROOT / "secrets.env"
BACKUP_LOG = BACKUP_ROOT / "backup.log"
BACKUP_LOCK = BACKUP_ROOT / "run.lock"


def _parse_env_file(path: Path) -> dict[str, str]:
    """Parse KEY=value / KEY='quoted' / bash-%q style env files (no token logging)."""
    import shlex

    out: dict[str, str] = {}
    for raw in _read_text(str(path)).splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip()
        if not key:
            continue
        try:
            parts = shlex.split(val, posix=True)
            val = parts[0] if parts else val
        except Exception:
            if (val.startswith('"') and val.endswith('"')) or (
                val.startswith("'") and val.endswith("'")
            ):
                val = val[1:-1]
            else:
                val = val.replace("\\ ", " ")
        out[key] = val
    return out


def _backup_running() -> bool:
    if not BACKUP_LOCK.is_file():
        return False
    try:
        pid = int(_read_text(str(BACKUP_LOCK)).strip().splitlines()[0])
        os.kill(pid, 0)
        return True
    except Exception:
        try:
            BACKUP_LOCK.unlink(missing_ok=True)
        except Exception:
            pass
        return False


PORTAL_ENV_PATH = Path(
    os.environ.get("PORTAL_ENV_FILE", "/opt/wireguard/port-forward-ui.env")
)


def _env_quote(value: str) -> str:
    """Quote a value for KEY=value env files (safe for special chars)."""
    return "'" + str(value).replace("'", "'\"'\"'") + "'"


def _upsert_env_file(path: Path, updates: dict[str, str]) -> None:
    """Update or append KEY=value lines in an EnvironmentFile."""
    if not updates:
        return
    path = Path(path)
    existing = path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""
    lines = existing.splitlines()
    seen: set[str] = set()
    out: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key in updates:
                out.append(f"{key}={_env_quote(updates[key])}")
                seen.add(key)
                continue
        out.append(line)
    for key, val in updates.items():
        if key not in seen:
            out.append(f"{key}={_env_quote(val)}")
    text = "\n".join(out).rstrip() + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    # Preserve mode when possible.
    mode = 0o600
    try:
        mode = path.stat().st_mode & 0o777
    except Exception:
        pass
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.chmod(tmp, mode)
    tmp.replace(path)


def proxmox_ssh(remote_cmd: str, timeout: int = 20) -> subprocess.CompletedProcess:
    """Run a command on the Proxmox host over SSH (key auth)."""
    cmd = [
        "ssh",
        "-i",
        PROXMOX_SSH_KEY,
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "ConnectTimeout=8",
        f"{PROXMOX_SSH_USER}@{PROXMOX_SSH_HOST}",
        remote_cmd,
    ]
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _parse_led_status_line(out: str) -> tuple[str, str]:
    state = "unknown"
    device = ""
    for tok in out.replace("\n", " ").split():
        if tok.startswith("state="):
            state = tok.split("=", 1)[1].strip() or state
        if tok.startswith("device="):
            device = tok.split("=", 1)[1].strip()
    return state, device


def _leds_schedule() -> dict:
    return {
        "timezone": "America/New_York",
        "on": "07:00",
        "off": "22:00",
        "label": "On 7:00 AM · Off 10:00 PM (Eastern)",
    }


def _leds_payload(
    *,
    ok: bool,
    state: str,
    owner: str,
    device: str = "",
    error: str | None = None,
    owner_detail: str | None = None,
    hint: str | None = None,
) -> dict:
    schedule = _leds_schedule()
    if hint is None:
        if owner == "windows":
            hint = (
                "Full motherboard lighting is in Windows VM "
                f"{PROXMOX_LED_WINDOWS_VMID} "
                "(AW-ELC USB + host alienware-wmi released). "
                "Set effects in Alienware FX Lighting / AWCC, then tell me when to "
                "copy them back — or click Return to host."
            )
        else:
            hint = (
                "Portal controls chassis lighting on the Proxmox host. "
                "Spectrum keeps every zone the same color while cycling the rainbow."
            )
    return {
        "ok": ok,
        "state": state,
        "owner": owner,
        "device": device,
        "windows_vmid": PROXMOX_LED_WINDOWS_VMID,
        "schedule": schedule,
        "host": PROXMOX_SSH_HOST,
        "hint": hint,
        "error": error,
        "owner_detail": owner_detail,
    }


def _parse_led_owner(out: str) -> dict:
    owner = "unknown"
    vmid = PROXMOX_LED_WINDOWS_VMID
    host_usb = None
    vm_usb = None
    for tok in out.replace("\n", " ").split():
        if tok.startswith("owner="):
            owner = tok.split("=", 1)[1].strip() or owner
        elif tok.startswith("vmid="):
            vmid = tok.split("=", 1)[1].strip() or vmid
        elif tok.startswith("host_usb="):
            host_usb = tok.split("=", 1)[1].strip() == "1"
        elif tok.startswith("vm_usb="):
            vm_usb = tok.split("=", 1)[1].strip() == "1"
    return {
        "owner": owner,
        "windows_vmid": vmid,
        "host_usb": host_usb,
        "vm_usb": vm_usb,
    }


# LED USB blackout / spectrum can take ~15–30s. Stacked 20s SSH calls made the
# Spectrum/Off switch fail with Unavailable even when the host command succeeded.
_LEDS_SSH_TIMEOUT = 90


def _leds_ssh(remote_cmd: str) -> subprocess.CompletedProcess:
    """SSH helper for LED control with a longer command budget."""
    return proxmox_ssh(remote_cmd, timeout=_LEDS_SSH_TIMEOUT)


def _leds_ssh_out(proc: subprocess.CompletedProcess) -> str:
    return ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()


def _leds_from_combined_out(out: str, *, require_state: bool = True) -> dict:
    """Build a portal LED payload from one SSH session's stdout/stderr."""
    owner_info = _parse_led_owner(out)
    owner = str(owner_info.get("owner") or "unknown")
    vmid = str(owner_info.get("windows_vmid") or PROXMOX_LED_WINDOWS_VMID)
    if owner == "windows":
        payload = _leds_payload(
            ok=True,
            state="windows",
            owner="windows",
            device="",
            owner_detail=out,
        )
        payload["windows_vmid"] = vmid
        return payload

    state, device = _parse_led_status_line(out)
    ok = (not require_state) or state in ("on", "off", "rainbow")
    # Prefer last-known on/off even if hidraw is missing (device=missing).
    if state in ("on", "off", "rainbow"):
        ok = True
    payload = _leds_payload(
        ok=ok,
        state=state if state in ("on", "off", "rainbow", "windows") else "unknown",
        owner=owner if owner in ("host", "windows") else ("host" if ok else "unknown"),
        device=device,
        error=None if ok else (out or "LED status unavailable"),
        owner_detail=out,
    )
    payload["windows_vmid"] = vmid
    return payload


def leds_owner_status() -> dict:
    """Who currently owns the AW-ELC USB: host (portal) or windows (FX Lighting)."""
    try:
        proc = _leds_ssh(f"{PROXMOX_LED_OWNER_CMD} status")
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "owner": "unknown",
            "windows_vmid": PROXMOX_LED_WINDOWS_VMID,
            "detail": "",
            "error": "SSH to Proxmox timed out while reading LED owner",
        }
    out = _leds_ssh_out(proc)
    info = _parse_led_owner(out)
    info["ok"] = proc.returncode == 0 and info.get("owner") in ("host", "windows")
    info["detail"] = out
    if proc.returncode != 0 and not info.get("owner"):
        info["error"] = out or f"owner status failed ({proc.returncode})"
    return info


def leds_status() -> dict:
    """Read Alienware/PC chassis LED state from the Proxmox host (one SSH)."""
    # Skip LED status when Windows owns USB — hidraw is gone from the host.
    remote = (
        f'o=$({PROXMOX_LED_OWNER_CMD} status 2>&1); echo "$o"; '
        f'case "$o" in *owner=windows*) ;; '
        f'*) {PROXMOX_LED_CMD} status 2>&1 ;; esac'
    )
    try:
        proc = _leds_ssh(remote)
    except subprocess.TimeoutExpired:
        return _leds_payload(
            ok=False,
            state="unknown",
            owner="unknown",
            error="SSH to Proxmox timed out while reading LED status",
        )
    except Exception as exc:
        return _leds_payload(
            ok=False,
            state="unknown",
            owner="unknown",
            error=str(exc),
        )
    return _leds_from_combined_out(_leds_ssh_out(proc))


def leds_set(action: str) -> dict:
    """Set chassis LEDs: on | off | rainbow | auto | windows | host.

    Uses a single SSH session for the action plus status so the portal switch
    does not stack multiple short SSH timeouts.
    """
    act = str(action or "").strip().lower()
    if act in ("windows", "to-windows"):
        remote = (
            f"{PROXMOX_LED_OWNER_CMD} to-windows; ec=$?; "
            f"{PROXMOX_LED_OWNER_CMD} status; "
            f"exit $ec"
        )
        try:
            proc = _leds_ssh(remote)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                "SSH to Proxmox timed out while handing LEDs to Windows"
            ) from exc
        out = _leds_ssh_out(proc)
        if proc.returncode != 0:
            raise RuntimeError(out or f"LED Windows handoff failed ({proc.returncode})")
        st = _leds_from_combined_out(out, require_state=False)
        st["action"] = "windows"
        st["detail"] = out
        return st
    if act in ("host", "to-host"):
        remote = (
            f"{PROXMOX_LED_OWNER_CMD} to-host; ec=$?; "
            f"{PROXMOX_LED_OWNER_CMD} status; "
            f"{PROXMOX_LED_CMD} status; "
            f"exit $ec"
        )
        try:
            proc = _leds_ssh(remote)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                "SSH to Proxmox timed out while reclaiming LEDs for the host"
            ) from exc
        out = _leds_ssh_out(proc)
        if proc.returncode != 0:
            raise RuntimeError(out or f"LED host reclaim failed ({proc.returncode})")
        st = _leds_from_combined_out(out)
        st["action"] = "host"
        st["detail"] = out
        return st
    if act not in ("on", "off", "auto", "rainbow"):
        raise ValueError("action must be on, off, rainbow, auto, windows, or host")
    # Host-side modes need the USB on the Proxmox host — check + set + status
    # in one SSH so Spectrum/Off does not burn the whole timeout on owner alone.
    remote = (
        f'o=$({PROXMOX_LED_OWNER_CMD} status 2>&1); echo "$o"; '
        f'case "$o" in *owner=windows*) '
        f'echo error=windows_owns_usb; exit 2;; esac; '
        f"{PROXMOX_LED_CMD} {act}; ec=$?; "
        f"{PROXMOX_LED_CMD} status; "
        f"exit $ec"
    )
    try:
        proc = _leds_ssh(remote)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"SSH to Proxmox timed out while setting LEDs to {act}"
        ) from exc
    out = _leds_ssh_out(proc)
    if "error=windows_owns_usb" in out or proc.returncode == 2:
        raise RuntimeError(
            "LED controller is in the Windows VM (FX Lighting). "
            "Click Return to host first, or say when to copy FX settings."
        )
    if proc.returncode != 0:
        raise RuntimeError(out or f"led command failed ({proc.returncode})")
    st = _leds_from_combined_out(out)
    st["action"] = act
    st["detail"] = out
    return st


_BT_SSH_TIMEOUT = 60


def _bt_ssh(remote_cmd: str) -> subprocess.CompletedProcess:
    return proxmox_ssh(remote_cmd, timeout=_BT_SSH_TIMEOUT)


def _bt_ssh_out(proc: subprocess.CompletedProcess) -> str:
    return ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()


def _parse_bt_owner(out: str) -> dict:
    owner = "unknown"
    vmid = PROXMOX_BT_WINDOWS_VMID
    host_usb = None
    vm_usb = None
    hci = None
    device = ""
    usb_id = PROXMOX_BT_USB_ID
    for tok in out.replace("\n", " ").split():
        if tok.startswith("owner="):
            owner = tok.split("=", 1)[1].strip() or owner
        elif tok.startswith("vmid="):
            vmid = tok.split("=", 1)[1].strip() or vmid
        elif tok.startswith("host_usb="):
            host_usb = tok.split("=", 1)[1].strip() == "1"
        elif tok.startswith("vm_usb="):
            vm_usb = tok.split("=", 1)[1].strip() == "1"
        elif tok.startswith("hci="):
            hci = tok.split("=", 1)[1].strip() == "1"
        elif tok.startswith("device="):
            device = tok.split("=", 1)[1].strip()
        elif tok.startswith("id="):
            usb_id = tok.split("=", 1)[1].strip() or usb_id
    return {
        "owner": owner,
        "windows_vmid": vmid,
        "host_usb": host_usb,
        "vm_usb": vm_usb,
        "hci": hci,
        "device": device,
        "usb_id": usb_id,
    }


def _bt_payload(
    *,
    ok: bool,
    owner: str,
    device: str = "",
    usb_id: str | None = None,
    error: str | None = None,
    detail: str | None = None,
    hint: str | None = None,
) -> dict:
    if hint is None:
        if owner == "windows":
            hint = (
                f"Bluetooth USB is in Windows VM {PROXMOX_BT_WINDOWS_VMID}. "
                "Pair controllers and headsets in Windows "
                "(Settings → Bluetooth & devices). Use this when gaming / remote over VPN."
            )
        elif owner == "host":
            hint = (
                "Bluetooth is on the Proxmox host. "
                "Click Windows VM to pass the Realtek radio into win11-pro-gpu."
            )
        else:
            hint = "Bluetooth ownership could not be determined on the Proxmox host."
    return {
        "ok": ok,
        "owner": owner,
        "state": owner if owner in ("host", "windows") else "unknown",
        "device": device,
        "usb_id": usb_id or PROXMOX_BT_USB_ID,
        "windows_vmid": PROXMOX_BT_WINDOWS_VMID,
        "host": PROXMOX_SSH_HOST,
        "hint": hint,
        "error": error,
        "detail": detail,
    }


def bluetooth_status() -> dict:
    """Who owns the Realtek Bluetooth USB: host or Windows VM."""
    try:
        proc = _bt_ssh(f"{PROXMOX_BT_OWNER_CMD} status")
    except subprocess.TimeoutExpired:
        return _bt_payload(
            ok=False,
            owner="unknown",
            error="SSH to Proxmox timed out while reading Bluetooth owner",
        )
    except Exception as exc:
        return _bt_payload(ok=False, owner="unknown", error=str(exc))
    out = _bt_ssh_out(proc)
    info = _parse_bt_owner(out)
    owner = str(info.get("owner") or "unknown")
    ok = proc.returncode == 0 and owner in ("host", "windows")
    return _bt_payload(
        ok=ok,
        owner=owner if ok else "unknown",
        device=str(info.get("device") or ""),
        usb_id=str(info.get("usb_id") or PROXMOX_BT_USB_ID),
        error=None if ok else (out or f"Bluetooth status failed ({proc.returncode})"),
        detail=out,
    )


def bluetooth_set(action: str) -> dict:
    """Hand Bluetooth USB to Windows or reclaim for the Proxmox host."""
    act = str(action or "").strip().lower()
    if act in ("windows", "to-windows", "vm"):
        remote = (
            f"{PROXMOX_BT_OWNER_CMD} to-windows; ec=$?; "
            f"{PROXMOX_BT_OWNER_CMD} status; "
            f"exit $ec"
        )
        label = "Windows"
    elif act in ("host", "to-host", "proxmox"):
        remote = (
            f"{PROXMOX_BT_OWNER_CMD} to-host; ec=$?; "
            f"{PROXMOX_BT_OWNER_CMD} status; "
            f"exit $ec"
        )
        label = "host"
    else:
        raise ValueError("action must be windows or host")
    try:
        proc = _bt_ssh(remote)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"SSH to Proxmox timed out while moving Bluetooth to {label}"
        ) from exc
    out = _bt_ssh_out(proc)
    if proc.returncode != 0:
        raise RuntimeError(out or f"Bluetooth {label} handoff failed ({proc.returncode})")
    info = _parse_bt_owner(out)
    owner = str(info.get("owner") or "unknown")
    st = _bt_payload(
        ok=owner in ("host", "windows"),
        owner=owner if owner in ("host", "windows") else "unknown",
        device=str(info.get("device") or ""),
        usb_id=str(info.get("usb_id") or PROXMOX_BT_USB_ID),
        detail=out,
    )
    st["action"] = "windows" if label == "Windows" else "host"
    return st


_XBOX_SSH_TIMEOUT = 60


def _xbox_ssh(remote_cmd: str) -> subprocess.CompletedProcess:
    return proxmox_ssh(remote_cmd, timeout=_XBOX_SSH_TIMEOUT)


def _xbox_ssh_out(proc: subprocess.CompletedProcess) -> str:
    return ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()


def _parse_xbox_owner(out: str) -> dict:
    owner = "unknown"
    vmid = PROXMOX_XBOX_WINDOWS_VMID
    host_usb = None
    vm_usb = None
    device = ""
    usb_id = PROXMOX_XBOX_USB_ID
    for tok in out.replace("\n", " ").split():
        if tok.startswith("owner="):
            owner = tok.split("=", 1)[1].strip() or owner
        elif tok.startswith("vmid="):
            vmid = tok.split("=", 1)[1].strip() or vmid
        elif tok.startswith("host_usb="):
            host_usb = tok.split("=", 1)[1].strip() == "1"
        elif tok.startswith("vm_usb="):
            vm_usb = tok.split("=", 1)[1].strip() == "1"
        elif tok.startswith("device="):
            device = tok.split("=", 1)[1].strip()
        elif tok.startswith("id="):
            usb_id = tok.split("=", 1)[1].strip() or usb_id
    return {
        "owner": owner,
        "windows_vmid": vmid,
        "host_usb": host_usb,
        "vm_usb": vm_usb,
        "device": device,
        "usb_id": usb_id,
    }


def _xbox_payload(
    *,
    ok: bool,
    owner: str,
    device: str = "",
    usb_id: str | None = None,
    error: str | None = None,
    detail: str | None = None,
    hint: str | None = None,
) -> dict:
    if hint is None:
        if owner == "windows":
            hint = (
                f"Xbox USB controller is in Windows VM {PROXMOX_XBOX_WINDOWS_VMID}. "
                "Check Windows Game Controllers (joy.cpl) or Xbox Game Bar. "
                "Keep it plugged into the same USB port on the Proxmox PC."
            )
        elif owner == "host":
            hint = (
                "Xbox controller is on the Proxmox host. "
                "Click Windows VM to pass it into win11-pro-gpu."
            )
        else:
            hint = (
                "Xbox controller not detected — plug it into the Proxmox PC via USB, "
                "then click Windows VM."
            )
    return {
        "ok": ok,
        "owner": owner,
        "state": owner if owner in ("host", "windows") else "unknown",
        "device": device,
        "usb_id": usb_id or PROXMOX_XBOX_USB_ID,
        "windows_vmid": PROXMOX_XBOX_WINDOWS_VMID,
        "host": PROXMOX_SSH_HOST,
        "hint": hint,
        "error": error,
        "detail": detail,
    }


def xbox_status() -> dict:
    """Who owns the Xbox USB controller: host or Windows VM."""
    try:
        proc = _xbox_ssh(f"{PROXMOX_XBOX_OWNER_CMD} status")
    except subprocess.TimeoutExpired:
        return _xbox_payload(
            ok=False,
            owner="unknown",
            error="SSH to Proxmox timed out while reading Xbox controller owner",
        )
    except Exception as exc:
        return _xbox_payload(ok=False, owner="unknown", error=str(exc))
    out = _xbox_ssh_out(proc)
    info = _parse_xbox_owner(out)
    owner = str(info.get("owner") or "unknown")
    ok = proc.returncode == 0 and owner in ("host", "windows")
    return _xbox_payload(
        ok=ok,
        owner=owner if ok else "unknown",
        device=str(info.get("device") or ""),
        usb_id=str(info.get("usb_id") or PROXMOX_XBOX_USB_ID),
        error=None if ok else (out or f"Xbox status failed ({proc.returncode})"),
        detail=out,
    )


def xbox_set(action: str) -> dict:
    """Hand Xbox USB controller to Windows or reclaim for the Proxmox host."""
    act = str(action or "").strip().lower()
    if act in ("windows", "to-windows", "vm"):
        remote = (
            f"{PROXMOX_XBOX_OWNER_CMD} to-windows; ec=$?; "
            f"{PROXMOX_XBOX_OWNER_CMD} status; "
            f"exit $ec"
        )
        label = "Windows"
    elif act in ("host", "to-host", "proxmox"):
        remote = (
            f"{PROXMOX_XBOX_OWNER_CMD} to-host; ec=$?; "
            f"{PROXMOX_XBOX_OWNER_CMD} status; "
            f"exit $ec"
        )
        label = "host"
    else:
        raise ValueError("action must be windows or host")
    try:
        proc = _xbox_ssh(remote)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"SSH to Proxmox timed out while moving Xbox controller to {label}"
        ) from exc
    out = _xbox_ssh_out(proc)
    if proc.returncode != 0:
        raise RuntimeError(out or f"Xbox {label} handoff failed ({proc.returncode})")
    info = _parse_xbox_owner(out)
    owner = str(info.get("owner") or "unknown")
    st = _xbox_payload(
        ok=owner in ("host", "windows"),
        owner=owner if owner in ("host", "windows") else "unknown",
        device=str(info.get("device") or ""),
        usb_id=str(info.get("usb_id") or PROXMOX_XBOX_USB_ID),
        detail=out,
    )
    st["action"] = "windows" if label == "Windows" else "host"
    return st


_ELEMENTS_SSH_TIMEOUT = 120


def _elements_ssh(remote_cmd: str) -> subprocess.CompletedProcess:
    return proxmox_ssh(remote_cmd, timeout=_ELEMENTS_SSH_TIMEOUT)


def _elements_ssh_out(proc: subprocess.CompletedProcess) -> str:
    return ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()


def _parse_elements_status(out: str) -> dict:
    info = {
        "ok": False,
        "present": False,
        "host_mounted": False,
        "ct_mounted": False,
        "ct_readable": False,
        "auto": False,
        "usb_id": "1058:25a3",
        "host_mnt": "/mnt/plex-usb",
        "ct_mnt": "/mnt/usb",
        "ctid": "101",
    }
    for tok in out.replace("\n", " ").split():
        if "=" not in tok:
            continue
        k, v = tok.split("=", 1)
        if k in ("ok", "present", "host_mounted", "ct_mounted", "ct_readable", "auto"):
            info[k] = v in ("1", "true", "True", "yes")
        elif k in ("id", "usb_id"):
            info["usb_id"] = v
        elif k == "host_mnt":
            info["host_mnt"] = v
        elif k == "ct_mnt":
            info["ct_mnt"] = v
        elif k == "ctid":
            info["ctid"] = v
    return info


def _parse_elements_pipeline_status(out: str) -> dict:
    info = {
        "ok": False,
        "mounted": False,
        "inbox_movies": 0,
        "inbox_kids_movies": 0,
        "inbox_tv": 0,
        "inbox_kids_tv": 0,
        "lib_movies": 0,
        "lib_kids_movies": 0,
        "lib_tv": 0,
        "lib_kids_tv": 0,
        "last_ok": False,
        "last_at": "",
        "last_detail": "",
        "host_mnt": "/mnt/plex-usb",
        "folders": {
            "movies": "Movies",
            "kids_movies": "Kids Movies",
            "tvshows": "TV Shows",
            "kids_tvshows": "KIDS TV SHOWS",
        },
    }
    int_keys = (
        "inbox_movies",
        "inbox_kids_movies",
        "inbox_tv",
        "inbox_kids_tv",
        "lib_movies",
        "lib_kids_movies",
        "lib_tv",
        "lib_kids_tv",
    )
    for line in out.splitlines():
        if line.startswith("last_detail="):
            info["last_detail"] = line.split("=", 1)[1]
            continue
        for tok in line.split():
            if "=" not in tok:
                continue
            k, v = tok.split("=", 1)
            if k in ("ok", "mounted", "last_ok"):
                info[k] = v in ("1", "true", "True", "yes")
            elif k in int_keys:
                try:
                    info[k] = int(v)
                except ValueError:
                    pass
            elif k == "last_at":
                info["last_at"] = v
            elif k == "host_mnt":
                info["host_mnt"] = v
    return info


def _elements_payload(
    *,
    ok: bool,
    info: dict | None = None,
    error: str | None = None,
    detail: str | None = None,
    hint: str | None = None,
    action: str | None = None,
    pipeline: dict | None = None,
) -> dict:
    info = info or {}
    present = bool(info.get("present"))
    readable = bool(info.get("ct_readable"))
    auto = bool(info.get("auto"))
    if hint is None:
        if not present:
            hint = "Plug the WD Elements drive into the Proxmox PC, then click Attach to Plex."
        elif readable:
            hint = (
                "Elements is mounted for Plex. Upload into Movies, Kids Movies, TV Shows, or "
                "KIDS TV SHOWS inboxes, then Run pipeline to sort and refresh Plex."
            )
        else:
            hint = "Drive is present but not readable in Plex — click Attach to Plex to remount."
    state = "attached" if readable else ("present" if present else "missing")
    return {
        "ok": ok,
        "state": state,
        "present": present,
        "host_mounted": bool(info.get("host_mounted")),
        "ct_mounted": bool(info.get("ct_mounted")),
        "ct_readable": readable,
        "auto": auto,
        "usb_id": info.get("usb_id") or "1058:25a3",
        "host_mnt": info.get("host_mnt") or "/mnt/plex-usb",
        "ct_mnt": info.get("ct_mnt") or "/mnt/usb",
        "ctid": info.get("ctid") or "101",
        "host": PROXMOX_SSH_HOST,
        "hint": hint,
        "error": error,
        "detail": detail,
        "action": action,
        "pipeline": pipeline,
    }


def elements_pipeline_status() -> dict:
    """Inbox / library counts for the Elements media pipeline."""
    try:
        proc = proxmox_ssh(f"{PROXMOX_ELEMENTS_PIPELINE_CMD} status", timeout=60)
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "error": "SSH to Proxmox timed out while reading media pipeline status",
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    out = _elements_ssh_out(proc)
    info = _parse_elements_pipeline_status(out)
    info["ok"] = proc.returncode == 0 and bool(info.get("ok", True))
    if proc.returncode != 0 and not info.get("error"):
        info["error"] = out or f"pipeline status failed ({proc.returncode})"
    info["detail"] = out
    return info


def elements_status() -> dict:
    """WD Elements USB mount status for Plex CT (+ pipeline summary)."""
    try:
        proc = _elements_ssh(f"{PROXMOX_ELEMENTS_CMD} status")
    except subprocess.TimeoutExpired:
        return _elements_payload(
            ok=False,
            error="SSH to Proxmox timed out while reading Elements status",
        )
    except Exception as exc:
        return _elements_payload(ok=False, error=str(exc))
    out = _elements_ssh_out(proc)
    info = _parse_elements_status(out)
    ok = proc.returncode == 0
    pipe = None
    try:
        pipe = elements_pipeline_status()
    except Exception:
        pipe = None
    return _elements_payload(
        ok=ok, info=info, detail=out, error=None if ok else out, pipeline=pipe
    )


def elements_set(action: str) -> dict:
    """Attach Elements to Plex, toggle auto-hookup, or run media pipeline."""
    act = str(action or "").strip().lower()
    if act in ("attach", "reattach", "mount", "hookup"):
        remote = (
            f"{PROXMOX_ELEMENTS_CMD} attach; ec=$?; "
            f"{PROXMOX_ELEMENTS_PIPELINE_CMD} ensure-dirs || true; "
            f"{PROXMOX_ELEMENTS_CMD} status; "
            f"exit $ec"
        )
        label = "attach"
        timeout = 240
    elif act in ("auto-on", "auto_on", "enable-auto", "auto"):
        remote = (
            f"{PROXMOX_ELEMENTS_CMD} auto-on; "
            f"{PROXMOX_ELEMENTS_CMD} status; "
            f"exit 0"
        )
        label = "auto-on"
        timeout = 60
    elif act in ("auto-off", "auto_off", "disable-auto"):
        remote = (
            f"{PROXMOX_ELEMENTS_CMD} auto-off; "
            f"{PROXMOX_ELEMENTS_CMD} status; "
            f"exit 0"
        )
        label = "auto-off"
        timeout = 60
    elif act in ("pipeline", "run", "process-scan"):
        remote = (
            f"{PROXMOX_ELEMENTS_PIPELINE_CMD} run; ec=$?; "
            f"{PROXMOX_ELEMENTS_CMD} status; "
            f"exit $ec"
        )
        label = "pipeline"
        timeout = 600
    elif act in ("process", "ingest"):
        remote = (
            f"{PROXMOX_ELEMENTS_PIPELINE_CMD} process; ec=$?; "
            f"{PROXMOX_ELEMENTS_PIPELINE_CMD} status; "
            f"exit $ec"
        )
        label = "process"
        timeout = 600
    elif act in ("scan", "refresh"):
        remote = (
            f"{PROXMOX_ELEMENTS_PIPELINE_CMD} scan; ec=$?; "
            f"{PROXMOX_ELEMENTS_PIPELINE_CMD} status; "
            f"exit $ec"
        )
        label = "scan"
        timeout = 300
    elif act in ("ensure-dirs", "ensure"):
        remote = (
            f"{PROXMOX_ELEMENTS_PIPELINE_CMD} ensure-dirs; ec=$?; "
            f"{PROXMOX_ELEMENTS_PIPELINE_CMD} status; "
            f"exit $ec"
        )
        label = "ensure-dirs"
        timeout = 60
    else:
        raise ValueError(
            "action must be attach, auto-on, auto-off, pipeline, process, or scan"
        )
    try:
        proc = proxmox_ssh(remote, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"SSH to Proxmox timed out during Elements {label}"
        ) from exc
    out = _elements_ssh_out(proc)
    if proc.returncode != 0:
        raise RuntimeError(out or f"Elements {label} failed ({proc.returncode})")
    info = _parse_elements_status(out)
    pipe = _parse_elements_pipeline_status(out)
    if not any(k in out for k in ("present=", "host_mounted=")):
        # pipeline-only status — merge with fresh hookup status
        try:
            st = elements_status()
            info = {
                "present": st.get("present"),
                "host_mounted": st.get("host_mounted"),
                "ct_mounted": st.get("ct_mounted"),
                "ct_readable": st.get("ct_readable"),
                "auto": st.get("auto"),
                "usb_id": st.get("usb_id"),
                "host_mnt": st.get("host_mnt"),
                "ct_mnt": st.get("ct_mnt"),
                "ctid": st.get("ctid"),
            }
            pipe = st.get("pipeline") or pipe
        except Exception:
            pass
    return _elements_payload(
        ok=True, info=info, detail=out, action=label, pipeline=pipe
    )


def _elements_sanitize_filename(name: str) -> str:
    base = Path(str(name or "")).name.strip()
    if not base or base in (".", "..") or "/" in base or "\\" in base:
        raise ValueError("invalid filename")
    # strip path tricks / nulls
    base = base.replace("\x00", "").strip()
    if not base or base.startswith("."):
        raise ValueError("invalid filename")
    return base


def elements_upload_media(
    library: str, filename: str, data: bytes, *, process: bool = False
) -> dict:
    """Upload a media file into one of the four Elements library inboxes."""
    lib = str(library or "").strip().lower().replace(" ", "-").replace("_", "-")
    if lib in ("movie", "movies", "film", "films"):
        sub = "inbox/movies"
        kind = "movies"
        folder = "Movies"
    elif lib in (
        "kids-movie",
        "kids-movies",
        "kidsmovie",
        "kidsmovies",
        "kid-movies",
        "kidmovies",
    ):
        sub = "inbox/kids-movies"
        kind = "kids-movies"
        folder = "Kids Movies"
    elif lib in ("tv", "tvshow", "tvshows", "show", "shows", "series"):
        sub = "inbox/tvshows"
        kind = "tvshows"
        folder = "TV Shows"
    elif lib in (
        "kids-tv",
        "kids-tvshow",
        "kids-tvshows",
        "kidstv",
        "kidstvshow",
        "kidstvshows",
        "kids-tv-show",
        "kids-tv-shows",
        "kid-tv",
        "kid-tvshows",
    ):
        sub = "inbox/kids-tvshows"
        kind = "kids-tvshows"
        folder = "KIDS TV SHOWS"
    else:
        raise ValueError(
            "library must be movies, kids-movies, tvshows, or kids-tvshows"
        )
    if not data:
        raise ValueError("empty upload")
    if len(data) > ELEMENTS_UPLOAD_MAX_BYTES:
        raise ValueError(
            f"file too large ({len(data)} bytes; max {ELEMENTS_UPLOAD_MAX_BYTES})"
        )
    name = _elements_sanitize_filename(filename)
    # Ensure drive is attached + inbox dirs exist
    prep = proxmox_ssh(
        f"{PROXMOX_ELEMENTS_CMD} status; "
        f"{PROXMOX_ELEMENTS_PIPELINE_CMD} ensure-dirs",
        timeout=120,
    )
    prep_out = _elements_ssh_out(prep)
    if "mounted=0" in prep_out or "not mounted" in prep_out.lower():
        # try attach once
        att = proxmox_ssh(
            f"{PROXMOX_ELEMENTS_CMD} attach; "
            f"{PROXMOX_ELEMENTS_PIPELINE_CMD} ensure-dirs",
            timeout=240,
        )
        if att.returncode != 0:
            raise RuntimeError(
                _elements_ssh_out(att) or "Elements not mounted; attach failed"
            )
    dest = f"/mnt/plex-usb/{sub}/{name}"
    # Stream bytes over SSH stdin
    timeout = max(300, len(data) // (512 * 1024) + 120)
    cmd = [
        "ssh",
        "-i",
        PROXMOX_SSH_KEY,
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "ConnectTimeout=8",
        f"{PROXMOX_SSH_USER}@{PROXMOX_SSH_HOST}",
        f"cat > {shlex.quote(dest)}",
    ]
    proc = subprocess.run(
        cmd, input=data, capture_output=True, timeout=timeout
    )
    if proc.returncode != 0:
        err = (proc.stderr or b"").decode("utf-8", errors="replace")
        raise RuntimeError(err.strip() or f"upload failed ({proc.returncode})")
    result: dict = {
        "ok": True,
        "library": kind,
        "folder": folder,
        "filename": name,
        "bytes": len(data),
        "path": dest,
        "processed": False,
    }
    if process:
        run = elements_set("pipeline")
        result["processed"] = True
        result["pipeline"] = run.get("pipeline")
        result["detail"] = run.get("detail")
    else:
        try:
            result["pipeline"] = elements_pipeline_status()
        except Exception:
            pass
    return result


def _active_session_count() -> int:
    with _sessions_lock:
        _purge_sessions()
        return len(_sessions)


def build_portal_settings() -> dict:
    """Safe, non-secret portal settings for the Settings tab."""
    services: list[dict] = []
    try:
        status = build_vps_status()
        services = list(status.get("services") or [])
        hostname = status.get("hostname") or ""
        egress_ip = status.get("egress_ip") or ""
        uptime_sec = status.get("uptime_sec") or 0
    except Exception:
        hostname = ""
        egress_ip = ""
        uptime_sec = 0

    host = PORTAL_HOST or "portal.vpstruelord.com"
    links = [
        {"id": "portal", "label": "Portal", "url": f"https://{host}/"},
        {"id": "wg-easy", "label": "WireGuard (wg-easy)", "url": "/wg-ui/"},
        {"id": "openvpn-ui", "label": "OpenVPN admin", "url": f"https://{host}/openvpn.html"},
        {"id": "ovpn-flint", "label": "OpenVPN Flint (.ovpn)", "url": f"https://{host}/api/openvpn/flint"},
        {"id": "ovpn-phone", "label": "OpenVPN iPhone (.ovpn)", "url": f"https://{host}/api/openvpn/phone"},
        {
            "id": "ovpn-windows",
            "label": "OpenVPN Windows (.ovpn)",
            "url": (
                f"https://{host}/api/openvpn/windows?t={OVPN_WINDOWS_DL_TOKEN}"
                if OVPN_WINDOWS_DL_TOKEN
                else f"https://{host}/api/openvpn/windows"
            ),
        },
        {"id": "wg-flint", "label": "WireGuard Flint (.conf)", "url": f"https://{host}/api/wireguard/config"},
        {"id": "files", "label": "Files (direct)", "url": "https://files.vpstruelord.com/"},
        {"id": "buffalo", "label": "Buffalo NAS", "url": "https://buffalo.vpstruelord.com/"},
        {"id": "proxmox", "label": "Proxmox", "url": f"https://{PROXMOX_PUBLIC_HOST}/"},
        {"id": "router", "label": "Flint router", "url": f"https://{ROUTER_PUBLIC_HOST}/"},
        {"id": "adguard", "label": "AdGuard", "url": "https://dns.vpstruelord.com/?lng=en"},
        {"id": "pihole", "label": "Pi-hole", "url": "https://pihole.vpstruelord.com/admin/"},
        {"id": "tailscale", "label": "Tailscale admin", "url": "https://login.tailscale.com/admin/machines"},
    ]

    return {
        "ok": True,
        "user": AUTH_USER,
        "title": PANEL_TITLE,
        "tagline": PANEL_TAGLINE,
        "portal_host": PORTAL_HOST,
        "session_hours": SESSION_HOURS,
        "active_sessions": _active_session_count(),
        "vps_public_ip": VPS_PUBLIC_IP,
        "egress_ip": egress_ip,
        "hostname": hostname,
        "uptime_sec": uptime_sec,
        "buffalo_user": BUFFALO_SSO_USER,
        "buffalo_sso_configured": bool(BUFFALO_SSO_PASS),
        "router_user": "root",
        "router_sso_configured": bool(ROUTER_PASS),
        "wg_easy_user": WG_EASY_SSO_USER,
        "wg_easy_sso_configured": bool(WG_EASY_SSO_PASS),
        "wg_ui_prefix": WG_UI_PREFIX,
        "nas_files_prefix": NAS_FILES_PREFIX,
        "buffalo_prefix": BUFFALO_PREFIX,
        "env_file": str(PORTAL_ENV_PATH),
        "env_writable": PORTAL_ENV_PATH.is_file() and os.access(PORTAL_ENV_PATH, os.W_OK),
        "services": services,
        "links": links,
    }


def apply_portal_settings(payload: dict) -> dict:
    """Update panel branding / session / password; persist to EnvironmentFile."""
    global AUTH_PASS, PANEL_TITLE, PANEL_TAGLINE, SESSION_HOURS

    if not isinstance(payload, dict):
        raise ValueError("invalid payload")

    changed: list[str] = []
    env_updates: dict[str, str] = {}
    logout_all = bool(payload.get("logout_all_sessions"))

    if "title" in payload:
        title = str(payload.get("title") or "").strip() or "ServerManager"
        if len(title) > 64:
            raise ValueError("title too long (max 64)")
        if title != PANEL_TITLE:
            PANEL_TITLE = title
            env_updates["PANEL_TITLE"] = title
            changed.append("title")

    if "tagline" in payload:
        tagline = str(payload.get("tagline") or "").strip()
        if len(tagline) > 120:
            raise ValueError("tagline too long (max 120)")
        if tagline != PANEL_TAGLINE:
            PANEL_TAGLINE = tagline
            env_updates["PANEL_TAGLINE"] = tagline
            changed.append("tagline")

    if "session_hours" in payload:
        try:
            hours = float(payload.get("session_hours"))
        except (TypeError, ValueError) as exc:
            raise ValueError("session_hours must be a number") from exc
        if hours < 1 or hours > 168:
            raise ValueError("session_hours must be between 1 and 168")
        if abs(hours - SESSION_HOURS) > 0.001:
            SESSION_HOURS = hours
            env_updates["SESSION_HOURS"] = str(hours)
            changed.append("session_hours")

    new_password = payload.get("new_password")
    if new_password is not None and str(new_password) != "":
        current = str(payload.get("current_password") or "")
        new_pw = str(new_password)
        confirm = str(payload.get("confirm_password") or new_pw)
        if not hmac.compare_digest(current, AUTH_PASS):
            raise ValueError("current password is incorrect")
        if new_pw != confirm:
            raise ValueError("new passwords do not match")
        if len(new_pw) < 8:
            raise ValueError("new password must be at least 8 characters")
        if len(new_pw) > 128:
            raise ValueError("new password too long")
        if hmac.compare_digest(new_pw, AUTH_PASS):
            raise ValueError("new password must be different")
        AUTH_PASS = new_pw
        env_updates["PF_PASS"] = new_pw
        changed.append("password")
        logout_all = True

    if env_updates:
        if not PORTAL_ENV_PATH.is_file():
            raise RuntimeError(f"env file missing: {PORTAL_ENV_PATH}")
        _upsert_env_file(PORTAL_ENV_PATH, env_updates)

    sessions_cleared = 0
    if logout_all:
        with _sessions_lock:
            sessions_cleared = len(_sessions)
            _sessions.clear()
        changed.append("sessions")

    return {
        "ok": True,
        "changed": changed,
        "sessions_cleared": sessions_cleared,
        "settings": build_portal_settings(),
    }


def _github_api_json(
    url: str,
    token: str,
    timeout: float = 8.0,
    *,
    method: str = "GET",
    body: dict | None = None,
) -> tuple[int, dict]:
    """Call a GitHub API URL with a bearer token. Returns (status, json_or_empty)."""
    import json as _json
    import urllib.error
    import urllib.request

    data_bytes = None
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "ServerManager-Backup",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    method = (method or "GET").upper()
    if body is not None:
        data_bytes = _json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
        if method == "GET":
            method = "POST"
    req = urllib.request.Request(
        url,
        data=data_bytes,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            try:
                data = _json.loads(raw) if raw else {}
            except Exception:
                data = {}
            return int(resp.status), data if isinstance(data, dict) else {}
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read().decode("utf-8", errors="replace")
            data = _json.loads(raw) if raw else {}
        except Exception:
            data = {}
        return int(exc.code), data if isinstance(data, dict) else {}
    except Exception as exc:
        return 0, {"message": str(exc)}


def check_github_backup_token(
    owner: str, repo: str, token: str
) -> dict:
    """Validate a GitHub token can reach the backup repo (contents:write ideally)."""
    owner = (owner or "").strip()
    repo = (repo or "").strip()
    token = (token or "").strip()
    if not token:
        return {"ok": False, "error": "GitHub token is missing"}
    if not owner or not repo:
        return {"ok": False, "error": "GitHub owner/repo not set"}

    status, data = _github_api_json("https://api.github.com/user", token)
    if status in (401, 403) and "Bad credentials" in str(data.get("message") or ""):
        return {
            "ok": False,
            "error": "GitHub token is invalid or revoked. Create a new classic PAT (repo scope) and save it here.",
            "http_status": status,
        }
    if status == 401:
        return {
            "ok": False,
            "error": "GitHub token rejected (401). Paste a fresh PAT with repo access.",
            "http_status": status,
        }
    if status == 0:
        return {
            "ok": False,
            "error": f"Could not reach GitHub API: {data.get('message') or 'network error'}",
            "http_status": 0,
        }

    status, data = _github_api_json(
        f"https://api.github.com/repos/{owner}/{repo}", token
    )
    if status == 404:
        return {
            "ok": False,
            "error": f"Repo {owner}/{repo} not found for this token (wrong name, or token lacks access).",
            "http_status": status,
        }
    if status in (401, 403):
        msg = str(data.get("message") or "forbidden")
        return {
            "ok": False,
            "error": f"GitHub denied access to {owner}/{repo}: {msg}",
            "http_status": status,
        }
    if status != 200:
        return {
            "ok": False,
            "error": f"GitHub API returned HTTP {status} for {owner}/{repo}",
            "http_status": status,
        }

    perms = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
    can_push = bool(perms.get("push") or perms.get("admin"))
    if perms and not can_push:
        return {
            "ok": False,
            "error": f"Token can see {owner}/{repo} but cannot push. Need a PAT with Contents: Read and write.",
            "http_status": status,
            "private": bool(data.get("private")),
        }

    # Fine-grained PATs often report repo permissions.push=true (account role) while
    # the token itself lacks Contents: Read and write — prove write with a blob create.
    blob_status, blob_data = _github_api_json(
        f"https://api.github.com/repos/{owner}/{repo}/git/blobs",
        token,
        method="POST",
        body={"content": "c20=", "encoding": "base64"},  # "sm"
    )
    if blob_status in (401, 403):
        msg = str((blob_data or {}).get("message") or "forbidden")
        kind = "fine-grained" if token.startswith("github_pat_") else "PAT"
        return {
            "ok": False,
            "error": (
                f"Token authenticates but cannot write to {owner}/{repo} ({msg}). "
                f"For a {kind} token: grant Contents: Read and write on that repo "
                "(or use a classic PAT with repo scope), then save again."
            ),
            "http_status": blob_status,
            "private": bool(data.get("private")),
        }
    if blob_status not in (200, 201) and blob_status != 0:
        # Non-auth failures (422 etc.) still mean the token reached Contents write.
        if blob_status >= 500 or blob_status == 404:
            return {
                "ok": False,
                "error": f"GitHub Contents check failed (HTTP {blob_status}) for {owner}/{repo}",
                "http_status": blob_status,
                "private": bool(data.get("private")),
            }

    return {
        "ok": True,
        "error": "",
        "http_status": status,
        "private": bool(data.get("private")),
        "full_name": str(data.get("full_name") or f"{owner}/{repo}"),
    }


def set_backup_timer(enabled: bool) -> tuple[bool, str]:
    """Enable or disable the daily sm-backup.timer."""
    unit = "sm-backup.timer"
    if not Path(f"/etc/systemd/system/{unit}").is_file() and not Path(
        f"/lib/systemd/system/{unit}"
    ).is_file():
        return False, "sm-backup.timer is not installed"
    if enabled:
        proc = subprocess.run(
            ["systemctl", "enable", "--now", unit],
            capture_output=True,
            text=True,
            timeout=20,
        )
    else:
        proc = subprocess.run(
            ["systemctl", "disable", "--now", unit],
            capture_output=True,
            text=True,
            timeout=20,
        )
    out = ((proc.stdout or "") + (proc.stderr or "")).strip()
    if proc.returncode != 0:
        return False, out or f"systemctl failed ({proc.returncode})"
    state = _sh_out(["systemctl", "is-enabled", unit], timeout=4).strip()
    active = _sh_out(["systemctl", "is-active", unit], timeout=4).strip()
    return True, f"{unit} enabled={state} active={active}"


def build_backup_status(*, check_token: bool = True) -> dict:
    """GitHub backup agent status for the Backup portal tab (never returns the token)."""
    installed = BACKUP_SCRIPT.is_file()
    secrets_ok = BACKUP_SECRETS.is_file()
    env = _parse_env_file(BACKUP_SECRETS) if secrets_ok else {}
    owner = (env.get("GITHUB_OWNER") or "").strip()
    repo = (env.get("GITHUB_REPO") or "").strip()
    branch = (env.get("GITHUB_BRANCH") or "main").strip() or "main"
    backup_name = (env.get("BACKUP_NAME") or "vps").strip() or "vps"
    token = (env.get("GITHUB_TOKEN") or "").strip()
    has_token = bool(token)
    configured = installed and secrets_ok and bool(owner and repo and has_token)

    log_text = _read_text(str(BACKUP_LOG))
    lines = [ln for ln in log_text.splitlines() if ln.strip()]
    log_tail = "\n".join(lines[-50:])
    last_ok = None
    last_message = ""
    last_at = ""
    for line in reversed(lines):
        # Prefer the most recent success OR error (do not ignore new failures
        # just because an older "Pushed backup" line exists further up).
        if "Pushed backup" in line or "No changes to commit" in line:
            last_ok = True
            last_message = line
            last_at = line.split(" ", 1)[0] if " " in line else ""
            break
        if "ERROR" in line:
            last_ok = False
            last_message = line
            last_at = line.split(" ", 1)[0] if " " in line else ""
            break

    timer_enabled = (
        _sh_out(["systemctl", "is-enabled", "sm-backup.timer"], timeout=4).strip()
        == "enabled"
    )
    timer_active = (
        _sh_out(["systemctl", "is-active", "sm-backup.timer"], timeout=4).strip()
        == "active"
    )
    next_run = _sh_out(
        ["systemctl", "show", "sm-backup.timer", "-p", "NextElapseUSecRealtime", "--value"],
        timeout=4,
    ).strip()
    if next_run in ("", "n/a", "0"):
        next_run = ""
    last_trigger = _sh_out(
        ["systemctl", "show", "sm-backup.timer", "-p", "LastTriggerUSec", "--value"],
        timeout=4,
    ).strip()
    if last_trigger in ("", "n/a", "0"):
        last_trigger = ""

    repo_url = f"https://github.com/{owner}/{repo}" if owner and repo else ""

    token_ok: bool | None = None
    token_error = ""
    if check_token and configured:
        probe = check_github_backup_token(owner, repo, token)
        token_ok = bool(probe.get("ok"))
        token_error = str(probe.get("error") or "")
    elif configured:
        token_ok = None
    else:
        token_ok = False
        if not installed:
            token_error = "Backup agent is not installed on this VPS"
        elif not has_token:
            token_error = "GitHub token is missing"
        elif not owner or not repo:
            token_error = "GitHub owner/repo not set"

    healthy = bool(configured and token_ok is not False and last_ok is not False)

    return {
        "ok": healthy,
        "installed": installed,
        "configured": configured,
        "has_token": has_token,
        "token_ok": token_ok,
        "token_error": token_error,
        "owner": owner,
        "repo": repo,
        "branch": branch,
        "backup_name": backup_name,
        "repo_url": repo_url,
        "running": _backup_running(),
        "timer_enabled": timer_enabled,
        "timer_active": timer_active,
        "next_run": next_run,
        "last_trigger": last_trigger,
        "last_ok": last_ok,
        "last_at": last_at,
        "last_message": last_message,
        "log_tail": log_tail,
    }


def apply_backup_settings(payload: dict) -> dict:
    """Update backup secrets / daily timer from the Backup tab."""
    if not isinstance(payload, dict):
        raise ValueError("invalid payload")

    BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
    env = _parse_env_file(BACKUP_SECRETS) if BACKUP_SECRETS.is_file() else {}
    updates: dict[str, str] = {}
    changed: list[str] = []

    if "owner" in payload:
        owner = str(payload.get("owner") or "").strip()
        if owner and (not re.match(r"^[A-Za-z0-9_.-]+$", owner) or len(owner) > 64):
            raise ValueError("invalid GitHub owner")
        if owner and owner != (env.get("GITHUB_OWNER") or "").strip():
            updates["GITHUB_OWNER"] = owner
            changed.append("owner")
    if "repo" in payload:
        repo = str(payload.get("repo") or "").strip()
        if repo and (not re.match(r"^[A-Za-z0-9_.-]+$", repo) or len(repo) > 100):
            raise ValueError("invalid GitHub repo")
        if repo and repo != (env.get("GITHUB_REPO") or "").strip():
            updates["GITHUB_REPO"] = repo
            changed.append("repo")
    if "branch" in payload:
        branch = str(payload.get("branch") or "").strip() or "main"
        if not re.match(r"^[A-Za-z0-9_./-]+$", branch) or len(branch) > 128:
            raise ValueError("invalid GitHub branch")
        if branch != (env.get("GITHUB_BRANCH") or "main").strip():
            updates["GITHUB_BRANCH"] = branch
            changed.append("branch")
    if "backup_name" in payload:
        name = str(payload.get("backup_name") or "").strip() or "vps"
        if not re.match(r"^[A-Za-z0-9_.-]+$", name) or len(name) > 64:
            raise ValueError("invalid backup_name")
        if name != (env.get("BACKUP_NAME") or "vps").strip():
            updates["BACKUP_NAME"] = name
            changed.append("backup_name")

    token = str(payload.get("token") or payload.get("github_token") or "").strip()
    if token:
        if len(token) < 20 or len(token) > 256:
            raise ValueError("token looks invalid (unexpected length)")
        if any(ch.isspace() for ch in token):
            raise ValueError("token must not contain whitespace")
        updates["GITHUB_TOKEN"] = token
        changed.append("token")

    # Always keep GIT_NAME quoted-safe when rewriting secrets.
    if "GIT_NAME" not in env or " " in (env.get("GIT_NAME") or ""):
        updates.setdefault("GIT_NAME", (env.get("GIT_NAME") or "ServerManager Backup").strip() or "ServerManager Backup")
    if "GIT_EMAIL" not in env:
        updates.setdefault("GIT_EMAIL", "servermanager-backup@local")

    if updates:
        # Preserve existing keys we are not changing.
        merged = dict(env)
        merged.update(updates)
        # Ensure required defaults exist for a working secrets file.
        merged.setdefault("GITHUB_OWNER", "jsa00414")
        merged.setdefault("GITHUB_REPO", "ServerManagerBackup")
        merged.setdefault("GITHUB_BRANCH", "main")
        merged.setdefault("BACKUP_NAME", "vps")
        merged.setdefault("GIT_NAME", "ServerManager Backup")
        merged.setdefault("GIT_EMAIL", "servermanager-backup@local")
        _upsert_env_file(BACKUP_SECRETS, merged)
        try:
            os.chmod(BACKUP_SECRETS, 0o600)
        except Exception:
            pass

    timer_out = ""
    if "timer_enabled" in payload:
        ok_t, timer_out = set_backup_timer(bool(payload.get("timer_enabled")))
        if not ok_t:
            raise ValueError(timer_out or "failed to update backup timer")
        changed.append("timer")

    status = build_backup_status(check_token=True)
    # If a new token was saved but is still bad, surface that clearly.
    if "token" in changed and status.get("token_ok") is False:
        return {
            "ok": False,
            "error": status.get("token_error") or "GitHub token still invalid",
            "changed": changed,
            "timer": timer_out,
            "status": status,
        }
    return {
        "ok": True,
        "changed": changed,
        "timer": timer_out,
        "status": status,
    }


def run_backup_now() -> dict:
    """Run sm-backup.sh once; returns status + command output."""
    if not BACKUP_SCRIPT.is_file():
        return {"ok": False, "error": "Backup agent not installed on this VPS"}
    if not BACKUP_SECRETS.is_file():
        return {"ok": False, "error": "Missing /opt/servermanager-backup/secrets.env"}
    if _backup_running():
        return {"ok": False, "error": "A backup is already running", "status": build_backup_status(check_token=False)}

    # Fail fast with a clear message when the PAT is dead.
    env = _parse_env_file(BACKUP_SECRETS)
    probe = check_github_backup_token(
        (env.get("GITHUB_OWNER") or "").strip(),
        (env.get("GITHUB_REPO") or "").strip(),
        (env.get("GITHUB_TOKEN") or "").strip(),
    )
    if not probe.get("ok"):
        try:
            BACKUP_LOG.parent.mkdir(parents=True, exist_ok=True)
            with BACKUP_LOG.open("a", encoding="utf-8") as fh:
                fh.write(
                    f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} ERROR: {probe.get('error')}\n"
                )
        except Exception:
            pass
        return {
            "ok": False,
            "error": str(probe.get("error") or "GitHub token check failed"),
            "status": build_backup_status(check_token=True),
        }

    BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
    proc = None
    try:
        proc = subprocess.Popen(
            [str(BACKUP_SCRIPT)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(BACKUP_ROOT),
        )
        try:
            BACKUP_LOCK.write_text(str(proc.pid), encoding="utf-8")
        except Exception:
            pass
        try:
            stdout, stderr = proc.communicate(timeout=300)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate(timeout=10)
            return {
                "ok": False,
                "error": "Backup timed out after 5 minutes",
                "status": build_backup_status(check_token=False),
            }
        stdout = (stdout or "").strip()
        stderr = (stderr or "").strip()
        tok = (env.get("GITHUB_TOKEN") or "").strip()
        if tok:
            stdout = stdout.replace(tok, "***")
            stderr = stderr.replace(tok, "***")
        ok = proc.returncode == 0
        err_msg = ""
        if not ok:
            err_msg = stderr or stdout or f"backup exited {proc.returncode}"
            # Keep a one-line ERROR in the log if the script's trap missed it.
            if "ERROR" not in (stdout + stderr):
                try:
                    with BACKUP_LOG.open("a", encoding="utf-8") as fh:
                        fh.write(
                            f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} ERROR: {err_msg.splitlines()[-1][:300]}\n"
                        )
                except Exception:
                    pass
        return {
            "ok": ok,
            "exit_code": proc.returncode,
            "error": err_msg if not ok else "",
            "stdout": stdout[-8000:],
            "stderr": stderr[-4000:],
            "status": build_backup_status(check_token=False),
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc), "status": build_backup_status(check_token=False)}
    finally:
        try:
            BACKUP_LOCK.unlink(missing_ok=True)
        except Exception:
            pass


def build_vps_status() -> dict:
    """Host + service health for the Overview page."""
    # CPU / load
    load1 = load5 = load15 = 0.0
    try:
        load1, load5, load15 = os.getloadavg()
    except Exception:
        pass
    cores = os.cpu_count() or 1

    # Memory
    mem_total = mem_avail = mem_used = 0
    for line in _read_text("/proc/meminfo").splitlines():
        if line.startswith("MemTotal:"):
            mem_total = int(line.split()[1]) * 1024
        elif line.startswith("MemAvailable:"):
            mem_avail = int(line.split()[1]) * 1024
    if mem_total:
        mem_used = max(0, mem_total - mem_avail)

    # Disk (root)
    disk_total = disk_used = disk_free = 0
    try:
        st = os.statvfs("/")
        disk_total = st.f_frsize * st.f_blocks
        disk_free = st.f_frsize * st.f_bavail
        disk_used = disk_total - disk_free
    except Exception:
        pass

    # Uptime
    uptime_sec = 0.0
    try:
        uptime_sec = float(_read_text("/proc/uptime").split()[0])
    except Exception:
        pass

    hostname = _sh_out(["hostname"], timeout=3).splitlines()[0] if _sh_out(["hostname"], timeout=3) else ""
    public_ip = (os.environ.get("VPS_PUBLIC_IP") or "").strip() or "74.208.76.213"

    # Quick egress check (non-fatal)
    egress_ip = ""
    try:
        proc = subprocess.run(
            ["curl", "-4", "-s", "--max-time", "4", "ifconfig.me"],
            capture_output=True,
            text=True,
            timeout=6,
        )
        egress_ip = (proc.stdout or "").strip()
    except Exception:
        pass

    ts = {}
    try:
        ts = tailscale_status()
    except Exception as exc:
        ts = {"ok": False, "enabled": False, "error": str(exc)}

    services = [
        {"id": "panel", "label": "Portal panel", "ok": True, "detail": "running"},
        {"id": "sslh", "label": "HTTPS mux", "ok": _svc_active("sslh-sm.service"), "detail": ":443 -> Caddy"},
        {"id": "caddy", "label": "Caddy", "ok": _docker_running("truemail-caddy-1"), "detail": "HTTPS proxy"},
        {"id": "wireguard", "label": "WireGuard", "ok": _docker_running("wg-easy"), "detail": "wg-easy"},
        {
            "id": "tailscale",
            "label": "Tailscale",
            "ok": bool(ts.get("enabled")),
            "detail": (ts.get("state") or ("on" if ts.get("enabled") else "off")),
        },
        {"id": "adguard", "label": "AdGuard", "ok": _docker_running("sm-adguard"), "detail": "DNS filter"},
        {"id": "pihole", "label": "Pi-hole", "ok": _docker_running("sm-pihole"), "detail": "DNS filter"},
        {"id": "unbound", "label": "Unbound", "ok": _docker_running("sm-unbound"), "detail": "recursive DNS"},
        {"id": "coredns", "label": "CoreDNS", "ok": _docker_running("wg-portal-dns"), "detail": "VPN DNS"},
    ]

    mem_pct = round((mem_used / mem_total) * 100, 1) if mem_total else 0.0
    disk_pct = round((disk_used / disk_total) * 100, 1) if disk_total else 0.0
    load_ok = load1 < max(1.0, cores * 1.5)
    mem_ok = mem_pct < 90
    disk_ok = disk_pct < 90
    services_ok = all(s["ok"] for s in services)
    overall_ok = load_ok and mem_ok and disk_ok and services_ok

    portal_host = PORTAL_HOST or "portal.vpstruelord.com"
    if portal_host.startswith("http"):
        portal_host = portal_host.split("://", 1)[-1].rstrip("/")

    return {
        "ok": overall_ok,
        "hostname": hostname,
        "portal_host": portal_host,
        "public_ip": public_ip,
        "egress_ip": egress_ip,
        "uptime_sec": uptime_sec,
        "load": {"one": load1, "five": load5, "fifteen": load15, "cores": cores, "ok": load_ok},
        "memory": {
            "total": mem_total,
            "used": mem_used,
            "available": mem_avail,
            "percent": mem_pct,
            "ok": mem_ok,
        },
        "disk": {
            "total": disk_total,
            "used": disk_used,
            "free": disk_free,
            "percent": disk_pct,
            "ok": disk_ok,
        },
        "services": services,
        "tailscale": {
            "enabled": bool(ts.get("enabled")),
            "ips": ts.get("ips") or [],
            "run_exit_node": bool(ts.get("run_exit_node")),
            "custom_exit_node": bool(ts.get("custom_exit_node")),
        },
    }




def apply_tailscale(payload: dict) -> dict:
    """Apply Tailscale settings.

    - VPS host always keeps its public IP (host-protect ip rules).
    - Custom Exit Node routes *WireGuard* (10.8.0.0/24), *OpenVPN* (10.9.0.0/24),
      and Flint/home LAN (192.168.8.0/24, 10.0.0.0/24) via the chosen Tailscale exit;
      it does not steal the VPS management path.
    - Run Exit Node advertises this VPS as an exit for other Tailscale clients.
    """
    enabled = bool(payload.get("enabled"))
    run_exit = bool(payload.get("run_exit_node"))
    custom_exit = bool(payload.get("custom_exit_node"))
    exit_ip = str(payload.get("exit_node_ip") or "").strip()
    advertise_lan = bool(payload.get("advertise_lan"))
    ip_masq = bool(payload.get("ip_masquerading"))
    if "auto_disable_exit" in payload:
        save_ts_portal_state({"auto_disable_exit": bool(payload.get("auto_disable_exit"))})

    logs: list[str] = []

    if not enabled:
        vpn_ok, vpn_out = set_vpn_only_exit(False)
        logs.append(f"vpn-exit: {vpn_out}")
        protect_ok, protect_out = set_ts_host_protect(False)
        logs.append(f"host-protect: {protect_out}")
        proc = subprocess.run(["tailscale", "down"], capture_output=True, text=True, timeout=30)
        logs.append(((proc.stdout or "") + (proc.stderr or "")).strip())
        dns_ok, dns_out = set_ts_exit_dns(False)
        logs.append(f"exit-dns-filter: {dns_out}")
        st = tailscale_status()
        ok = proc.returncode == 0 and dns_ok and vpn_ok and protect_ok
        st.update({"ok": ok, "stdout": "\n".join(x for x in logs if x), "stderr": ""})
        if not ok:
            st["error"] = (proc.stderr or proc.stdout or dns_out or vpn_out or "tailscale down failed").strip()
        return st

    # Make sure daemon is up without a host-wide sticky exit yet
    stj = _tailscale_status_json()
    if str(stj.get("BackendState") or "") != "Running":
        up = subprocess.run(
            [
                "tailscale",
                "up",
                "--accept-dns=false",
                "--accept-routes=false",
                "--hostname=vpstruelord-vps",
                "--reset",
                "--exit-node=",
                "--advertise-exit-node=false",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        logs.append(((up.stdout or "") + (up.stderr or "")).strip())
        if up.returncode != 0:
            st = tailscale_status()
            st.update({
                "ok": False,
                "error": (up.stderr or up.stdout or "tailscale up failed").strip(),
                "stdout": "\n".join(x for x in logs if x),
                "stderr": (up.stderr or "").strip(),
            })
            return st

    if run_exit or advertise_lan:
        _ensure_ip_forward()

    routes = "192.168.8.0/24,10.8.0.0/24" if advertise_lan else ""
    args = [
        "tailscale",
        "set",
        f"--advertise-exit-node={'true' if run_exit else 'false'}",
        f"--snat-subnet-routes={'true' if ip_masq else 'false'}",
        f"--advertise-routes={routes}",
        "--accept-dns=false",
        "--accept-routes=false",
        "--hostname=vpstruelord-vps",
        # Exit node for VPN is applied via ts-vpn-exit.sh (with host protect).
        "--exit-node=",
    ]

    proc = subprocess.run(args, capture_output=True, text=True, timeout=45)
    logs.append(((proc.stdout or "") + (proc.stderr or "")).strip())
    ok = proc.returncode == 0

    # VPN-only exit: protect VPS public IP, then attach exit for WG clients
    if custom_exit:
        # Disable Surfshark VPN exit if active
        if SS_VPN_EXIT_SCRIPT.is_file():
            ss_proc = subprocess.run(
                [str(SS_VPN_EXIT_SCRIPT), "disable"],
                capture_output=True,
                text=True,
                timeout=60,
            )
            logs.append(f"surfshark-vpn-exit-off: {((ss_proc.stdout or '') + (ss_proc.stderr or '')).strip()}")
        vpn_ok, vpn_out = set_vpn_only_exit(True, exit_ip)
    else:
        vpn_ok, vpn_out = set_vpn_only_exit(False)
    logs.append(f"vpn-exit: {vpn_out}")
    if not vpn_ok:
        ok = False

    dns_ok, dns_out = set_ts_exit_dns(bool(run_exit and enabled))
    logs.append(f"exit-dns-filter: {dns_out}")
    if not dns_ok and run_exit and enabled:
        ok = False

    protect_ok, protect_out = set_ts_host_protect(True)
    logs.append(f"host-protect: {protect_out}")
    if not protect_ok:
        ok = False

    st = tailscale_status()
    st.update({
        "ok": ok,
        "stdout": "\n".join(x for x in logs if x) or "Applied",
        "stderr": "" if ok else ((proc.stderr or "") + "\n" + vpn_out + "\n" + dns_out).strip(),
    })
    if not ok:
        st["error"] = st["stderr"] or "tailscale set failed"
    return st


SS_PORTAL_STATE = Path("/opt/surfshark/surfshark-portal.json")
SS_VPN_EXIT_SCRIPT = Path("/opt/surfshark/ss-vpn-exit.sh")
SS_VPN_EXIT_STATE = Path("/opt/surfshark/ss-vpn-exit.state")
SS_EXIT_DNS_SCRIPT = Path("/opt/surfshark/ss-exit-dns.sh")
SS_EXIT_DNS_FLAG = Path("/opt/surfshark/ss-exit-dns.enabled")
SS_CONF_DIR = Path("/opt/surfshark/conf")


def load_ss_portal_state() -> dict:
    if SS_PORTAL_STATE.is_file():
        try:
            data = json.loads(SS_PORTAL_STATE.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    return {"auto_disable_exit": True, "enabled": False, "dns_filter": True}


def save_ss_portal_state(data: dict) -> None:
    cur = load_ss_portal_state()
    cur.update(data)
    SS_PORTAL_STATE.parent.mkdir(parents=True, exist_ok=True)
    SS_PORTAL_STATE.write_text(json.dumps(cur, indent=2) + "\n", encoding="utf-8")


def _read_ss_vpn_exit_state() -> dict:
    out = {"enabled": False, "server": "", "iface": "", "public_ip": ""}
    if not SS_VPN_EXIT_STATE.is_file():
        return out
    try:
        for line in SS_VPN_EXIT_STATE.read_text(encoding="utf-8").splitlines():
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip()
            if k == "ENABLED":
                out["enabled"] = v in ("1", "true", "True", "yes")
            elif k == "SERVER":
                out["server"] = v
            elif k == "IFACE":
                out["iface"] = v
            elif k == "PUBLIC_IP":
                out["public_ip"] = v
    except Exception:
        pass
    return out


def list_surfshark_servers() -> list[dict]:
    servers: list[dict] = []
    if not SS_CONF_DIR.is_dir():
        return servers
    for path in sorted(SS_CONF_DIR.glob("*.conf")):
        name = path.stem
        endpoint = ""
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.strip().lower().startswith("endpoint"):
                    endpoint = line.split("=", 1)[1].strip()
                    break
        except Exception:
            pass
        servers.append({
            "id": name,
            "name": name,
            "label": _surfshark_display_name(name),
            "endpoint": endpoint,
        })
    return servers


def _surfshark_display_name(server_id: str) -> str:
    key = str(server_id or "").strip().lower()
    aliases = {
        "us-nyc": "New York",
        "us-new-york": "New York",
        "us-dtw": "Detroit",
        "us-lax": "Los Angeles",
        "us-chi": "Chicago",
        "us-mia": "Miami",
        "us-dal": "Dallas",
        "us-sea": "Seattle",
        "us-den": "Denver",
        "us-atl": "Atlanta",
        "us-phx": "Phoenix",
        "us-bos": "Boston",
        "us-hou": "Houston",
        "us-sfo": "San Francisco",
        "us-was": "Washington DC",
        "uk-lon": "London",
        "ca-tor": "Toronto",
        "ca-van": "Vancouver",
        "de-fra": "Frankfurt",
        "nl-ams": "Amsterdam",
        "fr-par": "Paris",
        "jp-tok": "Tokyo",
        "au-syd": "Sydney",
    }
    if key in aliases:
        return aliases[key]
    if "-" in key:
        city = key.split("-", 1)[1].replace("-", " ")
        return city.title()
    return server_id


def _ss_iface_up(iface: str) -> bool:
    if not iface:
        return False
    try:
        proc = subprocess.run(
            ["ip", "link", "show", iface],
            capture_output=True,
            text=True,
            timeout=4,
        )
        return proc.returncode == 0 and "state UP" in (proc.stdout or "")
    except Exception:
        return False


def set_surfshark_vpn_exit(enabled: bool, server: str = "") -> tuple[bool, str]:
    if not SS_VPN_EXIT_SCRIPT.is_file():
        return False, "ss-vpn-exit.sh missing"
    if enabled:
        srv = (server or "").strip()
        if not srv:
            return False, "Surfshark server required"
        proc = subprocess.run(
            [str(SS_VPN_EXIT_SCRIPT), "enable", srv],
            capture_output=True,
            text=True,
            timeout=90,
        )
    else:
        proc = subprocess.run(
            [str(SS_VPN_EXIT_SCRIPT), "disable"],
            capture_output=True,
            text=True,
            timeout=60,
        )
    msg = ((proc.stdout or "") + (proc.stderr or "")).strip()
    return proc.returncode == 0, msg or ("ok" if proc.returncode == 0 else "surfshark vpn-exit failed")


def ss_exit_dns_status() -> bool:
    if not SS_EXIT_DNS_SCRIPT.is_file():
        return False
    proc = subprocess.run(
        [str(SS_EXIT_DNS_SCRIPT), "status"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return "enabled" in (proc.stdout or "")


def set_ss_exit_dns(enabled: bool, iface: str = "") -> tuple[bool, str]:
    if not SS_EXIT_DNS_SCRIPT.is_file():
        return False, "ss-exit-dns.sh missing"
    if enabled:
        SS_EXIT_DNS_FLAG.write_text("1\n", encoding="utf-8")
        args = [str(SS_EXIT_DNS_SCRIPT), "enable"]
        if iface.strip():
            args.append(iface.strip())
        proc = subprocess.run(args, capture_output=True, text=True, timeout=15)
    else:
        if SS_EXIT_DNS_FLAG.exists():
            SS_EXIT_DNS_FLAG.unlink()
        proc = subprocess.run(
            [str(SS_EXIT_DNS_SCRIPT), "disable"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    out = ((proc.stdout or "") + (proc.stderr or "")).strip()
    return proc.returncode == 0, out


def surfshark_status() -> dict:
    portal = load_ss_portal_state()
    vpn_exit = _read_ss_vpn_exit_state()
    servers = list_surfshark_servers()
    iface = str(vpn_exit.get("iface") or "")
    server = str(vpn_exit.get("server") or "")
    custom_exit = bool(vpn_exit.get("enabled"))
    enabled = bool(portal.get("enabled")) or custom_exit or _ss_iface_up(iface)

    egress_ip = ""
    if custom_exit and iface:
        try:
            proc = subprocess.run(
                ["curl", "-4", "-s", "--max-time", "6", "--interface", iface, "ifconfig.me"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            egress_ip = (proc.stdout or "").strip()
        except Exception:
            pass

    wg_text = _sh_out(["wg", "show"], timeout=6)
    text_lines = [
        f"Surfshark: {'connected' if custom_exit else 'off'}",
        f"Server: {_surfshark_display_name(server) if server else '—'}",
        f"Interface: {iface or '—'}",
    ]
    if egress_ip:
        text_lines.append(f"VPN egress: {egress_ip}")
    if wg_text:
        text_lines.append("")
        text_lines.append(wg_text)

    return {
        "ok": True,
        "enabled": enabled,
        "custom_exit_node": custom_exit,
        "vpn_only_exit": True,
        "server": server if custom_exit else "",
        "iface": iface,
        "servers": servers,
        "has_configs": bool(servers),
        "egress_ip": egress_ip,
        "auto_disable_exit": bool(portal.get("auto_disable_exit", True)),
        "dns_filter": bool(portal.get("dns_filter", True)),
        "exit_dns_filter": ss_exit_dns_status(),
        "setup_hint": (
            "Add Surfshark WireGuard .conf files to /opt/surfshark/conf/ "
            "(Surfshark account → VPN → Manual setup → WireGuard)."
        ),
        "text": "\n".join(text_lines),
    }


def apply_surfshark(payload: dict) -> dict:
    """Apply Surfshark settings — WireGuard VPN exit for WG clients only."""
    enabled = bool(payload.get("enabled"))
    custom_exit = bool(payload.get("custom_exit_node"))
    server = str(payload.get("server") or payload.get("exit_node_ip") or "").strip()
    dns_filter = bool(payload.get("dns_filter", load_ss_portal_state().get("dns_filter", True)))
    if "auto_disable_exit" in payload:
        save_ss_portal_state({"auto_disable_exit": bool(payload.get("auto_disable_exit"))})
    if "dns_filter" in payload:
        save_ss_portal_state({"dns_filter": dns_filter})

    logs: list[str] = []

    if not enabled:
        vpn_ok, vpn_out = set_surfshark_vpn_exit(False)
        logs.append(f"surfshark-vpn-exit: {vpn_out}")
        dns_ok, dns_out = set_ss_exit_dns(False)
        logs.append(f"exit-dns-filter: {dns_out}")
        save_ss_portal_state({"enabled": False})
        st = surfshark_status()
        st.update({"ok": vpn_ok and dns_ok, "stdout": "\n".join(x for x in logs if x), "stderr": ""})
        if not vpn_ok:
            st["error"] = vpn_out or "surfshark disable failed"
        return st

    save_ss_portal_state({"enabled": True})

    if custom_exit:
        if not list_surfshark_servers():
            st = surfshark_status()
            st.update({
                "ok": False,
                "error": "No Surfshark configs in /opt/surfshark/conf/",
                "stdout": "",
                "stderr": "",
            })
            return st
        if not server and list_surfshark_servers():
            server = list_surfshark_servers()[0]["id"]
        # Disable Tailscale VPN exit if active
        if TS_VPN_EXIT_SCRIPT.is_file():
            ts_proc = subprocess.run(
                [str(TS_VPN_EXIT_SCRIPT), "disable"],
                capture_output=True,
                text=True,
                timeout=60,
            )
            logs.append(f"tailscale-vpn-exit-off: {((ts_proc.stdout or '') + (ts_proc.stderr or '')).strip()}")
        vpn_ok, vpn_out = set_surfshark_vpn_exit(True, server)
    else:
        vpn_ok, vpn_out = set_surfshark_vpn_exit(False)

    logs.append(f"surfshark-vpn-exit: {vpn_out}")
    iface = str(_read_ss_vpn_exit_state().get("iface") or "")
    if custom_exit and vpn_ok and dns_filter:
        dns_ok, dns_out = set_ss_exit_dns(True, iface)
    else:
        dns_ok, dns_out = set_ss_exit_dns(False)
    logs.append(f"exit-dns-filter: {dns_out}")
    ok = vpn_ok and dns_ok
    st = surfshark_status()
    st.update({
        "ok": ok,
        "stdout": "\n".join(x for x in logs if x) or "Applied",
        "stderr": "" if ok else (vpn_out + "\n" + dns_out).strip(),
    })
    if not ok:
        st["error"] = vpn_out or dns_out or "surfshark apply failed"
    return st


def check_basic_auth(header: str | None) -> bool:
    if not ALLOW_BASIC_AUTH:
        return False
    if not header or not header.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(header.split(" ", 1)[1]).decode("utf-8")
        user, _, password = decoded.partition(":")
    except Exception:
        return False
    return hmac.compare_digest(user, AUTH_USER) and hmac.compare_digest(
        password, AUTH_PASS
    )


def _purge_sessions(now: float | None = None) -> None:
    now = time.time() if now is None else now
    dead = [k for k, exp in _sessions.items() if exp <= now]
    for k in dead:
        _sessions.pop(k, None)


def create_session() -> str:
    token = secrets.token_urlsafe(32)
    with _sessions_lock:
        _purge_sessions()
        _sessions[token] = time.time() + SESSION_HOURS * 3600
    return token


def destroy_session(token: str | None) -> None:
    if not token:
        return
    with _sessions_lock:
        _sessions.pop(token, None)
    with _ssh_panel_unlocks_lock:
        _ssh_panel_unlocks.pop(token, None)


def session_valid(token: str | None) -> bool:
    if not token:
        return False
    now = time.time()
    with _sessions_lock:
        _purge_sessions(now)
        exp = _sessions.get(token)
        return bool(exp and exp > now)


def parse_session_cookie(header: str | None) -> str | None:
    if not header:
        return None
    jar = SimpleCookie()
    try:
        jar.load(header)
    except Exception:
        return None
    morsel = jar.get(COOKIE_NAME)
    return morsel.value if morsel else None


def check_credentials(username: str, password: str) -> bool:
    return hmac.compare_digest(username, AUTH_USER) and hmac.compare_digest(
        password, AUTH_PASS
    )


_pending_logins: dict[str, dict] = {}
_pending_logins_lock = threading.Lock()
PENDING_LOGIN_TTL_SECONDS = int(os.environ.get("PENDING_LOGIN_TTL_SECONDS", "300"))


def _purge_pending_logins(now: float | None = None) -> None:
    ts = time.time() if now is None else now
    with _pending_logins_lock:
        dead = [k for k, v in _pending_logins.items() if float(v.get("exp") or 0) <= ts]
        for k in dead:
            _pending_logins.pop(k, None)


def portal_login_2fa_method() -> str:
    """Prefer authenticator app when a TOTP secret exists; otherwise email codes."""
    cfg = _read_ssh_panel_2fa()
    if str(cfg.get("totp_secret") or "").strip():
        return "app"
    return "email"


def begin_portal_login(*, username: str, password: str, client_ip: str = "") -> dict:
    """Step 1: password OK → issue pending login and request 2FA code."""
    if not check_credentials(username, password):
        raise PermissionError("Invalid username or password")
    method = portal_login_2fa_method()
    login_token = secrets.token_urlsafe(24)
    now = time.time()
    _purge_pending_logins(now)
    with _pending_logins_lock:
        _pending_logins[login_token] = {
            "exp": now + max(60, PENDING_LOGIN_TTL_SECONDS),
            "user": AUTH_USER,
            "ip": client_ip or "",
            "method": method,
        }
    if method == "app":
        return {
            "ok": True,
            "need_code": True,
            "two_factor_method": "app",
            "login_token": login_token,
            "message": "Enter the code from your Authenticator app.",
        }
    sent = send_email_test_code(client_ip or "login", key=f"portal-login:{login_token}")
    return {
        "ok": True,
        "need_code": True,
        "two_factor_method": "email",
        "login_token": login_token,
        "message": sent.get("message") or "Enter the email verification code.",
    }


def complete_portal_login(
    *,
    login_token: str,
    code: str,
    client_ip: str = "",
) -> dict:
    """Step 2: verify 2FA code for a pending login, then create session."""
    token = str(login_token or "").strip()
    if not token:
        raise ValueError("Login session expired. Sign in again.")
    now = time.time()
    _purge_pending_logins(now)
    with _pending_logins_lock:
        pending = _pending_logins.get(token)
    if not pending or float(pending.get("exp") or 0) <= now:
        raise ValueError("Login session expired. Sign in again.")
    method = str(pending.get("method") or "email")
    if method == "app":
        secret = str(_read_ssh_panel_2fa().get("totp_secret") or "")
        if not verify_totp_code(secret, code):
            time.sleep(0.25)
            raise ValueError("Incorrect authenticator code")
    else:
        verify_email_test_code(client_ip or "login", code, key=f"portal-login:{token}")
    with _pending_logins_lock:
        _pending_logins.pop(token, None)
    session = create_session()
    return {
        "ok": True,
        "need_code": False,
        "user": AUTH_USER,
        "session": session,
        "message": "Signed in.",
    }


# --- Email verification code test (portalvpsserver@truemailor.com → Gmail) ---
EMAIL_CODE_TO = os.environ.get(
    "EMAIL_CODE_TO", "portalvpsserver@truemailor.com"
).strip()
EMAIL_CODE_FROM = os.environ.get(
    "EMAIL_CODE_FROM", "portal@truemailor.com"
).strip()
PORTAL_SMTP_USER = os.environ.get("PORTAL_SMTP_USER", EMAIL_CODE_FROM).strip()
EMAIL_CODE_TTL_SECONDS = int(os.environ.get("EMAIL_CODE_TTL_SECONDS", "600"))
EMAIL_CODE_COOLDOWN_SECONDS = int(os.environ.get("EMAIL_CODE_COOLDOWN_SECONDS", "45"))
_email_codes: dict[str, dict] = {}
_email_codes_lock = threading.Lock()
_email_code_last_send: dict[str, float] = {}


def _portal_smtp_password() -> str:
    """Password for the portal-only send mailbox (portal@…), not admin webmail."""
    direct = (os.environ.get("PORTAL_SMTP_PASS") or "").strip()
    if direct:
        return direct
    b64 = (os.environ.get("PORTAL_SMTP_PASS_B64") or "").strip()
    if b64:
        try:
            return base64.b64decode(b64).decode("utf-8")
        except Exception:
            pass
    # Legacy fallback while migrating off admin@
    for path in (
        Path(os.environ.get("TRUEMAIL_ENV", "/opt/truemail/.env")),
        Path(__file__).resolve().parent.parent / "truemail" / ".env",
    ):
        if not path.is_file():
            continue
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.startswith("FIRST_MAIL_PASS="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
        except Exception:
            continue
    return (os.environ.get("TRUEMAIL_ADMIN_PASS") or "").strip()


def _smtp_send_email(
    *,
    to_addr: str,
    subject: str,
    body: str,
    html: str | None = None,
) -> None:
    import smtplib
    import ssl
    from email.message import EmailMessage
    from email.utils import formatdate, make_msgid

    user = PORTAL_SMTP_USER or EMAIL_CODE_FROM
    pw = _portal_smtp_password()
    if not pw:
        raise RuntimeError("Portal SMTP password not configured (PORTAL_SMTP_PASS)")

    msg = EmailMessage()
    msg["From"] = f"ServerManager <{EMAIL_CODE_FROM}>"
    msg["To"] = to_addr
    msg["Reply-To"] = EMAIL_CODE_FROM
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain="truemailor.com")
    msg["Auto-Submitted"] = "auto-generated"
    msg["X-Auto-Response-Suppress"] = "All"
    msg["List-Id"] = f"<portal-codes.{PORTAL_HOST}>"
    msg.set_content(body)
    if html:
        msg.add_alternative(html, subtype="html")

    ctx = ssl._create_unverified_context()
    host = os.environ.get("SMTP_HOST", "127.0.0.1").strip() or "127.0.0.1"
    port = int(os.environ.get("SMTP_PORT", "587"))
    with smtplib.SMTP(host, port, timeout=30) as s:
        s.ehlo()
        s.starttls(context=ctx)
        s.ehlo()
        s.login(user, pw)
        s.send_message(msg)


def _email_code_html(code: str, *, minutes: int) -> str:
    """Transactional HTML email for a one-time portal code (spam-filter friendly)."""
    digits = "".join(ch for ch in str(code) if ch.isdigit())
    mins = max(1, int(minutes))
    # Keep markup simple: tables + inline styles only. Avoid gradients/web fonts
    # that Gmail often treats as promotional.
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="color-scheme" content="light only" />
  <title>Your verification code</title>
</head>
<body style="margin:0;padding:0;background:#f4f6f5;color:#14201b;">
  <div style="display:none;max-height:0;overflow:hidden;opacity:0;">
    Your ServerManager verification code is {digits}. Valid for {mins} minutes.
  </div>
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#f4f6f5;padding:28px 12px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="max-width:480px;background:#ffffff;border:1px solid #d7e0db;border-radius:12px;">
          <tr>
            <td align="center" style="padding:28px 28px 8px;text-align:center;font-family:Arial,Helvetica,sans-serif;font-size:18px;color:#3d7a5f;font-weight:700;letter-spacing:0.04em;text-transform:uppercase;">
              ServerManager
            </td>
          </tr>
          <tr>
            <td align="center" style="padding:4px 28px 0;text-align:center;font-family:Arial,Helvetica,sans-serif;font-size:22px;line-height:1.3;color:#14201b;font-weight:700;">
              Your verification code
            </td>
          </tr>
          <tr>
            <td align="center" style="padding:12px 28px 0;text-align:center;font-family:Arial,Helvetica,sans-serif;font-size:15px;line-height:1.5;color:#4a5c54;">
              Use this code to continue signing in. It expires in {mins} minutes.
            </td>
          </tr>
          <tr>
            <td align="center" style="padding:26px 28px 28px;">
              <div style="display:inline-block;padding:16px 22px;border:1px solid #cfe0d7;border-radius:10px;background:#f7faf8;font-family:Consolas,'Courier New',monospace;font-size:32px;font-weight:700;letter-spacing:0.28em;color:#0f3d2c;">
                {digits}
              </div>
            </td>
          </tr>
        </table>
        <div style="padding:14px 8px 0;font-family:Arial,Helvetica,sans-serif;font-size:11px;color:#8a9a92;">
          Truemailor · mail.truemailor.com
        </div>
      </td>
    </tr>
  </table>
</body>
</html>"""


def send_email_test_code(client_ip: str, *, key: str | None = None) -> dict:
    """Generate + email a 6-digit code (rate-limited per key/IP)."""
    store_key = (key or client_ip or "unknown").strip() or "unknown"
    now = time.time()
    with _email_codes_lock:
        last = float(_email_code_last_send.get(store_key) or 0)
        wait = EMAIL_CODE_COOLDOWN_SECONDS - (now - last)
        if wait > 0:
            raise ValueError(f"Wait {int(wait) + 1}s before sending another code")
        code = f"{secrets.randbelow(1_000_000):06d}"
        _email_codes[store_key] = {
            "hash": hashlib.sha256(code.encode("utf-8")).hexdigest(),
            "expires": now + max(60, EMAIL_CODE_TTL_SECONDS),
            "attempts": 0,
        }
        _email_code_last_send[store_key] = now

    minutes = max(1, EMAIL_CODE_TTL_SECONDS // 60)
    # Keep digits out of the subject — OTP-in-subject is a common spam signal.
    subject = "Your ServerManager verification code"
    body = (
        f"Your ServerManager verification code is: {code}\n\n"
        f"This code expires in {minutes} minutes.\n"
    )
    html = _email_code_html(code, minutes=minutes)
    try:
        _smtp_send_email(
            to_addr=EMAIL_CODE_TO, subject=subject, body=body, html=html
        )
    except Exception as exc:
        with _email_codes_lock:
            _email_codes.pop(store_key, None)
        raise RuntimeError(f"Failed to send email: {exc}") from exc

    return {
        "ok": True,
        "to": EMAIL_CODE_TO,
        "expires_in": EMAIL_CODE_TTL_SECONDS,
        "message": "Code sent. Check your email.",
    }


def verify_email_test_code(client_ip: str, code: str, *, key: str | None = None) -> dict:
    store_key = (key or client_ip or "unknown").strip() or "unknown"
    raw = re.sub(r"\D+", "", str(code or ""))
    if len(raw) != 6:
        raise ValueError("Enter the 6-digit code")
    now = time.time()
    with _email_codes_lock:
        entry = _email_codes.get(store_key)
        if not entry:
            raise ValueError("No code pending — send a new one")
        if float(entry.get("expires") or 0) <= now:
            _email_codes.pop(store_key, None)
            raise ValueError("Code expired — send a new one")
        attempts = int(entry.get("attempts") or 0) + 1
        entry["attempts"] = attempts
        if attempts > 8:
            _email_codes.pop(store_key, None)
            raise ValueError("Too many attempts — send a new code")
        expect = str(entry.get("hash") or "")
        got = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(expect, got):
            raise ValueError("Incorrect code")
        _email_codes.pop(store_key, None)
    return {
        "ok": True,
        "message": "Code accepted. Email path works.",
    }


# Persist 2FA toggle for Security → VPS login method & SSH keys panel.
SSH_PANEL_2FA_PATH = Path(
    os.environ.get(
        "SSH_PANEL_2FA_PATH",
        "/opt/servermanager/panel/ssh-panel-2fa.json",
    )
)
VPN_ALLOWLIST_PATH = Path(
    os.environ.get(
        "VPN_ALLOWLIST_FILE",
        "/opt/servermanager/panel/vpn-allowlist.json",
    )
)
AUTH_APP_DEVICES_PATH = Path(
    os.environ.get(
        "AUTH_APP_DEVICES_FILE",
        "/opt/servermanager/panel/auth-app-devices.json",
    )
)
STICKY_VPN_IPS_PATH = Path(
    os.environ.get(
        "STICKY_VPN_IPS_FILE",
        "/opt/servermanager/panel/caddy-sticky-vpn-ips.txt",
    )
)
VPN_PEER_ACL_SCRIPT = Path(
    os.environ.get("VPN_PEER_ACL_SCRIPT", "/opt/ikev2/ensure-ikev2-peer-acl.sh")
)
# Always-on trust-circle members (router WAN, etc). Hidden from Authenticator apps.
# Default seals the Flint public WAN; override with comma/space-separated IPv4s.
VPN_CIRCLE_SEALED_IPS = os.environ.get(
    "VPN_CIRCLE_SEALED_IPS",
    "192.81.235.246",
)
_ssh_panel_2fa_lock = threading.Lock()


def _sealed_vpn_ips() -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    raw = str(VPN_CIRCLE_SEALED_IPS or "")
    for part in re.split(r"[\s,;]+", raw):
        ip = _normalize_vpn_ip(part)
        if not ip or not _is_public_ipv4(ip) or ip in seen:
            continue
        seen.add(ip)
        out.append(ip)
    return out


def _is_sealed_vpn_ip(ip: str) -> bool:
    return _normalize_vpn_ip(ip) in set(_sealed_vpn_ips())


def _read_auth_app_devices() -> dict:
    data = {"devices": [], "updated_at": 0}
    if AUTH_APP_DEVICES_PATH.is_file():
        try:
            loaded = json.loads(AUTH_APP_DEVICES_PATH.read_text(encoding="utf-8"))
            if isinstance(loaded, dict) and isinstance(loaded.get("devices"), list):
                data["devices"] = [x for x in loaded["devices"] if isinstance(x, dict)]
                data["updated_at"] = int(loaded.get("updated_at") or 0)
        except Exception:
            pass
    return data


def _write_auth_app_devices(data: dict) -> None:
    AUTH_APP_DEVICES_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "devices": list(data.get("devices") or [])[-80:],
        "updated_at": int(time.time()),
    }
    tmp = AUTH_APP_DEVICES_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    tmp.replace(AUTH_APP_DEVICES_PATH)
    try:
        os.chmod(AUTH_APP_DEVICES_PATH, 0o600)
    except Exception:
        pass


def auth_app_enrolled_lan_ips() -> set[str]:
    """LAN IPs of phones that successfully registered an enrolled Authenticator."""
    out: set[str] = set()
    for row in _read_auth_app_devices().get("devices") or []:
        ip = _normalize_vpn_ip(row.get("ip", ""))
        if _is_home_lan_ipv4(ip):
            out.add(ip)
    return out


def touch_auth_app_device(
    *,
    lan_ip: str = "",
    note: str = "",
    platform: str = "",
) -> dict:
    """Record an enrolled Authenticator's home-LAN IP so Flint pending can exempt it."""
    ip = _normalize_vpn_ip(lan_ip)
    if not ip or not _is_home_lan_ipv4(ip):
        raise ValueError("A home LAN (192.168.8.x) IPv4 address is required")
    now = int(time.time())
    data = _read_auth_app_devices()
    devices = [dict(x) for x in (data.get("devices") or []) if isinstance(x, dict)]
    by_ip = {
        _normalize_vpn_ip(x.get("ip", "")): x
        for x in devices
        if _normalize_vpn_ip(x.get("ip", ""))
    }
    row = by_ip.get(ip) or {"ip": ip, "first_seen": now}
    row.update(
        {
            "ip": ip,
            "last_seen": now,
            "enrolled": True,
            "note": (note or row.get("note") or "Authenticator app")[:120],
            "platform": (platform or row.get("platform") or "")[:40],
        }
    )
    by_ip[ip] = row
    data["devices"] = sorted(
        by_ip.values(),
        key=lambda x: int(x.get("last_seen") or 0),
        reverse=True,
    )[:80]
    _write_auth_app_devices(data)
    # Refresh Flint gate so this enrolled phone is no longer blocked while pending.
    lan_gate = Path(
        os.environ.get(
            "LAN_CIRCLE_FLINT_GATE_SCRIPT",
            "/opt/ikev2/ensure-lan-circle-flint-gate.sh",
        )
    )
    if lan_gate.is_file():
        try:
            subprocess.run(
                ["bash", str(lan_gate)],
                capture_output=True,
                text=True,
                timeout=45,
            )
        except Exception:
            pass
    return {"ok": True, "ip": ip, "devices": data["devices"]}


def _sealed_vpn_row(ip: str) -> dict:
    return {
        "ip": _normalize_vpn_ip(ip),
        "note": "Flint router WAN (sealed)",
        "approved_at": 0,
        "source": "router",
        "sealed": True,
        "hidden": True,
    }


def _ensure_sealed_vpn_allowlist(data: dict) -> tuple[dict, bool]:
    """Keep sealed router WAN IPs permanently allowed; never drop them."""
    changed = False
    sealed = _sealed_vpn_ips()
    sealed_set = set(sealed)
    allowed_in = [x for x in (data.get("allowed") or []) if isinstance(x, dict)]
    by_ip: dict[str, dict] = {}
    for row in allowed_in:
        ip = _normalize_vpn_ip(row.get("ip", ""))
        if ip:
            by_ip[ip] = dict(row)

    for ip in sealed:
        row = by_ip.get(ip) or _sealed_vpn_row(ip)
        before = dict(row)
        row["ip"] = ip
        row["sealed"] = True
        row["hidden"] = True
        row["source"] = "router"
        if not str(row.get("note") or "").strip() or "seeded from sticky" in str(row.get("note") or ""):
            row["note"] = "Flint router WAN (sealed)"
        if not row.get("approved_at"):
            row["approved_at"] = int(time.time())
        by_ip[ip] = row
        if before != row or ip not in {_normalize_vpn_ip(r.get("ip", "")) for r in allowed_in}:
            changed = True

    # Preserve non-sealed entries after sealed ones.
    rebuilt: list[dict] = []
    seen: set[str] = set()
    for ip in sealed:
        rebuilt.append(by_ip[ip])
        seen.add(ip)
    for row in allowed_in:
        ip = _normalize_vpn_ip(row.get("ip", ""))
        if not ip or ip in seen:
            continue
        if ip in sealed_set:
            continue
        rebuilt.append(row)
        seen.add(ip)

    denied = [
        r for r in (data.get("denied") or [])
        if isinstance(r, dict) and _normalize_vpn_ip(r.get("ip", "")) not in sealed_set
    ]
    pending = [
        r for r in (data.get("pending") or [])
        if isinstance(r, dict) and _normalize_vpn_ip(r.get("ip", "")) not in sealed_set
    ]
    attempts = [
        r for r in (data.get("attempts") or [])
        if isinstance(r, dict) and _normalize_vpn_ip(r.get("ip", "")) not in sealed_set
    ]
    if len(denied) != len(list(data.get("denied") or [])) or len(pending) != len(list(data.get("pending") or [])) or len(attempts) != len(list(data.get("attempts") or [])):
        changed = True
    if rebuilt != allowed_in:
        changed = True
    data["allowed"] = rebuilt
    data["denied"] = denied
    data["pending"] = pending
    data["attempts"] = attempts
    return data, changed


def _public_vpn_allowlist_view(data: dict, *, for_auth_app: bool = False) -> dict:
    """Optionally hide sealed router entries from Authenticator apps."""
    def _vis(rows: list) -> list:
        out = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            ip = _normalize_vpn_ip(row.get("ip", ""))
            if for_auth_app and (row.get("sealed") or row.get("hidden") or _is_sealed_vpn_ip(ip)):
                continue
            out.append(row)
        return out

    return {
        "allowed": _vis(list(data.get("allowed") or [])),
        "denied": _vis(list(data.get("denied") or [])),
        "pending": _vis(list(data.get("pending") or [])),
        "attempts": _vis(list(data.get("attempts") or [])),
    }


def _b32_encode_secret(raw: bytes) -> str:
    import base64 as _b64

    return _b64.b32encode(raw).decode("ascii").rstrip("=")


def _b32_decode_secret(secret: str) -> bytes:
    import base64 as _b64

    s = re.sub(r"\s+", "", str(secret or "")).upper()
    pad = "=" * ((8 - len(s) % 8) % 8)
    return _b64.b32decode(s + pad, casefold=True)


def _totp_at(secret_b32: str, for_time: float | None = None, *, step: int = 30, digits: int = 6) -> str:
    """RFC 6238 TOTP (HMAC-SHA1) without third-party deps."""
    ts = int(time.time() if for_time is None else for_time)
    counter = ts // max(1, step)
    key = _b32_decode_secret(secret_b32)
    msg = counter.to_bytes(8, "big")
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (
        ((digest[offset] & 0x7F) << 24)
        | ((digest[offset + 1] & 0xFF) << 16)
        | ((digest[offset + 2] & 0xFF) << 8)
        | (digest[offset + 3] & 0xFF)
    )
    mod = 10 ** digits
    return f"{code_int % mod:0{digits}d}"


def verify_totp_code(secret_b32: str, code: str, *, window: int = 1) -> bool:
    raw = re.sub(r"\D+", "", str(code or ""))
    if len(raw) != 6 or not secret_b32:
        return False
    now = time.time()
    for skew in range(-window, window + 1):
        expect = _totp_at(secret_b32, now + skew * 30)
        if hmac.compare_digest(expect, raw):
            return True
    return False


def _read_ssh_panel_2fa() -> dict:
    try:
        if not SSH_PANEL_2FA_PATH.is_file():
            return {
                "enabled": False,
                "method": "email",
                "device_enroll_unlocked": False,
            }
        data = json.loads(SSH_PANEL_2FA_PATH.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {
                "enabled": False,
                "method": "email",
                "device_enroll_unlocked": False,
            }
        method = str(data.get("method") or "email").strip().lower()
        if method not in ("email", "app"):
            method = "email"
        return {
            "enabled": bool(data.get("enabled")),
            "method": method,
            "totp_secret": str(data.get("totp_secret") or ""),
            "email_to": str(data.get("email_to") or EMAIL_CODE_TO),
            "updated_at": data.get("updated_at"),
            "device_enroll_unlocked": bool(data.get("device_enroll_unlocked")),
        }
    except Exception:
        return {
            "enabled": False,
            "method": "email",
            "device_enroll_unlocked": False,
        }


def ssh_panel_2fa_enabled() -> bool:
    return bool(_read_ssh_panel_2fa().get("enabled"))


def ssh_panel_2fa_method() -> str:
    return str(_read_ssh_panel_2fa().get("method") or "email")


def auth_app_device_enroll_unlocked() -> bool:
    """Whether phones may add a new authenticator account via Enter secret."""
    return bool(_read_ssh_panel_2fa().get("device_enroll_unlocked"))


def auth_app_enroll_status() -> dict:
    """Public status for Authenticator PWAs (no secret material)."""
    unlocked = auth_app_device_enroll_unlocked()
    return {
        "enroll_unlocked": unlocked,
        "device_enroll_unlocked": unlocked,
        "auth_app_path": "/auth-app-iphone.html",
        "auth_app_android_path": "/auth-app.html",
        "message": (
            "Enrollment unlocked — Enter secret is available in the Authenticator app."
            if unlocked
            else "Enrollment locked — Enter secret is hidden until unlocked in Security."
        ),
    }


def _write_ssh_panel_2fa(
    *,
    enabled: bool,
    method: str = "email",
    totp_secret: str = "",
    device_enroll_unlocked: bool | None = None,
) -> None:
    SSH_PANEL_2FA_PATH.parent.mkdir(parents=True, exist_ok=True)
    method_n = "app" if str(method).lower() == "app" else "email"
    prev = _read_ssh_panel_2fa()
    secret = totp_secret or str(prev.get("totp_secret") or "")
    if method_n != "app":
        secret = ""
    enroll_flag = (
        bool(device_enroll_unlocked)
        if device_enroll_unlocked is not None
        else bool(prev.get("device_enroll_unlocked"))
    )
    payload = {
        "enabled": bool(enabled),
        "method": method_n,
        "totp_secret": secret if enabled and method_n == "app" else secret,
        "updated_at": int(time.time()),
        "email_to": EMAIL_CODE_TO,
        "device_enroll_unlocked": enroll_flag,
    }
    if not enabled:
        # Keep secret only while enabled as app; wipe on disable for safety.
        payload["totp_secret"] = ""
        payload["method"] = method_n
        # Disabling 2FA also locks new-device enrollment.
        payload["device_enroll_unlocked"] = False
    with _ssh_panel_2fa_lock:
        SSH_PANEL_2FA_PATH.write_text(
            json.dumps(payload, indent=2) + "\n", encoding="utf-8"
        )
        try:
            os.chmod(SSH_PANEL_2FA_PATH, 0o600)
        except Exception:
            pass


def set_auth_app_device_enroll(token: str | None, *, unlocked: bool) -> dict:
    """Lock/unlock Enter-secret enrollment for new Authenticator devices."""
    if not token or not session_valid(token):
        raise ValueError("Not signed in")
    st = ssh_panel_unlock_status(token)
    if not st.get("unlocked"):
        raise ValueError("Unlock the panel before changing device enrollment")
    cfg = _read_ssh_panel_2fa()
    want = bool(unlocked)
    if want and not (cfg.get("enabled") and cfg.get("method") == "app"):
        raise ValueError(
            "Enable Authenticator app two-factor before unlocking new-device enrollment"
        )
    secret = str(cfg.get("totp_secret") or "").strip()
    if want and not secret:
        raise ValueError("No authenticator secret is enrolled yet")
    _write_ssh_panel_2fa(
        enabled=bool(cfg.get("enabled")),
        method=str(cfg.get("method") or "app"),
        totp_secret=secret,
        device_enroll_unlocked=want,
    )
    # Enrollment unlock opens Flint for pending LAN so new phones can reach /auth-app.
    lan_gate = Path(
        os.environ.get(
            "LAN_CIRCLE_FLINT_GATE_SCRIPT",
            "/opt/ikev2/ensure-lan-circle-flint-gate.sh",
        )
    )
    if lan_gate.is_file():
        try:
            subprocess.run(
                ["bash", str(lan_gate)],
                capture_output=True,
                text=True,
                timeout=45,
            )
        except Exception:
            pass
    out: dict = {
        "ok": True,
        "device_enroll_unlocked": want,
        "enroll_unlocked": want,
        "two_factor_enabled": bool(cfg.get("enabled")),
        "two_factor_method": str(cfg.get("method") or "app"),
        "auth_app_path": "/auth-app-iphone.html",
        "auth_app_android_path": "/auth-app.html",
        "message": (
            "New-device enrollment unlocked. Enter secret is visible in the Authenticator app until you lock it again."
            if want
            else "New-device enrollment locked. Enter secret is hidden in the Authenticator app."
        ),
    }
    if want and secret:
        out["enroll"] = _totp_provisioning(secret)
    return out


def _normalize_vpn_ip(raw: str) -> str:
    ip = str(raw or "").strip()
    if "/" in ip:
        ip = ip.split("/", 1)[0].strip()
    return ip


def _is_public_ipv4(ip: str) -> bool:
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip or ""):
        return False
    parts = [int(x) for x in ip.split(".")]
    if parts[0] == 10 or parts[0] == 127:
        return False
    if parts[0] == 192 and parts[1] == 168:
        return False
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return False
    if parts[0] == 100 and 64 <= parts[1] <= 127:
        return False
    return True


def _is_home_lan_ipv4(ip: str) -> bool:
    """True for Flint home LAN clients (192.168.8.0/24), excluding network/broadcast."""
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip or ""):
        return False
    parts = [int(x) for x in ip.split(".")]
    if parts[0] != 192 or parts[1] != 168 or parts[2] != 8:
        return False
    if parts[3] in (0, 255, 1):  # network, broadcast, Flint router
        return False
    return True


def _lan_circle_skip_ips() -> set[str]:
    """Always-on LAN infra — never park these in pending."""
    skip = {
        ROUTER_ADMIN_HOST,
        PROXMOX_HOST,
        PLEX_HOST,
        "192.168.8.1",
    }
    for raw in (
        os.environ.get("BUFFALO_HOST", ""),
        urlparse(BUFFALO_UPSTREAM).hostname or "",
        urlparse(NAS_FILES_UPSTREAM).hostname or "",
        FTP_HOST,
        os.environ.get("NAS_SMB_HOST", ""),
    ):
        host = str(raw or "").strip()
        if host and (
            _is_home_lan_ipv4(host)
            or (host.startswith("192.168.8.") and bool(IP_RE.match(host)))
        ):
            skip.add(host)
    return {_normalize_vpn_ip(x) for x in skip if x}


def _is_circle_candidate_ip(ip: str) -> bool:
    """Public WAN or home LAN client IP may enter the trust-circle lists."""
    ip_n = _normalize_vpn_ip(ip)
    return bool(ip_n) and (_is_public_ipv4(ip_n) or _is_home_lan_ipv4(ip_n))


def _empty_vpn_allowlist() -> dict:
    return {"allowed": [], "denied": [], "pending": [], "attempts": []}


def sync_offline_lan_into_pending(data: dict | None = None) -> dict:
    """Park known LAN devices that are not allowed/denied into pending.

    Both online and offline DHCP/ARP entries are offered for circle approval.
    (Home Wi-Fi NATs to the sealed router WAN, so pending is also enforced on
    Flint pre-NAT via ensure-lan-circle-flint-gate.sh.)
    """
    data = dict(data or _read_vpn_allowlist())
    now = int(time.time())
    try:
        lan = read_lan_devices()
    except Exception:
        lan = {"ok": False, "devices": []}
    devices = list(lan.get("devices") or []) if lan.get("ok") else []
    if not devices:
        return data

    allowed = {
        _normalize_vpn_ip(x.get("ip", ""))
        for x in (data.get("allowed") or [])
        if isinstance(x, dict)
    }
    denied = {
        _normalize_vpn_ip(x.get("ip", ""))
        for x in (data.get("denied") or [])
        if isinstance(x, dict)
    }
    pending_rows = [x for x in (data.get("pending") or []) if isinstance(x, dict)]
    skip = _lan_circle_skip_ips()
    changed = False

    candidates: list[dict] = []
    for d in devices:
        ip = _normalize_vpn_ip(d.get("ip", ""))
        if not _is_home_lan_ipv4(ip) or ip in skip:
            continue
        candidates.append(d)

    # Drop auto LAN-pending rows once approved/denied.
    pending_by_ip: dict = {}
    for row in pending_rows:
        ip = _normalize_vpn_ip(row.get("ip", ""))
        is_lan_row = str(row.get("source") or "") in (
            "lan-offline",
            "lan",
        ) or str(row.get("kind") or "") == "lan"
        if is_lan_row and _is_home_lan_ipv4(ip) and (ip in allowed or ip in denied):
            changed = True
            continue
        if ip:
            pending_by_ip[ip] = dict(row)
        else:
            pending_by_ip[f"_row_{id(row)}"] = dict(row)

    for d in candidates:
        ip = _normalize_vpn_ip(d.get("ip", ""))
        if not ip or ip in allowed or ip in denied:
            continue
        name = str(d.get("hostname") or "").strip()
        mac = str(d.get("mac") or "").strip().lower()
        online = bool(d.get("online"))
        note = name or (f"LAN {mac}" if mac else "LAN device")
        source = "lan" if online else "lan-offline"
        existing = pending_by_ip.get(ip)
        if existing:
            before = dict(existing)
            existing["last_seen"] = now
            existing["source"] = source
            existing["vip"] = existing.get("vip") or ""
            existing["note"] = note[:120]
            existing["name"] = name[:64]
            existing["mac"] = mac
            existing["kind"] = "lan"
            existing["online"] = online
            if str(existing.get("status") or "") != "denied":
                existing["status"] = "pending"
            if existing != before:
                changed = True
            continue
        pending_by_ip[ip] = {
            "ip": ip,
            "vip": "",
            "first_seen": now,
            "last_seen": now,
            "count": 1,
            "status": "pending",
            "source": source,
            "kind": "lan",
            "note": note[:120],
            "name": name[:64],
            "mac": mac,
            "online": online,
        }
        changed = True

    data["pending"] = sorted(
        [v for v in pending_by_ip.values() if isinstance(v, dict)],
        key=lambda x: int(x.get("last_seen") or 0),
        reverse=True,
    )[:80]
    if changed:
        _write_vpn_allowlist(data)
    return data


def build_vpn_allowlist_status(*, for_auth_app: bool = False) -> dict:
    data = sync_offline_lan_into_pending(_read_vpn_allowlist())
    view = _public_vpn_allowlist_view(data, for_auth_app=for_auth_app)
    enrolled = auth_app_enrolled_lan_ips()
    pending = []
    for row in view.get("pending") or []:
        if not isinstance(row, dict):
            continue
        item = dict(row)
        ip = _normalize_vpn_ip(item.get("ip", ""))
        if ip in enrolled:
            item["auth_app"] = True
            item["auth_app_enrolled"] = True
        pending.append(item)
    recent = list(reversed(list(view.get("attempts") or [])[-40:]))
    return {
        "ok": True,
        "allowed": view.get("allowed") or [],
        "denied": view.get("denied") or [],
        "pending": pending,
        "attempts": recent,
        "guest_dns": os.environ.get("VPN_GUEST_DNS", "1.1.1.1"),
        "circle_dns": os.environ.get("OVPN_DNS_ADGUARD", "10.42.42.44"),
        "sticky_file": str(STICKY_VPN_IPS_PATH),
        "auth_app_devices": sorted(enrolled),
        "sealed_ips": [] if for_auth_app else list(_sealed_vpn_ips()),
        "detail": (
            "Unapproved IKEv2 clients keep internet via guest DNS; "
            "approve a WAN IP (Authenticator unlock) to enter the trust circle. "
            "Home LAN devices stay pending until approved; pending/denied LAN IPs "
            "are blocked on the Flint router before NAT — except enrolled "
            "Authenticator phones, which keep portal access while remaining pending."
            + (
                ""
                if for_auth_app
                else " Sealed router WAN stays in the circle and is hidden from Authenticator apps."
            )
        ),
    }


def mutate_vpn_allowlist(*, action: str, ip: str, note: str = "", source: str = "security-ui") -> dict:
    ip_n = _normalize_vpn_ip(ip)
    if not ip_n or not _is_circle_candidate_ip(ip_n):
        raise ValueError("A public WAN or home LAN (192.168.8.x) IPv4 address is required")
    action_n = str(action or "").strip().lower()
    if action_n not in ("approve", "revoke", "deny"):
        raise ValueError("action must be approve, revoke, or deny")
    if _is_sealed_vpn_ip(ip_n) and action_n in ("revoke", "deny"):
        raise ValueError("Sealed router WAN cannot be revoked or denied")
    data = _read_vpn_allowlist()
    now = int(time.time())
    src = (source or "security-ui").strip()[:40] or "security-ui"
    is_lan = _is_home_lan_ipv4(ip_n)

    def _without(rows: list, target: str) -> list:
        out = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            row_ip = _normalize_vpn_ip(row.get("ip", ""))
            if row_ip == target:
                # Never strip sealed rows during approve rebuild either —
                # approve path re-adds below; revoke/deny already blocked.
                if row.get("sealed") or _is_sealed_vpn_ip(row_ip):
                    out.append(row)
                    continue
                continue
            out.append(row)
        return out

    data["allowed"] = _without(list(data.get("allowed") or []), ip_n)
    data["denied"] = _without(list(data.get("denied") or []), ip_n)
    data["pending"] = _without(list(data.get("pending") or []), ip_n)

    if action_n == "approve":
        if _is_sealed_vpn_ip(ip_n):
            # Already permanent; just ensure sealed metadata.
            data, _ = _ensure_sealed_vpn_allowlist(data)
        else:
            row = {
                "ip": ip_n,
                "note": (note or "").strip()[:120],
                "approved_at": now,
                "source": src,
            }
            if is_lan:
                row["kind"] = "lan"
                row["source"] = src if src.startswith("auth-app") or src == "security-ui" else src
            data["allowed"].append(row)
    elif action_n == "deny":
        data["denied"].append(
            {
                "ip": ip_n,
                "note": (note or "").strip()[:120],
                "denied_at": now,
                "source": src,
                **({"kind": "lan"} if is_lan else {}),
            }
        )
        data["pending"].append(
            {
                "ip": ip_n,
                "status": "denied",
                "first_seen": now,
                "last_seen": now,
                "count": 1,
                **(
                    {
                        "source": "lan-offline",
                        "kind": "lan",
                        "vip": "",
                    }
                    if is_lan
                    else {}
                ),
            }
        )
    # revoke: already removed from allowed/denied (sealed preserved)

    data, _ = _ensure_sealed_vpn_allowlist(data)
    _write_vpn_allowlist(data)
    sync_msg = _run_vpn_peer_acl_sync()
    for_auth = str(source or "").startswith("auth-app")
    return {
        "ok": True,
        "action": action_n,
        "ip": ip_n,
        "sync": sync_msg,
        "vpn_allowlist": build_vpn_allowlist_status(for_auth_app=for_auth),
    }


def _read_vpn_allowlist() -> dict:
    data = _empty_vpn_allowlist()
    if VPN_ALLOWLIST_PATH.is_file():
        try:
            loaded = json.loads(VPN_ALLOWLIST_PATH.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                for key in data:
                    if isinstance(loaded.get(key), list):
                        data[key] = loaded[key]
        except Exception:
            pass
    # Seed sticky WAN entries so existing home IP stays trusted.
    sticky_ips: list[str] = []
    if STICKY_VPN_IPS_PATH.is_file():
        try:
            for line in STICKY_VPN_IPS_PATH.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines():
                raw = line.strip()
                if not raw or raw.startswith("#"):
                    continue
                sticky_ips.append(_normalize_vpn_ip(raw))
        except Exception:
            sticky_ips = []
    allowed_set = {
        _normalize_vpn_ip(x.get("ip", ""))
        for x in data["allowed"]
        if isinstance(x, dict)
    }
    changed = False
    for ip in sticky_ips:
        if ip and _is_public_ipv4(ip) and ip not in allowed_set and not _is_sealed_vpn_ip(ip):
            data["allowed"].append(
                {
                    "ip": ip,
                    "note": "seeded from sticky WAN",
                    "approved_at": int(time.time()),
                    "source": "sticky",
                }
            )
            allowed_set.add(ip)
            changed = True
    data, sealed_changed = _ensure_sealed_vpn_allowlist(data)
    if changed or sealed_changed or not VPN_ALLOWLIST_PATH.is_file():
        _write_vpn_allowlist(data)
    return data


def _write_vpn_allowlist(data: dict) -> None:
    data, _ = _ensure_sealed_vpn_allowlist(data)
    VPN_ALLOWLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "allowed": list(data.get("allowed") or []),
        "denied": list(data.get("denied") or []),
        "pending": list(data.get("pending") or []),
        "attempts": list(data.get("attempts") or [])[-200:],
        "updated_at": int(time.time()),
    }
    tmp = VPN_ALLOWLIST_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    tmp.replace(VPN_ALLOWLIST_PATH)
    try:
        os.chmod(VPN_ALLOWLIST_PATH, 0o600)
    except Exception:
        pass
    # Keep sticky file in sync with allowlist (Caddy peer ACL reads sticky).
    lines = [
        "# Managed by Security → VPN trust circle",
        "# Approved sticky WAN + LAN IPs (one IPv4 /32 per line)",
        "# Sealed router WAN IPs are always included and cannot be revoked from apps.",
        "# Blanket 192.168.8.0/24 is never written — approved LAN /32s only.",
    ]
    for row in payload["allowed"]:
        if not isinstance(row, dict):
            continue
        ip = _normalize_vpn_ip(row.get("ip", ""))
        if ip and (_is_public_ipv4(ip) or _is_home_lan_ipv4(ip)):
            lines.append(f"{ip}/32")
    STICKY_VPN_IPS_PATH.parent.mkdir(parents=True, exist_ok=True)
    STICKY_VPN_IPS_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _run_vpn_peer_acl_sync() -> str:
    script = VPN_PEER_ACL_SCRIPT
    if not script.is_file():
        return "peer-acl script missing"
    try:
        proc = subprocess.run(
            ["bash", str(script)],
            capture_output=True,
            text=True,
            timeout=90,
        )
        out = ((proc.stdout or "") + (proc.stderr or "")).strip()
        return out[-500:] if out else ("ok" if proc.returncode == 0 else "failed")
    except Exception as exc:
        return str(exc)


def verify_auth_app_totp(code: str) -> bool:
    """Validate a TOTP from the phone authenticator PWA against the enrolled secret."""
    st = _read_ssh_panel_2fa()
    secret = str(st.get("totp_secret") or "").strip()
    if not st.get("enabled") or str(st.get("method") or "") != "app" or not secret:
        return False
    return verify_totp_code(secret, code, window=1)


def require_auth_app_totp(code: str) -> None:
    if not verify_auth_app_totp(code):
        raise ValueError("Incorrect or missing authenticator code")


def _totp_provisioning(secret_b32: str) -> dict:
    from urllib.parse import quote

    account = f"portal@{PORTAL_HOST}"
    issuer = "ServerManager"
    label = quote(f"{issuer}:{account}")
    uri = (
        f"otpauth://totp/{label}?secret={secret_b32}"
        f"&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"
    )
    return {
        "secret": secret_b32,
        "otpauth_url": uri,
        "account": account,
        "issuer": issuer,
        "auth_app_path": f"/auth-app-iphone.html#secret={secret_b32}&issuer={quote(issuer)}&account={quote(account)}",
    }


def _check_ssh_panel_password(password: str) -> None:
    if not AUTH_PASS:
        raise ValueError("Password is not configured")
    expected = f"!!{AUTH_PASS}!!"
    if not hmac.compare_digest(str(password or ""), expected):
        time.sleep(0.35)
        raise ValueError("Incorrect password")


def set_ssh_panel_2fa(
    token: str | None,
    *,
    enabled: bool,
    password: str = "",
    code: str = "",
    client_ip: str = "",
    method: str = "",
    enroll_secret: str = "",
) -> dict:
    """Enable/disable 2FA for the VPS login panel (email or authenticator app)."""
    if not token or not session_valid(token):
        raise ValueError("Not signed in")
    st = ssh_panel_unlock_status(token)
    if not st.get("unlocked"):
        raise ValueError("Unlock the panel before changing two-factor settings")
    want = bool(enabled)
    cfg = _read_ssh_panel_2fa()
    method_n = str(method or cfg.get("method") or "app").strip().lower()
    if method_n not in ("email", "app"):
        method_n = "app"
    if want and want == bool(cfg.get("enabled")) and method_n == cfg.get("method"):
        return {
            "ok": True,
            "two_factor_enabled": True,
            "two_factor_method": cfg.get("method"),
            "email_to": EMAIL_CODE_TO,
            "message": "Two-factor already enabled.",
        }
    if want:
        _check_ssh_panel_password(password)
        if method_n == "app":
            secret = str(enroll_secret or "").strip()
            if not secret:
                secret = _b32_encode_secret(secrets.token_bytes(20))
                prov = _totp_provisioning(secret)
                return {
                    "ok": True,
                    "need_code": True,
                    "two_factor_enabled": False,
                    "two_factor_method": "app",
                    "enroll": prov,
                    "enroll_secret": secret,
                    "email_to": EMAIL_CODE_TO,
                    "message": "Scan the QR in the Authenticator app, then enter the 6-digit code.",
                }
            if not verify_totp_code(secret, code):
                time.sleep(0.25)
                raise ValueError("Incorrect authenticator code")
            _write_ssh_panel_2fa(enabled=True, method="app", totp_secret=secret)
            return {
                "ok": True,
                "two_factor_enabled": True,
                "two_factor_method": "app",
                "email_to": EMAIL_CODE_TO,
                "auth_app_path": "/auth-app-iphone.html",
                "message": "Authenticator app two-factor enabled.",
            }
        # Email method
        key = f"ssh-2fa-enable:{token}"
        if not str(code or "").strip():
            sent = send_email_test_code(client_ip or "panel", key=key)
            return {
                "ok": True,
                "need_code": True,
                "two_factor_enabled": False,
                "two_factor_method": "email",
                "email_to": EMAIL_CODE_TO,
                "message": sent.get("message")
                or "Enter the email code to enable two-factor.",
            }
        verify_email_test_code(client_ip or "panel", code, key=key)
        _write_ssh_panel_2fa(enabled=True, method="email", totp_secret="")
        return {
            "ok": True,
            "two_factor_enabled": True,
            "two_factor_method": "email",
            "email_to": EMAIL_CODE_TO,
            "message": "Two-factor enabled.",
        }
    _write_ssh_panel_2fa(enabled=False, method=method_n, totp_secret="")
    return {
        "ok": True,
        "two_factor_enabled": False,
        "two_factor_method": method_n,
        "email_to": EMAIL_CODE_TO,
        "message": "Two-factor disabled for VPS login panel.",
    }


def _purge_ssh_panel_unlocks(now: float | None = None) -> None:
    ts = now if now is not None else time.time()
    with _ssh_panel_unlocks_lock:
        dead = [tok for tok, exp in _ssh_panel_unlocks.items() if exp <= ts]
        for tok in dead:
            _ssh_panel_unlocks.pop(tok, None)


def ssh_panel_unlock_status(token: str | None) -> dict:
    """Whether this portal session may mutate VPS login / SSH keys."""
    now = time.time()
    _purge_ssh_panel_unlocks(now)
    two_factor = ssh_panel_2fa_enabled()
    method = ssh_panel_2fa_method() if two_factor else "email"
    enroll_unlocked = auth_app_device_enroll_unlocked()
    required = ["portal_password"]
    if two_factor:
        required.append("app_code" if method == "app" else "email_code")
    base = {
        "two_factor_enabled": two_factor,
        "two_factor_method": method,
        "device_enroll_unlocked": enroll_unlocked,
        "enroll_unlocked": enroll_unlocked,
        "auth_app_path": "/auth-app-iphone.html",
        "auth_app_android_path": "/auth-app.html",
        "email_to": EMAIL_CODE_TO,
        "unlock_seconds": SSH_PANEL_UNLOCK_SECONDS,
        "required": required,
    }
    if not token or not session_valid(token):
        return {
            **base,
            "unlocked": False,
            "expires_at": None,
            "expires_in": 0,
        }
    with _ssh_panel_unlocks_lock:
        exp = _ssh_panel_unlocks.get(token)
    if not exp or exp <= now:
        return {
            **base,
            "unlocked": False,
            "expires_at": None,
            "expires_in": 0,
        }
    return {
        **base,
        "unlocked": True,
        "expires_at": int(exp),
        "expires_in": max(0, int(exp - now)),
    }


def unlock_ssh_panel(
    token: str | None,
    password: str,
    *,
    code: str = "",
    client_ip: str = "",
) -> dict:
    """Unlock SSH panel with !!password!! (+ authenticator or email code when 2FA on)."""
    if not token or not session_valid(token):
        raise ValueError("Not signed in")
    _check_ssh_panel_password(password)
    cfg = _read_ssh_panel_2fa()
    two_factor = bool(cfg.get("enabled"))
    method = str(cfg.get("method") or "email")
    if two_factor:
        if method == "app":
            secret = str(cfg.get("totp_secret") or "")
            if not str(code or "").strip():
                return {
                    "ok": True,
                    "unlocked": False,
                    "need_code": True,
                    "two_factor_enabled": True,
                    "two_factor_method": "app",
                    "auth_app_path": "/auth-app-iphone.html",
                    "email_to": EMAIL_CODE_TO,
                    "expires_at": None,
                    "expires_in": 0,
                    "unlock_seconds": SSH_PANEL_UNLOCK_SECONDS,
                    "message": "Enter the code from the Authenticator app.",
                }
            if not verify_totp_code(secret, code):
                time.sleep(0.25)
                raise ValueError("Incorrect authenticator code")
        else:
            key = f"ssh-unlock:{token}"
            if not str(code or "").strip():
                sent = send_email_test_code(client_ip or "panel", key=key)
                return {
                    "ok": True,
                    "unlocked": False,
                    "need_code": True,
                    "two_factor_enabled": True,
                    "two_factor_method": "email",
                    "email_to": EMAIL_CODE_TO,
                    "expires_at": None,
                    "expires_in": 0,
                    "unlock_seconds": SSH_PANEL_UNLOCK_SECONDS,
                    "message": sent.get("message")
                    or "Enter the email verification code to unlock.",
                }
            verify_email_test_code(client_ip or "panel", code, key=key)
    now = time.time()
    exp = now + max(60, SSH_PANEL_UNLOCK_SECONDS)
    _purge_ssh_panel_unlocks(now)
    with _ssh_panel_unlocks_lock:
        _ssh_panel_unlocks[token] = exp
    return {
        "ok": True,
        "unlocked": True,
        "need_code": False,
        "two_factor_enabled": two_factor,
        "two_factor_method": method if two_factor else "email",
        "auth_app_path": "/auth-app-iphone.html",
        "email_to": EMAIL_CODE_TO,
        "expires_at": int(exp),
        "expires_in": int(exp - now),
        "unlock_seconds": SSH_PANEL_UNLOCK_SECONDS,
        "message": f"VPS login panel unlocked for {SSH_PANEL_UNLOCK_SECONDS // 60} minutes.",
    }


def lock_ssh_panel(token: str | None) -> dict:
    if token:
        with _ssh_panel_unlocks_lock:
            _ssh_panel_unlocks.pop(token, None)
    method = ssh_panel_2fa_method() if ssh_panel_2fa_enabled() else "email"
    return {
        "ok": True,
        "unlocked": False,
        "need_code": False,
        "two_factor_enabled": ssh_panel_2fa_enabled(),
        "two_factor_method": method,
        "auth_app_path": "/auth-app-iphone.html",
        "email_to": EMAIL_CODE_TO,
        "expires_at": None,
        "expires_in": 0,
        "unlock_seconds": SSH_PANEL_UNLOCK_SECONDS,
        "message": "VPS login panel locked.",
    }


# ServerManager Files theme (desktop + mobile) — injected into /nas-files HTML.
# Matches portal / Pi-hole / AdGuard palette (Sora, #0a0f0d, #3ddea0).
NAS_FILES_MOBILE_CSS = """
:root{
  --sm-bg0:#0a0f0d;
  --sm-bg1:#111916;
  --sm-bg2:#17221d;
  --sm-bg3:#1e2b25;
  --sm-line:rgba(170,210,185,.14);
  --sm-text:#e8f2ec;
  --sm-muted:#84998c;
  --sm-accent:#3ddea0;
  --sm-accent-dim:rgba(61,222,160,.14);
  --sm-accent-strong:rgba(61,222,160,.35);
  --sm-danger:#ff6b6b;
  --sm-warn:#e2b45a;
  --sm-radius:12px;
  --sm-tap:40px;
  --sm-safe-top:env(safe-area-inset-top,0px);
  --sm-safe-bottom:env(safe-area-inset-bottom,0px);
  --sm-safe-left:env(safe-area-inset-left,0px);
  --sm-safe-right:env(safe-area-inset-right,0px);
}

/* Layout shell */
html,body{
  height:100%!important;width:100%!important;margin:0!important;padding:0!important;
  overflow:hidden!important;-webkit-text-size-adjust:100%;text-size-adjust:100%;zoom:1!important;
  overscroll-behavior:none!important;overscroll-behavior-y:none!important;
}
body{
  position:relative!important;box-sizing:border-box!important;
  background:var(--sm-bg0)!important;color:var(--sm-text)!important;
  font-family:"Sora",system-ui,-apple-system,sans-serif!important;
}
html,body,.x-viewport,.x-border-layout-ct,.x-panel,.x-panel-body,.x-toolbar,.x-panel-header,
.x-panel-bwrap,.x-panel-tbar,.x-panel-bbar,.x-grid3,.x-grid3-viewport,.x-tree,.x-menu,
.x-window,.x-form-label,.x-form-item-label,.x-btn-text,.x-combo-list,.x-editable,.thumb{
  font-family:"Sora",system-ui,-apple-system,sans-serif!important;
  color:var(--sm-text)!important;
}
body *,body *::before,body *::after{text-shadow:none!important;box-shadow:none!important}
.x-viewport,.x-border-layout-ct{
  min-height:100%!important;background:var(--sm-bg0)!important;
  overscroll-behavior:none!important;overscroll-behavior-y:none!important}
.x-fullscreen,.x-panel.x-fullscreen,#maindataview{
  position:absolute!important;left:0!important;top:0!important;right:0!important;bottom:0!important;
  width:100%!important;height:100%!important;max-height:100%!important}
.x-scroller,.x-scroll-container,.x-dataview,.x-list-inner,
#maindataview .x-panel-body,#maindataview .x-dataview,
#main-panel .x-panel-body,.icon-panel .x-panel-body,
#main-panel .x-grid3-scroller,.x-grid3-scroller{
  touch-action:pan-y!important;-ms-touch-action:pan-y!important;
  -webkit-overflow-scrolling:touch;overflow-y:auto!important;
  overscroll-behavior:none!important;overscroll-behavior-y:none!important}
.x-mask.sm-nas-mask-clear,.x-mask-msg.sm-nas-mask-clear{display:none!important;pointer-events:none!important}

/* In-app file viewer */
#sm-nas-viewer{
  background:rgba(10,15,13,.96)!important;color:var(--sm-text)!important;
  font-family:"Sora",system-ui,-apple-system,sans-serif!important}
#sm-nas-viewer #sm-nas-viewer-close{
  background:var(--sm-bg3)!important;color:var(--sm-text)!important;border-radius:10px!important}
#sm-nas-viewer #sm-nas-viewer-dl{
  background:var(--sm-accent)!important;color:#062016!important;border-radius:10px!important;
  font-weight:700!important;text-decoration:none!important}
#sm-nas-viewer #sm-nas-viewer-title{color:var(--sm-text)!important}

/* Hide Buffalo legacy chrome — match Pi-hole/AdGuard clean embed */
#footer-panel,.footer,#copyright,#version-text,
.logo,.dummy-button,#loading-cancel,#powered-by,
#header-logo img,.product-name,#BUFFALO_LOGO,img[src*="logo.png"],img[src*="buffalo"]{
  display:none!important;height:0!important;min-height:0!important;width:0!important;
  margin:0!important;padding:0!important;overflow:hidden!important;border:0!important;
  background:none!important}

/* Hide Buffalo WebAccess "Displaying... (large number of items)" overlay */
#loading-main,#loading-mask,#loading-text,#loading-cancel,
#loading-main .loading-indicator,#loading-main img{
  display:none!important;visibility:hidden!important;opacity:0!important;
  pointer-events:none!important;height:0!important;width:0!important;
  max-height:0!important;overflow:hidden!important;border:0!important;
  margin:0!important;padding:0!important}

/* Kill Ext framed skins / gradients everywhere */
.x-panel,.x-panel-body,.x-panel-bwrap,.x-panel-bbar,.x-panel-tbar,.x-panel-header,
.x-toolbar,.x-border-layout-ct,.x-grid3,.x-grid3-header,.x-grid3-body,.x-grid3-row,
.x-tree-node-el,.x-menu,.x-window,.x-window-tl,.x-window-tr,.x-window-tc,
.x-window-ml,.x-window-mr,.x-window-mc,.x-window-bl,.x-window-br,.x-window-bc,
.x-window-plain .x-window-mc,.x-panel-noborder .x-panel-body-noborder,
.x-toolbar-ct,.x-toolbar-left,.x-toolbar-right,.x-toolbar-right-ct,
.x-panel-tl,.x-panel-tr,.x-panel-tc,.x-panel-ml,.x-panel-mr,.x-panel-mc,
.x-panel-bl,.x-panel-br,.x-panel-bc,.x-panel-nofooter .x-panel-bc,
.x-panel-btns-ct,.x-panel-body-noheader,.x-panel-body-noborder{
  background:var(--sm-bg1)!important;background-image:none!important;
  border-color:var(--sm-line)!important;color:var(--sm-text)!important;
  box-shadow:none!important}
.x-panel-body{background:var(--sm-bg0)!important}
.x-panel-header,.x-panel-header-text,.x-panel-header-text-container,
.x-unselectable .x-panel-header-text{
  background:var(--sm-bg2)!important;background-image:none!important;
  color:var(--sm-text)!important;font-weight:600!important;font-size:13px!important;
  border-color:var(--sm-line)!important;padding:8px 12px!important}
.x-panel-header .x-tool,
.x-tool-toggle,.x-tool-close,.x-tool-maximize,.x-tool-minimize,.x-tool-restore,
.x-tool-collapse-west,.x-tool-expand-west,.x-tool-collapse-east,.x-tool-expand-east{
  filter:invert(1) brightness(1.25);opacity:.9}
.x-panel-collapsed .x-panel-header{background:var(--sm-bg2)!important}

/* Top menus + toolbars */
#menu-bar,.x-toolbar,#icon-panel,.x-panel-tbar .x-toolbar,#status-bar{
  background:var(--sm-bg1)!important;background-image:none!important;
  border:0!important;border-bottom:1px solid var(--sm-line)!important;
  min-height:var(--sm-tap)!important;padding:4px 8px!important}
#menu-bar .x-btn,#icon-panel .x-btn,.x-toolbar .x-btn,.x-btn{
  background:transparent!important;background-image:none!important;
  border:0!important;box-shadow:none!important;min-height:36px!important;margin:0 2px!important;
  border-radius:10px!important}
#menu-bar .x-btn-tl,#menu-bar .x-btn-tr,#menu-bar .x-btn-tc,
#menu-bar .x-btn-ml,#menu-bar .x-btn-mr,#menu-bar .x-btn-mc,
#menu-bar .x-btn-bl,#menu-bar .x-btn-br,#menu-bar .x-btn-bc,
#icon-panel .x-btn-tl,#icon-panel .x-btn-tr,#icon-panel .x-btn-tc,
#icon-panel .x-btn-ml,#icon-panel .x-btn-mr,#icon-panel .x-btn-mc,
#icon-panel .x-btn-bl,#icon-panel .x-btn-br,#icon-panel .x-btn-bc,
.x-toolbar .x-btn-tl,.x-toolbar .x-btn-tr,.x-toolbar .x-btn-tc,
.x-toolbar .x-btn-ml,.x-toolbar .x-btn-mr,.x-toolbar .x-btn-mc,
.x-toolbar .x-btn-bl,.x-toolbar .x-btn-br,.x-toolbar .x-btn-bc,
.x-btn-tl,.x-btn-tr,.x-btn-tc,.x-btn-ml,.x-btn-mr,.x-btn-mc,
.x-btn-bl,.x-btn-br,.x-btn-bc{
  background:transparent!important;background-image:none!important}
#menu-bar .x-btn-text,#icon-panel .x-btn-text,.x-toolbar .x-btn-text,
#menu-bar .x-menu-item-text,.x-menu-item-text,.x-btn button{
  color:var(--sm-text)!important;font-size:12px!important;font-weight:500!important}
#menu-bar .x-btn-over,#icon-panel .x-btn-over,.x-toolbar .x-btn-over,
#menu-bar .x-btn-click,#icon-panel .x-btn-click,.x-btn-over,.x-btn-focus,
.x-btn-pressed,.x-btn-menu-active{
  background:var(--sm-accent-dim)!important;border-radius:10px!important}
.user-name,#userName,.x-status-text{color:var(--sm-muted)!important;font-size:12px!important}
#login_button,#logout_button,.x-btn-text-icon .x-btn-text{color:var(--sm-accent)!important}
.x-toolbar-separator,.xtb-sep{border-left-color:var(--sm-line)!important;background:var(--sm-line)!important}

/* Hide WebAccess action icon toolbar (Open/Download/…) — File menu has equivalents */
#icon-panel,
#icon-panel .x-toolbar,
#icon-panel .x-panel-body,
#icon-panel .x-panel-bwrap,
#btn_open,#btn_download,#btn_newfolder,#btn_remove,#btn_rename,#btn_copy,#btn_move,#btn_upload,#btn_clearthumb,#btn_mailurl,#btn_onetimeurl{
  display:none!important;visibility:hidden!important;
  height:0!important;min-height:0!important;max-height:0!important;
  overflow:hidden!important;padding:0!important;margin:0!important;
  border:0!important;line-height:0!important}
html.sm-auth-top #menu-bar{
  display:flex!important;align-items:center!important;
  justify-content:flex-start!important;gap:4px!important;
  position:relative!important;padding-right:8px!important}
html.sm-auth-top #menu-bar .x-toolbar-ct{flex:1 1 auto!important;width:auto!important}
html.sm-auth-top #sm-auth-slot{
  display:flex!important;align-items:center!important;justify-content:flex-end!important;
  gap:8px!important;margin-left:auto!important;flex:0 0 auto!important;
  padding:0 4px 0 12px!important;min-height:var(--sm-tap)!important;
  white-space:nowrap!important;z-index:5}
html.sm-auth-top #sm-auth-slot #userName,
html.sm-auth-top #sm-auth-slot .user,
html.sm-auth-top #sm-auth-slot .x-form-item,
html.sm-auth-top #sm-auth-slot .x-toolbar-cell,
html.sm-auth-top #menu-bar #userName,
html.sm-auth-top #menu-bar .user{
  display:inline-flex!important;align-items:center!important;gap:6px!important;
  color:var(--sm-muted)!important;font:500 12px/1.2 "Sora",system-ui,sans-serif!important;
  margin:0!important;padding:0!important;border:0!important;background:transparent!important}
html.sm-auth-top #sm-auth-slot #login_button,
html.sm-auth-top #sm-auth-slot #logout_button,
html.sm-auth-top #menu-bar #login_button,
html.sm-auth-top #menu-bar #logout_button{
  display:inline-flex!important;align-items:center!important;
  min-height:32px!important;margin:0!important}
html.sm-auth-top #sm-auth-slot #logout_button .x-btn-mc,
html.sm-auth-top #sm-auth-slot #login_button .x-btn-mc,
html.sm-auth-top #menu-bar #logout_button .x-btn-mc,
html.sm-auth-top #menu-bar #login_button .x-btn-mc{
  background:var(--sm-bg3)!important;border-radius:8px!important;padding:0 10px!important}
html.sm-auth-top #sm-auth-slot #logout_button .x-btn-text,
html.sm-auth-top #sm-auth-slot #login_button .x-btn-text,
html.sm-auth-top #menu-bar #logout_button .x-btn-text,
html.sm-auth-top #menu-bar #login_button .x-btn-text{
  color:var(--sm-text)!important;font:600 12px/1.2 "Sora",system-ui,sans-serif!important}
html.sm-auth-top #menu-bar::after{display:none!important;content:none!important}

/* Windows 11 Explorer-style nav — custom row replaces Ext toolbar table layout */
html.sm-merged-chrome #control-panel #alertButton,
html.sm-win-nav #control-panel #alertButton{
  display:none!important;visibility:hidden!important;width:0!important;height:0!important;
  overflow:hidden!important;margin:0!important;padding:0!important}
html.sm-merged-chrome #control-panel,
html.sm-win-nav #control-panel{
  display:block!important;visibility:visible!important;position:relative!important;
  box-sizing:border-box!important;
  height:auto!important;min-height:0!important;max-height:none!important;
  overflow:visible!important;padding:4px 10px!important;margin:0!important;
  border:0!important;border-bottom:1px solid var(--sm-line)!important;
  background:var(--sm-bg1)!important;
  line-height:normal!important;z-index:30!important}
html.sm-win-nav #headerPanel,
html.sm-merged-chrome #headerPanel{
  position:relative!important;z-index:25!important;overflow:visible!important;
  background:var(--sm-bg1)!important}
/* Hide native Ext toolbar chrome; custom #sm-win-explorer-bar paints the nav */
html.sm-win-nav #control-panel>.x-toolbar-ct,
html.sm-win-nav #control-panel>table,
html.sm-win-nav #control-panel .x-toolbar-left,
html.sm-win-nav #control-panel .x-toolbar-right,
html.sm-win-nav #control-panel .x-toolbar-cell,
html.sm-win-nav #location-buttons,
html.sm-win-nav #location-buttons-ie,
html.sm-win-nav #location-textfield,
html.sm-win-nav #location-bar .x-box-item img[src*="location_spacer"],
html.sm-win-nav #location-bar .location_item,
html.sm-win-nav #location-bar .location_item2,
html.sm-win-nav #location-bar .x-form-clear-trigger,
html.sm-win-nav #location-bar .x-form-trigger,
html.sm-win-nav #location-bar .x-form-field-wrap,
html.sm-win-nav #control-panel .sm-win-hide{
  display:none!important;visibility:hidden!important;width:0!important;height:0!important;
  max-width:0!important;max-height:0!important;margin:0!important;padding:0!important;
  overflow:hidden!important;pointer-events:none!important;opacity:0!important}
#sm-win-explorer-bar{
  display:flex!important;align-items:center!important;gap:8px!important;
  width:100%!important;max-width:100%!important;box-sizing:border-box!important;
  min-height:34px!important;height:auto!important;margin:0!important;padding:0!important;
  line-height:normal!important;position:relative!important;z-index:31!important}
#sm-win-explorer-bar .sm-win-nav-btns{
  display:flex!important;align-items:center!important;gap:2px!important;
  flex:0 0 auto!important}
#sm-win-explorer-bar .sm-win-nav-btn{
  appearance:none!important;width:32px!important;height:32px!important;
  margin:0!important;padding:0!important;border:0!important;border-radius:6px!important;
  background:transparent!important;cursor:pointer!important;position:relative!important;
  flex:0 0 32px!important;opacity:.9!important}
#sm-win-explorer-bar .sm-win-nav-btn:hover{background:rgba(255,255,255,.08)!important}
#sm-win-explorer-bar .sm-win-nav-btn.is-disabled{opacity:.35!important;cursor:default!important}
#sm-win-explorer-bar .sm-win-nav-btn::before{
  content:""!important;position:absolute!important;inset:7px!important;
  background-repeat:no-repeat!important;background-position:center!important;background-size:contain!important}
#sm-win-explorer-bar .sm-win-back::before{
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23e8f2ec' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M15 18l-6-6 6-6'/%3E%3C/svg%3E")!important}
#sm-win-explorer-bar .sm-win-fwd::before{
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23e8f2ec' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M9 18l6-6-6-6'/%3E%3C/svg%3E")!important}
#sm-win-explorer-bar .sm-win-up::before{
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23e8f2ec' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M12 19V5'/%3E%3Cpath d='M5 12l7-7 7 7'/%3E%3C/svg%3E")!important}
#sm-win-explorer-bar .sm-win-ref::before{
  background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23e8f2ec' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M21 12a9 9 0 1 1-3-6.7'/%3E%3Cpath d='M21 3v6h-6'/%3E%3C/svg%3E")!important}
/* Park Ext #location-bar off-layout so doLayout cannot wipe our address host */
html.sm-win-nav #control-panel #location-bar,
html.sm-merged-chrome #control-panel #location-bar{
  position:absolute!important;left:-9999px!important;top:0!important;
  width:1px!important;height:1px!important;min-width:0!important;max-width:1px!important;
  margin:0!important;padding:0!important;border:0!important;overflow:hidden!important;
  visibility:hidden!important;opacity:0!important;pointer-events:none!important;
  flex:0 0 0!important;display:block!important}
html.sm-win-nav #location-bar .x-panel-body,
html.sm-win-nav #location-bar .x-panel-bwrap{
  display:block!important;width:1px!important;height:1px!important;overflow:hidden!important;
  background:transparent!important;border:0!important}
#sm-win-address{
  position:relative!important;top:auto!important;left:auto!important;right:auto!important;
  bottom:auto!important;inset:auto!important;z-index:1!important;
  display:flex!important;align-items:center!important;gap:0!important;
  box-sizing:border-box!important;width:auto!important;max-width:none!important;
  height:34px!important;max-height:34px!important;min-height:34px!important;min-width:0!important;
  padding:0 10px 0 36px!important;overflow:hidden!important;flex:1 1 auto!important;
  border:1px solid rgba(255,255,255,.12)!important;border-radius:8px!important;
  background:var(--sm-bg0)!important;cursor:text!important}
#sm-win-address::before{
  content:""!important;position:absolute!important;left:11px!important;top:50%!important;
  width:16px!important;height:16px!important;transform:translateY(-50%)!important;
  background:no-repeat center/contain
    url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%23c5d4cc' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M3 10.5L12 3l9 7.5'/%3E%3Cpath d='M5 9.5V20h14V9.5'/%3E%3C/svg%3E")!important;
  pointer-events:none!important}
#sm-win-address .sm-win-crumb{
  appearance:none!important;border:0!important;background:transparent!important;
  color:var(--sm-text)!important;cursor:pointer!important;
  font:400 13px/1.2 "Segoe UI",Sora,system-ui,sans-serif!important;
  padding:3px 6px!important;border-radius:4px!important;white-space:nowrap!important;
  max-width:280px!important;overflow:hidden!important;text-overflow:ellipsis!important}
#sm-win-address .sm-win-crumb:hover{background:rgba(255,255,255,.08)!important}
#sm-win-address .sm-win-crumb.is-current{color:var(--sm-text)!important;cursor:default!important;font-weight:500!important}
#sm-win-address .sm-win-crumb.is-current:hover{background:transparent!important}
#sm-win-address .sm-win-chev{
  flex:0 0 auto!important;color:rgba(232,242,236,.55)!important;
  font:400 14px/1 "Segoe UI",system-ui,sans-serif!important;padding:0 1px!important;
  user-select:none!important;pointer-events:none!important}
#sm-win-address .sm-win-edit{
  display:none!important;flex:1 1 auto!important;min-width:0!important;height:28px!important;
  margin:0!important;padding:0 4px!important;border:0!important;outline:none!important;
  background:transparent!important;color:var(--sm-text)!important;
  font:400 13px/28px "Segoe UI",Sora,system-ui,sans-serif!important}
#sm-win-address.is-editing .sm-win-crumb,
#sm-win-address.is-editing .sm-win-chev{display:none!important}
#sm-win-address.is-editing .sm-win-edit{display:block!important}
#main-panel,#main-panel .x-panel-bwrap,#main-panel .x-panel-body,#main-panel .x-border-panel{
  pointer-events:auto!important}
#sm-win-address.sm-win-misplaced{
  display:none!important;pointer-events:none!important;width:0!important;height:0!important}
#sm-win-search-wrap{
  position:relative!important;flex:0 0 240px!important;min-width:160px!important;max-width:280px!important;
  height:34px!important}
#sm-win-search-wrap input{
  width:100%!important;height:34px!important;box-sizing:border-box!important;
  margin:0!important;padding:0 12px 0 34px!important;border-radius:8px!important;
  border:1px solid rgba(255,255,255,.12)!important;background:var(--sm-bg0)!important;
  font:400 13px/34px "Segoe UI",Sora,system-ui,sans-serif!important;
  color:var(--sm-text)!important;outline:none!important;box-shadow:none!important}
#sm-win-search-wrap input::placeholder{color:rgba(232,242,236,.45)!important;opacity:1!important}
#sm-win-search-wrap::before{
  content:""!important;position:absolute!important;left:11px!important;top:50%!important;
  width:15px!important;height:15px!important;transform:translateY(-50%)!important;z-index:2!important;
  background:no-repeat center/contain
    url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%2384998c' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Ccircle cx='11' cy='11' r='7'/%3E%3Cpath d='M21 21l-4.3-4.3'/%3E%3C/svg%3E")!important;
  pointer-events:none!important}
html.sm-win-nav #control-panel #search-textbox,
html.sm-win-nav #search-panel,
html.sm-win-nav #search-panel .x-form-field-wrap,
html.sm-win-nav #search-panel .x-form-clear-trigger{
  display:none!important;visibility:hidden!important;width:0!important;height:0!important;
  pointer-events:none!important;opacity:0!important;position:absolute!important;left:-9999px!important}
#control-panel.sm-nas-gone{
  display:none!important;visibility:hidden!important;
  height:0!important;min-height:0!important;max-height:0!important;
  overflow:hidden!important;padding:0!important;margin:0!important;border:0!important}
html.sm-merged-chrome #menu-bar{
  display:flex!important;align-items:center!important;flex-wrap:nowrap!important;
  gap:6px!important;padding:4px 8px!important;border-bottom:1px solid var(--sm-line)!important}
html.sm-merged-chrome #menu-bar .x-toolbar-ct{
  display:flex!important;align-items:center!important;flex:1 1 auto!important;
  width:100%!important;gap:6px!important}
@media (max-width:900px){
  #sm-win-explorer-bar{flex-wrap:wrap!important}
  #sm-win-search-wrap{flex:1 1 100%!important;max-width:none!important;order:11!important}
  #sm-win-address{flex:1 1 100%!important;order:10!important;min-width:100%!important}
}

/* Location / search shared */
#control-panel,#location-bar,.navi-button,#location-buttons,#location-buttons-ie,#search-panel{
  background:var(--sm-bg1)!important;background-image:none!important;border:0!important}
#location-textfield,#search-textbox,.x-form-text,.x-form-field,
.x-form-textarea,.x-form-field-wrap .x-form-text{
  background:var(--sm-bg0)!important;background-image:none!important;
  color:var(--sm-text)!important;border:1px solid var(--sm-line)!important;
  border-radius:8px!important;min-height:34px!important;font-size:13px!important;
  padding:6px 10px!important;box-shadow:none!important}
#location-textfield:focus,#search-textbox:focus,.x-form-focus,.x-form-text:focus{
  border-color:rgba(170,210,185,.45)!important;box-shadow:0 0 0 2px var(--sm-accent-dim)!important;
  outline:none!important}
.x-form-invalid,.x-form-invalid.x-form-text{
  border-color:var(--sm-danger)!important;background:rgba(255,107,107,.08)!important}
.location_item2,.active_history_item{color:var(--sm-accent)!important}
.navi-button .x-btn{min-width:32px!important;min-height:32px!important}
.x-form-trigger,.x-form-arrow-trigger,.x-form-date-trigger,.x-form-clear-trigger{
  background-color:var(--sm-bg3)!important;filter:invert(1) brightness(1.2);border:0!important}
.x-form-item-label,.x-form-cb-label,.x-form-item label,.x-form-label-top label{
  color:var(--sm-muted)!important;font-size:12px!important;font-weight:600!important}
.x-form-check-wrap,.x-form-radio-group{color:var(--sm-text)!important}
select,.x-combo-list{
  background:var(--sm-bg2)!important;color:var(--sm-text)!important;
  border:1px solid var(--sm-line)!important;border-radius:10px!important}
.x-combo-list-item{padding:8px 12px!important;color:var(--sm-text)!important}
.x-combo-selected{background:var(--sm-accent-dim)!important;border:0!important;color:var(--sm-accent)!important}

/* West tree + details */
#left-panel,#tree-panel,#details-panel{
  background:var(--sm-bg1)!important;border-right:1px solid var(--sm-line)!important}
#left-panel .x-panel-body,#tree-panel .x-panel-body,#details-panel .x-panel-body{
  background:var(--sm-bg1)!important}
.x-tree-node-el{color:var(--sm-text)!important;min-height:32px!important;
  line-height:32px!important;padding:0 10px!important;border-radius:8px!important}
/* Ext sets .x-tree-node a span { color:black } — force readable light labels */
.x-tree-node a,.x-tree-node a span,.x-tree-node .x-tree-node-anchor,
.x-tree-node .x-tree-node-anchor span,.x-dd-drag-ghost a span,
#tree-panel .x-tree-node a,#tree-panel .x-tree-node a span,
#left-panel .x-tree-node a,#left-panel .x-tree-node a span{
  color:var(--sm-text)!important;text-decoration:none!important;background:transparent!important}
.x-tree-node .x-tree-node-over a span,.x-tree-node-el.x-tree-node-over a span{
  color:var(--sm-text)!important;background:transparent!important}
.x-tree-selected,.x-tree-node .x-tree-selected{
  background:var(--sm-accent-dim)!important;color:var(--sm-accent)!important}
.x-tree-node .x-tree-selected a span,.x-tree-node .x-tree-selected .x-tree-node-anchor span{
  color:var(--sm-accent)!important;background:transparent!important;font-weight:600!important}
.x-tree-node-over{background:rgba(255,255,255,.04)!important}
.x-tree-node .x-tree-node-disabled a span{color:var(--sm-muted)!important}
.x-tree-node-icon,.x-tree-ec-icon,.x-tree-arrows .x-tree-ec-over .x-tree-ec-icon{
  filter:saturate(.8) brightness(1.15)}
#details-panel .details-info,p.details-info,.details-title{
  color:var(--sm-muted)!important;font-size:12px!important;line-height:1.45!important;
  padding:8px 12px!important;background:transparent!important}
.x-panel-ghost{background:var(--sm-bg2)!important;border:1px dashed var(--sm-accent)!important;opacity:.9}

/* Main file pane */
#main-panel,.icon-panel,#main-panel .x-panel-bwrap,
#main-panel .x-panel-ml,#main-panel .x-panel-mr,#main-panel .x-panel-mc,
#main-panel .x-panel-tl,#main-panel .x-panel-tr,#main-panel .x-panel-tc,
#main-panel .x-panel-bl,#main-panel .x-panel-br,#main-panel .x-panel-bc,
.x-grid-panel,.x-grid-panel .x-panel-body{
  background:var(--sm-bg0)!important;background-image:none!important;
  border:0!important;outline:0!important;box-shadow:none!important;overflow:hidden!important}
#main-panel .x-panel-body,.icon-panel .x-panel-body,
#main-panel .x-grid3-scroller,.x-grid3-scroller{
  background:var(--sm-bg0)!important;overflow-x:hidden!important;overflow-y:auto!important;
  overscroll-behavior:none!important;overscroll-behavior-y:none!important}
.icon-panel .x-view-over,.icon-panel .thumb-wrap.x-view-over,
.icon-small.x-view-over,.icon-medium.x-view-over,.icon-large.x-view-over{
  background:rgba(255,255,255,.05)!important;background-image:none!important;
  border:1px solid var(--sm-line)!important;border-radius:12px!important;padding:4px!important;
  color:var(--sm-text)!important}
.icon-panel .x-view-selected,.icon-panel .thumb-wrap.x-view-selected,
.icon-small.x-view-selected,.icon-medium.x-view-selected,.icon-large.x-view-selected,
.icon-panel .x-view-selected .thumb{
  background:var(--sm-accent-dim)!important;background-image:none!important;
  border:1px solid var(--sm-accent-strong)!important;border-radius:12px!important;
  color:var(--sm-text)!important}
.icon-panel .x-view-over .x-editable,.icon-panel .x-view-selected .x-editable,
.icon-panel .x-view-over .thumb,.icon-panel .x-view-selected .thumb,
.icon-panel .x-view-over .icon-info,.icon-panel .x-view-selected .icon-info,
.icon-small.x-view-over .x-editable,.icon-medium.x-view-over .x-editable,
.icon-large.x-view-over .x-editable,.icon-small.x-view-selected .x-editable,
.icon-medium.x-view-selected .x-editable,.icon-large.x-view-selected .x-editable{
  color:var(--sm-text)!important;text-shadow:none!important}
.icon-small,.icon-medium,.icon-large,.icon-side{
  color:var(--sm-text)!important;border-radius:12px!important;margin:6px!important}
.icon-small .x-editable,.icon-medium .x-editable,.icon-large .x-editable,
.thumb,.x-editable,.filename,.file-name{
  color:var(--sm-text)!important;font-size:12px!important;line-height:1.35!important;
  text-shadow:none!important}
.icon-info,.file-size,.file-date{color:var(--sm-muted)!important;font-size:11px!important}
.dd-img{border-radius:8px!important}
/* Icon tile views — Ext 2.3 DataView root is .x-border-panel (no .x-view class) */
/* Hide Name/Size/Date/Type sort bar above icon tiles (keep it for side-by-side/list) */
#icon-panel-small .x-border-layout-ct > .x-toolbar,
#icon-panel-medium .x-border-layout-ct > .x-toolbar,
#icon-panel-large .x-border-layout-ct > .x-toolbar{
  display:none!important;visibility:hidden!important;pointer-events:none!important;
  height:0!important;min-height:0!important;max-height:0!important;line-height:0!important;
  overflow:hidden!important;border:0!important;padding:0!important;margin:0!important;
  opacity:0!important}
#icon-panel-small .x-border-layout-ct,#icon-panel-medium .x-border-layout-ct,
#icon-panel-large .x-border-layout-ct,#sidebyside-panel .x-border-layout-ct{
  width:100%!important;max-width:100%!important;box-sizing:border-box!important}
#icon-panel-small .x-border-layout-ct > .x-border-panel:not(.x-toolbar),
#icon-panel-medium .x-border-layout-ct > .x-border-panel:not(.x-toolbar),
#icon-panel-large .x-border-layout-ct > .x-border-panel:not(.x-toolbar){
  display:grid!important;
  grid-auto-flow:row dense!important;
  align-content:start!important;
  gap:10px 12px!important;
  position:relative!important;
  left:0!important;top:0!important;
  width:100%!important;min-width:100%!important;max-width:100%!important;
  height:auto!important;min-height:0!important;max-height:none!important;
  padding:10px 12px!important;box-sizing:border-box!important}
#icon-panel-small .x-border-layout-ct > .x-border-panel:not(.x-toolbar){
  grid-template-columns:repeat(auto-fill,minmax(88px,1fr))!important}
#icon-panel-medium .x-border-layout-ct > .x-border-panel:not(.x-toolbar){
  grid-template-columns:repeat(auto-fill,minmax(128px,1fr))!important}
#icon-panel-large .x-border-layout-ct > .x-border-panel:not(.x-toolbar){
  grid-template-columns:repeat(auto-fill,minmax(208px,1fr))!important}
#icon-panel-small .x-border-layout-ct > .x-border-panel:not(.x-toolbar) > .x-clear,
#icon-panel-medium .x-border-layout-ct > .x-border-panel:not(.x-toolbar) > .x-clear,
#icon-panel-large .x-border-layout-ct > .x-border-panel:not(.x-toolbar) > .x-clear,
#sidebyside-panel .x-border-layout-ct > .x-border-panel:not(.x-toolbar) > .x-clear{
  display:none!important;width:0!important;height:0!important;
  margin:0!important;padding:0!important;overflow:hidden!important}
#icon-panel-small .x-border-layout-ct > .x-border-panel:not(.x-toolbar) > .icon-thumbnail,
#icon-panel-medium .x-border-layout-ct > .x-border-panel:not(.x-toolbar) > .icon-thumbnail,
#icon-panel-large .x-border-layout-ct > .x-border-panel:not(.x-toolbar) > .icon-thumbnail{
  position:static!important;
  left:auto!important;top:auto!important;right:auto!important;bottom:auto!important;
  float:none!important;clear:none!important;
  width:auto!important;max-width:none!important;height:auto!important;
  margin:0!important;padding:0!important;box-sizing:border-box!important}
#icon-panel-small .icon-thumbnail .icon-small,#icon-panel-medium .icon-thumbnail .icon-medium,
#icon-panel-large .icon-thumbnail .icon-large{
  width:100%!important;height:auto!important;margin:0!important}
#icon-panel-small .icon-thumbnail img,#icon-panel-medium .icon-thumbnail img,
#icon-panel-large .icon-thumbnail img{
  margin-left:auto!important;margin-right:auto!important}
#icon-panel-small .icon-thumbnail .x-editable,#icon-panel-medium .icon-thumbnail .x-editable,
#icon-panel-large .icon-thumbnail .x-editable{
  width:100%!important;text-align:center!important}
#icon-panel-small .icon-thumbnail.x-view-over,#icon-panel-medium .icon-thumbnail.x-view-over,
#icon-panel-large .icon-thumbnail.x-view-over,
#icon-panel-small .icon-thumbnail.x-view-selected,#icon-panel-medium .icon-thumbnail.x-view-selected,
#icon-panel-large .icon-thumbnail.x-view-selected{
  background:rgba(255,255,255,.05)!important;background-image:none!important;
  border:1px solid var(--sm-line)!important;border-radius:12px!important;padding:4px!important}
#icon-panel-small .icon-thumbnail.x-view-selected,#icon-panel-medium .icon-thumbnail.x-view-selected,
#icon-panel-large .icon-thumbnail.x-view-selected{
  background:var(--sm-accent-dim)!important;border-color:var(--sm-accent-strong)!important}
/* Side-by-side list — full-width rows on DataView .x-border-panel root */
#sidebyside-panel .x-border-layout-ct > .x-border-panel:not(.x-toolbar){
  display:block!important;
  width:100%!important;min-width:0!important;max-width:100%!important;
  box-sizing:border-box!important;padding:0!important;overflow:auto!important}
#sidebyside-panel .x-border-layout-ct > .x-border-panel:not(.x-toolbar) > .icon-thumbnail{
  position:static!important;
  left:auto!important;top:auto!important;right:auto!important;bottom:auto!important;
  float:none!important;clear:both!important;
  width:100%!important;max-width:100%!important;height:auto!important;
  margin:0!important;padding:0!important;box-sizing:border-box!important;
  border-bottom:1px solid var(--sm-line)!important}
#sidebyside-panel .icon-thumbnail .icon-side{
  display:flex!important;flex-direction:row!important;align-items:center!important;
  gap:12px!important;padding:6px 12px!important;
  width:100%!important;max-width:100%!important;height:auto!important;min-height:44px!important;
  margin:0!important;box-sizing:border-box!important}
#sidebyside-panel .icon-thumbnail .icon-side[style]{
  width:100%!important;height:auto!important}
#sidebyside-panel .icon-thumbnail img,#sidebyside-panel .icon-thumbnail .dd-img{
  float:none!important;flex:0 0 40px!important;
  width:40px!important;height:40px!important;object-fit:contain!important;margin:0!important}
#sidebyside-panel .icon-thumbnail .icon-info{
  float:none!important;flex:1 1 auto!important;
  width:auto!important;min-width:0!important;padding-top:0!important;
  display:grid!important;
  grid-template-columns:minmax(200px,1fr) 100px 160px 100px!important;
  column-gap:12px!important;align-items:center!important;overflow:hidden!important}
#sidebyside-panel .icon-info > .x-editable,
#sidebyside-panel .icon-info > span{
  display:block!important;text-align:left!important;min-width:0!important;
  white-space:nowrap!important;overflow:hidden!important;text-overflow:ellipsis!important;
  color:var(--sm-text)!important;font-size:13px!important;line-height:1.3!important}
#sidebyside-panel .icon-info > .x-editable{
  grid-column:1!important;font-weight:500!important}
#sidebyside-panel .icon-info > span.sm-nas-col-size{grid-column:2!important;color:var(--sm-muted)!important}
#sidebyside-panel .icon-info > span.sm-nas-col-date{grid-column:3!important;color:var(--sm-muted)!important}
#sidebyside-panel .icon-info > span.sm-nas-col-type{grid-column:4!important;color:var(--sm-muted)!important}
#sidebyside-panel .icon-info > span.sm-nas-size-empty{
  display:block!important;visibility:visible!important;color:var(--sm-muted)!important;opacity:.55!important}
#sidebyside-panel .icon-thumbnail.x-view-over,#sidebyside-panel .icon-thumbnail.x-view-selected{
  background:rgba(255,255,255,.05)!important;background-image:none!important;
  border-color:var(--sm-line)!important}
#sidebyside-panel .icon-thumbnail.x-view-selected{
  background:var(--sm-accent-dim)!important;border-color:var(--sm-accent-strong)!important}
/* Sort header row: spread Name/Size/Date/Type across the content width */
#sidebyside-panel > .x-panel-bwrap > .x-panel-body > .x-border-layout-ct > .x-toolbar,
#sidebyside-panel .x-border-layout-ct > .x-toolbar{
  padding-left:52px!important;box-sizing:border-box!important}
#sidebyside-panel .x-border-layout-ct > .x-toolbar .x-toolbar-left > table{
  width:100%!important;table-layout:fixed!important}
#sidebyside-panel .x-border-layout-ct > .x-toolbar .x-toolbar-left > table > tbody > tr > .x-toolbar-cell{
  width:25%!important}
#sidebyside-panel .x-border-layout-ct > .x-toolbar .x-btn{
  width:100%!important;max-width:100%!important}
#sidebyside-panel .x-border-layout-ct > .x-toolbar .x-btn-text{
  text-align:left!important;padding-left:0!important}
#icon-panel-small .icon-thumbnail .x-dv-focus,#icon-panel-medium .icon-thumbnail .x-dv-focus,
#icon-panel-large .icon-thumbnail .x-dv-focus,#sidebyside-panel .icon-thumbnail .x-dv-focus{
  display:none!important;width:0!important;height:0!important;
  overflow:hidden!important;position:absolute!important;pointer-events:none!important}
/* Detail/list grid — keep Ext table layout (do not apply DataView tile rules) */
#list-panel .x-grid3-body{display:block!important;width:100%!important}
#list-panel .x-grid3-row td{vertical-align:middle!important}
#list-panel .x-grid3-cell-inner{
  display:block!important;visibility:visible!important;opacity:1!important;
  overflow:hidden!important;text-overflow:ellipsis!important;white-space:nowrap!important}
.x-view-empty,.x-grid-empty,.empty-text{
  color:var(--sm-muted)!important;font-size:14px!important;padding:24px!important;text-align:center!important}

/* List / grid */
.x-grid3-row{border-color:var(--sm-line)!important;min-height:40px!important;background:transparent!important}
.x-grid3-row-alt{background:rgba(255,255,255,.02)!important}
.x-grid3-row-over{background:rgba(255,255,255,.05)!important}
.x-grid3-row-selected{background:var(--sm-accent-dim)!important}
.x-grid3-row-over .x-grid3-cell-inner,.x-grid3-row-selected .x-grid3-cell-inner{
  color:var(--sm-text)!important}
.x-grid3-hd-row td,.x-grid3-header,.x-grid3-header-inner{
  background:var(--sm-bg2)!important;background-image:none!important;
  color:var(--sm-muted)!important;border-color:var(--sm-line)!important;
  font-size:11px!important;font-weight:600!important;text-transform:uppercase!important;
  letter-spacing:.04em!important}
td.x-grid3-hd-over .x-grid3-hd-inner,td.sort-desc .x-grid3-hd-inner,
td.sort-asc .x-grid3-hd-inner,td.x-grid3-hd-menu-open .x-grid3-hd-inner,
td.x-grid3-hd-over,td.sort-desc,td.sort-asc,td.x-grid3-hd-menu-open{
  background:var(--sm-accent-dim)!important;background-image:none!important;
  border-color:var(--sm-line)!important;color:var(--sm-accent)!important}
.x-grid3-cell-inner,.x-grid3-hd-inner{color:var(--sm-text)!important;font-size:13px!important;
  line-height:40px!important;min-height:40px!important}
.x-grid3-cell-selected{background:var(--sm-accent-dim)!important;color:var(--sm-text)!important}
/* Detail/list grid — Ext sets inline white backgrounds; keep dark theme readable */
#main-panel .x-grid-panel,#main-panel .x-grid-panel .x-panel-body,
#main-panel .x-grid-panel .x-panel-bwrap,#main-panel .x-grid3,
#main-panel .x-grid3-viewport,#main-panel .x-grid3-scroller,#main-panel .x-grid3-body{
  background:var(--sm-bg0)!important;background-color:var(--sm-bg0)!important}
#main-panel .x-grid3-row td,#main-panel .x-grid3-cell-inner{
  color:var(--sm-text)!important;background:transparent!important}
.x-grid3-hd-btn{filter:invert(1) brightness(1.2)}
.x-grid3-resize-marker,.x-grid3-resize-proxy{background:var(--sm-accent)!important}

/* Menus / dialogs */
.x-menu,.x-menu-floating,.x-menu-list,.x-menu ul,.x-menu table,
.x-menu-list-item,.x-menu-item,.x-menu-item-text,.x-menu-item a{
  background:var(--sm-bg2)!important;background-color:var(--sm-bg2)!important;
  background-image:none!important;color:var(--sm-text)!important;border-color:var(--sm-line)!important}
.x-menu,.x-menu-floating{
  border:1px solid var(--sm-line)!important;border-radius:12px!important;
  padding:6px!important;box-shadow:0 16px 48px rgba(0,0,0,.5)!important}
.x-menu-item{border-radius:8px!important;min-height:36px!important;line-height:36px!important}
.x-menu-item-active,.x-menu-item-active a,.x-menu-item-active .x-menu-item-text,.x-menu-item-active *{
  background:var(--sm-accent-dim)!important;background-image:none!important;
  color:var(--sm-accent)!important;border-color:transparent!important;border-radius:8px!important}
.x-menu-sep{border-bottom:1px solid var(--sm-line)!important;background:transparent!important;margin:4px 8px!important}
.x-menu-item-icon{filter:brightness(1.1)}
.x-menu-check-item .x-menu-item-icon,.x-menu-item-checked .x-menu-item-icon{
  filter:invert(1) brightness(1.2)}
.x-window,.x-window-plain,.x-window-dlg{
  border-radius:16px!important;overflow:hidden!important;
  box-shadow:0 24px 64px rgba(0,0,0,.55)!important;border:1px solid var(--sm-line)!important;
  background:var(--sm-bg1)!important}
.x-window-tl,.x-window-tr,.x-window-tc,.x-window-header,.x-window-header-text,
.x-window-draggable .x-window-header{
  background:var(--sm-bg2)!important;background-image:none!important;
  color:var(--sm-text)!important;font-weight:600!important;padding:12px 14px!important}
.x-window-body,.x-window-mc,.x-window-plain .x-window-body-plain{
  background:var(--sm-bg1)!important;color:var(--sm-text)!important}
.x-window .x-btn{min-height:36px!important;border-radius:10px!important;
  background:var(--sm-bg3)!important;padding:0 14px!important}
.x-window .x-btn-text{color:var(--sm-text)!important;font-weight:600!important}
.x-window .x-btn-over,.x-window .x-btn-focus{background:var(--sm-accent-dim)!important}
.x-window .x-btn-default-small,.x-msg-box .x-btn{background:var(--sm-accent)!important}
.x-window .x-btn-default-small .x-btn-text,.x-msg-box .x-btn .x-btn-text{color:#062016!important}
.x-msg-box .x-window-body{font-size:14px!important;line-height:1.45!important;color:var(--sm-text)!important}
.x-window-footer,.x-panel-btns,.x-panel-fbar,.x-toolbar-footer{
  background:var(--sm-bg1)!important;border-top:1px solid var(--sm-line)!important;padding:10px!important}
#login-window,.x-window-dlg .x-window-body{background:var(--sm-bg1)!important}

/* Progress / masks */
.x-progress,.x-progress-wrap{
  background:var(--sm-bg3)!important;border:1px solid var(--sm-line)!important;
  border-radius:999px!important;overflow:hidden!important;height:10px!important}
.x-progress-bar,.x-progress-inner{
  background:var(--sm-accent)!important;background-image:none!important;border:0!important}
.x-progress-text{color:var(--sm-text)!important;font-size:11px!important;font-weight:600!important}
.x-progress-text-back{color:var(--sm-muted)!important}
.x-mask{background:rgba(10,15,13,.55)!important}
.x-mask-msg,.x-mask-loading,#loading-msg{
  background:var(--sm-bg2)!important;border:1px solid var(--sm-line)!important;
  border-radius:12px!important;color:var(--sm-text)!important;padding:12px 16px!important}
/* Keep Ext body mask usable for dialogs, but never show the Displaying... panel */
#loading-mask,#loading-main,.ext-el-mask#loading-mask{
  display:none!important;visibility:hidden!important;pointer-events:none!important;
  opacity:0!important;background:transparent!important}
.loading-indicator,.x-tbar-loading,.x-status-busy,.x-loading-spinner{color:var(--sm-accent)!important}
.x-shadow{display:none!important}

/* Tabs / tips / misc */
.x-tab-strip-top,.x-tab-panel-header,.x-tab-panel-footer{
  background:var(--sm-bg1)!important;background-image:none!important;border-color:var(--sm-line)!important}
.x-tab-strip span.x-tab-strip-text{color:var(--sm-muted)!important}
.x-tab-strip-active span.x-tab-strip-text{color:var(--sm-accent)!important;font-weight:600!important}
.x-tab-strip-over span.x-tab-strip-text{color:var(--sm-text)!important}
.x-tip,.x-tip-body,.x-tip-tc,.x-tip-tl,.x-tip-tr,.x-tip-bc,.x-tip-bl,.x-tip-br,.x-tip-ml,.x-tip-mr{
  background:var(--sm-bg3)!important;background-image:none!important;color:var(--sm-text)!important;
  border:1px solid var(--sm-line)!important;border-radius:8px!important}
.x-splitbar-h,.x-splitbar-v,.x-layout-split{background:var(--sm-line)!important}
.x-resizable-handle{background:transparent!important}
.x-layout-collapsed,.x-layout-cmini-west,.x-layout-cmini-east{
  background:var(--sm-bg2)!important;border-color:var(--sm-line)!important}
.x-layout-mini,.x-layout-mini-west,.x-layout-mini-east{
  filter:invert(1) brightness(1.2);opacity:.85}
#status-bar,.x-statusbar,.x-panel-bbar .x-toolbar{
  background:var(--sm-bg1)!important;border-top:1px solid var(--sm-line)!important;
  border-bottom:0!important;min-height:32px!important;color:var(--sm-muted)!important}
a{color:var(--sm-accent)!important}
::selection{background:var(--sm-accent-dim);color:var(--sm-text)}
::-webkit-scrollbar{width:8px!important;height:8px!important}
::-webkit-scrollbar-thumb{background:rgba(170,210,185,.22)!important;border-radius:8px!important}
::-webkit-scrollbar-track{background:transparent!important}

/* Desktop polish — roomier chrome, subtle brand strip */
@media (min-width:901px){
  --sm-tap:36px;
  #menu-bar::after{
    content:"Files";
    float:right;margin:8px 12px 0 0;
    font:600 12px/1.2 "Sora",system-ui,sans-serif;
    letter-spacing:.08em;text-transform:uppercase;color:var(--sm-accent);
    opacity:.9}
  #menu-bar .x-btn,#icon-panel .x-btn,.x-toolbar .x-btn{min-width:36px!important}
  .icon-small,.icon-medium,.icon-large{margin:8px!important}
  .icon-small .x-editable,.icon-medium .x-editable,.icon-large .x-editable{font-size:13px!important}
  #location-textfield,#search-textbox,.x-form-text{font-size:13px!important}
}

/* Mobile extras — larger taps, safe areas, hide leftover chrome */
@media (max-width:900px){
  --sm-tap:44px;
  html,body{
    padding-top:var(--sm-safe-top)!important;padding-bottom:var(--sm-safe-bottom)!important;
    padding-left:var(--sm-safe-left)!important;padding-right:var(--sm-safe-right)!important}
  #menu-bar .x-btn,#icon-panel .x-btn,.x-toolbar .x-btn{
    min-width:var(--sm-tap)!important;min-height:var(--sm-tap)!important}
  #location-textfield,#search-textbox,.x-form-text,.x-form-field{font-size:16px!important;min-height:36px!important}
  .x-tree-node-el{min-height:40px!important;line-height:40px!important}
  .x-grid3-row{min-height:48px!important}
  .x-grid3-cell-inner,.x-grid3-hd-inner{line-height:48px!important;min-height:48px!important}
  .x-menu-item{min-height:44px!important;line-height:44px!important}
  .x-window .x-btn{min-height:44px!important}
  .icon-panel .thumb-wrap,.icon-panel .icon-small,.icon-panel .icon-medium,
  .icon-panel .icon-large,.icon-panel .x-view,.x-dd-drag-proxy{
    -webkit-user-drag:none!important;user-select:none!important;touch-action:pan-y!important}
  #icon-panel .x-toolbar,#menu-bar{
    overflow-x:auto!important;overflow-y:hidden!important;-webkit-overflow-scrolling:touch;
    white-space:nowrap!important}
  #status-bar,.x-statusbar,.x-panel-bbar .x-toolbar{
    padding-bottom:max(4px,var(--sm-safe-bottom))!important}
  .x-layout-collapsed,.x-layout-cmini-west,.x-layout-cmini-east{width:36px!important}
  ::-webkit-scrollbar{width:0!important;height:0!important}
}

/* Sencha Touch (/st/) edit mode — only the edit menu, not Ext.Msg docked OK bars */
#maindataview .edit-menu-box,
#maindataview .x-docked-bottom.edit-menu-box,
#maindataview .x-dock-item.x-docked-bottom:has(.edit-menu-box),
#maindataview .x-dock-item.x-docked-bottom:has(.edit-button){
  display:block!important;visibility:visible!important;opacity:1!important;
  z-index:40!important;pointer-events:auto!important;
  padding-bottom:max(8px,env(safe-area-inset-bottom,0px))!important;
  max-height:42vh!important;overflow:visible!important}
.edit-button .x-button-label,.slc-numBtn,.slc-numBtn .x-button-label{
  color:var(--sm-text)!important;font-size:13px!important}
.x-button-confirm .x-button-label{color:var(--sm-accent)!important;font-weight:700!important}
.selected-wrap,.selected-wrap-icon{
  outline:2px solid var(--sm-accent)!important;background:var(--sm-accent-dim)!important}
.main-wrap.x-app-row-pressed,.main-wrap.selected-wrap,.main-wrap.selected-wrap-icon{
  touch-action:manipulation!important}

/* MsgBox / ActionSheet — hide only via Sencha's hidden classes (never sticky inline styles) */
.x-msgbox.x-hidden,.x-msgbox.x-item-hidden,
.x-sheet.x-hidden,.x-sheet.x-item-hidden,
.x-msgbox.x-hidden .x-docked-bottom,.x-msgbox.x-item-hidden .x-docked-bottom,
.x-sheet.x-hidden .x-docked-bottom,.x-sheet.x-item-hidden .x-docked-bottom,
.x-msgbox.x-hidden .x-button,.x-msgbox.x-item-hidden .x-button,
.x-sheet.x-hidden .x-button,.x-sheet.x-item-hidden .x-button{
  display:none!important;visibility:hidden!important;opacity:0!important;
  pointer-events:none!important}
.x-msgbox:not(.x-hidden):not(.x-item-hidden),
.x-sheet:not(.x-hidden):not(.x-item-hidden),
#tapactionsheet:not(.x-hidden):not(.x-item-hidden){
  display:block!important;visibility:visible!important;opacity:1!important;
  pointer-events:auto!important;z-index:10000!important}
.x-msgbox:not(.x-hidden):not(.x-item-hidden) .x-docked-bottom,
.x-msgbox:not(.x-hidden):not(.x-item-hidden) .x-toolbar,
.x-msgbox:not(.x-hidden):not(.x-item-hidden) .x-button,
.x-sheet:not(.x-hidden):not(.x-item-hidden) .x-button,
#tapactionsheet:not(.x-hidden):not(.x-item-hidden) .x-button{
  display:block!important;visibility:visible!important;opacity:1!important;
  pointer-events:auto!important;height:auto!important;min-height:0!important;
  overflow:visible!important}
.x-msgbox .x-input-el,.x-msgbox input,.x-msgbox textarea,.x-msgbox .x-field-input,
.x-msgbox .x-form-field,.x-msgbox .x-input-field{
  display:block!important;visibility:visible!important;opacity:1!important;
  pointer-events:auto!important;width:100%!important;min-height:36px!important;
  font-size:16px!important;color:#111!important;background:#fff!important;
  -webkit-user-select:text!important;user-select:text!important}
#uploadbtn,#uploadbtn .x-button-label{position:relative!important}
#sm-st-upload-input-btn{
  position:absolute!important;left:0!important;top:0!important;right:0!important;bottom:0!important;
  width:100%!important;height:100%!important;opacity:0.01!important;z-index:20!important;
  border:0!important;margin:0!important;padding:0!important;cursor:pointer!important;
  -webkit-appearance:none!important;appearance:none!important}
.x-msgbox .x-toolbar,.x-msgbox .x-docked-bottom{
  background:var(--sm-bg1)!important;border-top:1px solid var(--sm-line)!important}
.x-msgbox .x-button-label{color:#062016!important;font-weight:700!important}
.x-msgbox .x-button-confirm,.x-msgbox .x-button-action{
  background:var(--sm-accent)!important}


/* Custom ServerManager toolbar / menu / navi icons (SVG backgrounds) */
#icon-panel .x-btn-text.navi-button,
#location-buttons .x-btn-text.navi-button,
#location-buttons-ie .x-btn-text.navi-button,
#menu-bar .x-btn-text.navi-button,
.x-btn-text.navi-button,
.x-btn-text[class*="icon-"],
.x-menu-item-icon[class*="icon-"]{
  background-image:none!important;background-repeat:no-repeat!important;
  position:relative!important}
#location-buttons .x-btn-text.navi-button,
#location-buttons-ie .x-btn-text.navi-button{
  color:transparent!important;text-indent:-9999px!important;overflow:visible!important;
  width:30px!important;height:30px!important;padding:0!important;margin:0!important}
#icon-panel .x-btn-text.navi-button{
  color:var(--sm-muted)!important;text-indent:0!important;overflow:visible!important;
  width:auto!important;min-width:52px!important;height:auto!important;min-height:48px!important;
  padding:2px 6px 4px!important;margin:0!important;
  font-size:11px!important;line-height:1.15!important;white-space:normal!important;
  text-align:center!important}
#menu-bar .x-btn-text[class*="icon-"],#menu-bar .x-btn-text.navi-button{
  color:var(--sm-text)!important;text-indent:0!important;overflow:visible!important;
  width:auto!important;min-height:28px!important;padding:4px 10px 4px 28px!important;
  line-height:20px!important}
.x-btn-text.navi-button::before,.x-btn-text[class*="icon-"]::before{
  content:""!important;display:block!important;width:18px!important;height:18px!important;
  margin:2px auto 4px!important;
  background-color:transparent!important;
  background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;
  -webkit-mask-image:none!important;mask-image:none!important}
#icon-panel .x-btn-text.navi-button::before{margin:2px auto 4px!important}
#menu-bar .x-btn-text[class*="icon-"]::before,#menu-bar .x-btn-text.navi-button::before{
  position:absolute!important;left:6px!important;top:50%!important;
  transform:translateY(-50%)!important;margin:0!important}
.x-menu-item-icon{
  background-color:transparent!important;width:18px!important;height:18px!important;
  background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;
  -webkit-mask-image:none!important;mask-image:none!important}

.x-btn-text.navi-button::before,.x-btn-text[class*="icon-"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM1%2012s4-8%2011-8%2011%208%2011%208-4%208-11%208-11-8-11-8zM12%209a3%203%200%201%201%200%206%203%203%200%200%201%200-6z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
#btn_open .x-btn-text::before,#btn_open button::before,.x-btn-text[style*="menu_file_open.png"]::before,button[style*="menu_file_open.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM22%2019a2%202%200%200%201-2%202H4a2%202%200%200%201-2-2V5a2%202%200%200%201%202-2h5l2%203h9a2%202%200%200%201%202%202z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over #btn_open .x-btn-text::before,.x-btn-over #btn_open button::before,.x-btn-over .x-btn-text[style*="menu_file_open.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM22%2019a2%202%200%200%201-2%202H4a2%202%200%200%201-2-2V5a2%202%200%200%201%202-2h5l2%203h9a2%202%200%200%201%202%202z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
#btn_download .x-btn-text::before,#btn_download button::before,.x-btn-text[style*="menu_file_download.png"]::before,button[style*="menu_file_download.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM21%2015v4a2%202%200%200%201-2%202H5a2%202%200%200%201-2-2v-4M7%2010l5%205%205-5M12%2015V3%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over #btn_download .x-btn-text::before,.x-btn-over #btn_download button::before,.x-btn-over .x-btn-text[style*="menu_file_download.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM21%2015v4a2%202%200%200%201-2%202H5a2%202%200%200%201-2-2v-4M7%2010l5%205%205-5M12%2015V3%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
#btn_newfolder .x-btn-text::before,#btn_newfolder button::before,.x-btn-text[style*="menu_file_newfolder.png"]::before,button[style*="menu_file_newfolder.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM22%2019a2%202%200%200%201-2%202H4a2%202%200%200%201-2-2V5a2%202%200%200%201%202-2h5l2%203h9a2%202%200%200%201%202%202zM12%2011v6M9%2014h6%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over #btn_newfolder .x-btn-text::before,.x-btn-over #btn_newfolder button::before,.x-btn-over .x-btn-text[style*="menu_file_newfolder.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM22%2019a2%202%200%200%201-2%202H4a2%202%200%200%201-2-2V5a2%202%200%200%201%202-2h5l2%203h9a2%202%200%200%201%202%202zM12%2011v6M9%2014h6%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
#btn_remove .x-btn-text::before,#btn_remove button::before,.x-btn-text[style*="menu_file_delete.png"]::before,button[style*="menu_file_delete.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM3%206h18M19%206v14a2%202%200%200%201-2%202H7a2%202%200%200%201-2-2V6m3%200V4a2%202%200%200%201%202-2h4a2%202%200%200%201%202%202v2%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over #btn_remove .x-btn-text::before,.x-btn-over #btn_remove button::before,.x-btn-over .x-btn-text[style*="menu_file_delete.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM3%206h18M19%206v14a2%202%200%200%201-2%202H7a2%202%200%200%201-2-2V6m3%200V4a2%202%200%200%201%202-2h4a2%202%200%200%201%202%202v2%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
#btn_rename .x-btn-text::before,#btn_rename button::before,.x-btn-text[style*="menu_file_rename.png"]::before,button[style*="menu_file_rename.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM12%2020h9M16.5%203.5a2.12%202.12%200%200%201%203%203L7%2019l-4%201%201-4L16.5%203.5z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over #btn_rename .x-btn-text::before,.x-btn-over #btn_rename button::before,.x-btn-over .x-btn-text[style*="menu_file_rename.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM12%2020h9M16.5%203.5a2.12%202.12%200%200%201%203%203L7%2019l-4%201%201-4L16.5%203.5z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
#btn_copy .x-btn-text::before,#btn_copy button::before,.x-btn-text[style*="menu_file_copy.png"]::before,button[style*="menu_file_copy.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM16%204h2a2%202%200%200%201%202%202v14a2%202%200%200%201-2%202H6a2%202%200%200%201-2-2V6a2%202%200%200%201%202-2h2M8%202h8v4H8z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over #btn_copy .x-btn-text::before,.x-btn-over #btn_copy button::before,.x-btn-over .x-btn-text[style*="menu_file_copy.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM16%204h2a2%202%200%200%201%202%202v14a2%202%200%200%201-2%202H6a2%202%200%200%201-2-2V6a2%202%200%200%201%202-2h2M8%202h8v4H8z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
#btn_move .x-btn-text::before,#btn_move button::before,.x-btn-text[style*="menu_file_move.png"]::before,button[style*="menu_file_move.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM5%2012h14M12%205l7%207-7%207%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over #btn_move .x-btn-text::before,.x-btn-over #btn_move button::before,.x-btn-over .x-btn-text[style*="menu_file_move.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM5%2012h14M12%205l7%207-7%207%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
#btn_upload .x-btn-text::before,#btn_upload button::before,.x-btn-text[style*="menu_file_upload.png"]::before,button[style*="menu_file_upload.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM21%2015v4a2%202%200%200%201-2%202H5a2%202%200%200%201-2-2v-4M17%208l-5-5-5%205M12%203v12%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over #btn_upload .x-btn-text::before,.x-btn-over #btn_upload button::before,.x-btn-over .x-btn-text[style*="menu_file_upload.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM21%2015v4a2%202%200%200%201-2%202H5a2%202%200%200%201-2-2v-4M17%208l-5-5-5%205M12%203v12%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
#btn_thumb_clear .x-btn-text::before,#btn_thumb_clear button::before,.x-btn-text[style*="thumb_clear.png"]::before,button[style*="thumb_clear.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM3%206h18M8%206V4a2%202%200%200%201%202-2h4a2%202%200%200%201%202%202v2M19%206l-1%2014a2%202%200%200%201-2%202H8a2%202%200%200%201-2-2L5%206%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over #btn_thumb_clear .x-btn-text::before,.x-btn-over #btn_thumb_clear button::before,.x-btn-over .x-btn-text[style*="thumb_clear.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM3%206h18M8%206V4a2%202%200%200%201%202-2h4a2%202%200%200%201%202%202v2M19%206l-1%2014a2%202%200%200%201-2%202H8a2%202%200%200%201-2-2L5%206%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
#btn_mailurl .x-btn-text::before,#btn_mailurl button::before,.x-btn-text[style*="menu_file_mailurl.png"]::before,button[style*="menu_file_mailurl.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM4%204h16c1.1%200%202%20.9%202%202v12c0%201.1-.9%202-2%202H4c-1.1%200-2-.9-2-2V6c0-1.1.9-2%202-2zM22%206l-10%207L2%206%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over #btn_mailurl .x-btn-text::before,.x-btn-over #btn_mailurl button::before,.x-btn-over .x-btn-text[style*="menu_file_mailurl.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM4%204h16c1.1%200%202%20.9%202%202v12c0%201.1-.9%202-2%202H4c-1.1%200-2-.9-2-2V6c0-1.1.9-2%202-2zM22%206l-10%207L2%206%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
#btn_onetimeurl .x-btn-text::before,#btn_onetimeurl button::before,.x-btn-text[style*="menu_file_onetimeurl.png"]::before,button[style*="menu_file_onetimeurl.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM12%202v2M12%2020v2M4.93%204.93l1.41%201.41M17.66%2017.66l1.41%201.41M2%2012h2M20%2012h2M4.93%2019.07l1.41-1.41M17.66%206.34l1.41-1.41M12%208a4%204%200%201%201%200%208%204%204%200%200%201%200-8z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over #btn_onetimeurl .x-btn-text::before,.x-btn-over #btn_onetimeurl button::before,.x-btn-over .x-btn-text[style*="menu_file_onetimeurl.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM12%202v2M12%2020v2M4.93%204.93l1.41%201.41M17.66%2017.66l1.41%201.41M2%2012h2M20%2012h2M4.93%2019.07l1.41-1.41M17.66%206.34l1.41-1.41M12%208a4%204%200%201%201%200%208%204%204%200%200%201%200-8z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
#navi-button-up .x-btn-text::before,#navi-button-up button::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM12%2019V5M5%2012l7-7%207%207%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-text[style*="menu_file.png"]::before,button[style*="menu_file.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM14%202H6a2%202%200%200%200-2%202v16a2%202%200%200%200%202%202h12a2%202%200%200%200%202-2V8zM14%202v6h6%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over .x-btn-text[style*="menu_file.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM14%202H6a2%202%200%200%200-2%202v16a2%202%200%200%200%202%202h12a2%202%200%200%200%202-2V8zM14%202v6h6%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-text[style*="menu_view.png"]::before,button[style*="menu_view.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM1%2012s4-8%2011-8%2011%208%2011%208-4%208-11%208-11-8-11-8zM12%209a3%203%200%201%201%200%206%203%203%200%200%201%200-6z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over .x-btn-text[style*="menu_view.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM1%2012s4-8%2011-8%2011%208%2011%208-4%208-11%208-11-8-11-8zM12%209a3%203%200%201%201%200%206%203%203%200%200%201%200-6z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-text[style*="menu_view_list.png"]::before,button[style*="menu_view_list.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM8%206h13M8%2012h13M8%2018h13M3%206h.01M3%2012h.01M3%2018h.01%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over .x-btn-text[style*="menu_view_list.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM8%206h13M8%2012h13M8%2018h13M3%206h.01M3%2012h.01M3%2018h.01%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-text[style*="menu_view_small.png"]::before,button[style*="menu_view_small.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM3%203h7v7H3zM14%203h7v7h-7zM14%2014h7v7h-7zM3%2014h7v7H3z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over .x-btn-text[style*="menu_view_small.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM3%203h7v7H3zM14%203h7v7h-7zM14%2014h7v7h-7zM3%2014h7v7H3z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-text[style*="menu_view_medium.png"]::before,button[style*="menu_view_medium.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM3%203h8v8H3zM13%203h8v8h-8zM3%2013h8v8H3zM13%2013h8v8h-8z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over .x-btn-text[style*="menu_view_medium.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM3%203h8v8H3zM13%203h8v8h-8zM3%2013h8v8H3zM13%2013h8v8h-8z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-text[style*="menu_view_large.png"]::before,button[style*="menu_view_large.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM3%203h18v18H3z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over .x-btn-text[style*="menu_view_large.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM3%203h18v18H3z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-text[style*="menu_help.png"]::before,button[style*="menu_help.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM12%2022a10%2010%200%201%201%200-20%2010%2010%200%200%201%200%2020zM9.09%209a3%203%200%200%201%205.83%201c0%202-3%203-3%203M12%2017h.01%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over .x-btn-text[style*="menu_help.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM12%2022a10%2010%200%201%201%200-20%2010%2010%200%200%201%200%2020zM9.09%209a3%203%200%200%201%205.83%201c0%202-3%203-3%203M12%2017h.01%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-text[style*="menu_settings.png"]::before,button[style*="menu_settings.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM12%2015a3%203%200%201%200%200-6%203%203%200%200%200%200%206zM19.4%2015a1.65%201.65%200%200%200%20.33%201.82l.06.06a2%202%200%201%201-2.83%202.83l-.06-.06a1.65%201.65%200%200%200-1.82-.33%201.65%201.65%200%200%200-1%201.51V21a2%202%200%201%201-4%200v-.09A1.65%201.65%200%200%200%209%2019.4a1.65%201.65%200%200%200-1.82.33l-.06.06a2%202%200%201%201-2.83-2.83l.06-.06A1.65%201.65%200%200%200%204.68%2015a1.65%201.65%200%200%200-1.51-1H3a2%202%200%201%201%200-4h.09A1.65%201.65%200%200%200%204.6%209a1.65%201.65%200%200%200-.33-1.82l-.06-.06a2%202%200%201%201%202.83-2.83l.06.06A1.65%201.65%200%200%200%209%204.68a1.65%201.65%200%200%200%201-1.51V3a2%202%200%201%201%204%200v.09a1.65%201.65%200%200%200%201%201.51%201.65%201.65%200%200%200%201.82-.33l.06-.06a2%202%200%201%201%202.83%202.83l-.06.06A1.65%201.65%200%200%200%2019.4%209a1.65%201.65%200%200%200%201.51%201H21a2%202%200%201%201%200%204h-.09a1.65%201.65%200%200%200-1.51%201z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over .x-btn-text[style*="menu_settings.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM12%2015a3%203%200%201%200%200-6%203%203%200%200%200%200%206zM19.4%2015a1.65%201.65%200%200%200%20.33%201.82l.06.06a2%202%200%201%201-2.83%202.83l-.06-.06a1.65%201.65%200%200%200-1.82-.33%201.65%201.65%200%200%200-1%201.51V21a2%202%200%201%201-4%200v-.09A1.65%201.65%200%200%200%209%2019.4a1.65%201.65%200%200%200-1.82.33l-.06.06a2%202%200%201%201-2.83-2.83l.06-.06A1.65%201.65%200%200%200%204.68%2015a1.65%201.65%200%200%200-1.51-1H3a2%202%200%201%201%200-4h.09A1.65%201.65%200%200%200%204.6%209a1.65%201.65%200%200%200-.33-1.82l-.06-.06a2%202%200%201%201%202.83-2.83l.06.06A1.65%201.65%200%200%200%209%204.68a1.65%201.65%200%200%200%201-1.51V3a2%202%200%201%201%204%200v.09a1.65%201.65%200%200%200%201%201.51%201.65%201.65%200%200%200%201.82-.33l.06-.06a2%202%200%201%201%202.83%202.83l-.06.06A1.65%201.65%200%200%200%2019.4%209a1.65%201.65%200%200%200%201.51%201H21a2%202%200%201%201%200%204h-.09a1.65%201.65%200%200%200-1.51%201z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-text[style*="back.png"]::before,button[style*="back.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM19%2012H5M12%2019l-7-7%207-7%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over .x-btn-text[style*="back.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM19%2012H5M12%2019l-7-7%207-7%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-text[style*="forward.png"]::before,button[style*="forward.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM5%2012h14M12%205l7%207-7%207%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over .x-btn-text[style*="forward.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM5%2012h14M12%205l7%207-7%207%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-text[style*="up.png"]::before,button[style*="up.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM12%2019V5M5%2012l7-7%207%207%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over .x-btn-text[style*="up.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM12%2019V5M5%2012l7-7%207%207%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-text[style*="etc_history.png"]::before,button[style*="etc_history.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM3%203v5h5M3.05%2013a9%209%200%201%200%20.5-4.5M12%207v5l3%203%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over .x-btn-text[style*="etc_history.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM3%203v5h5M3.05%2013a9%209%200%201%200%20.5-4.5M12%207v5l3%203%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-text[style*="alert.png"]::before,button[style*="alert.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM10.29%203.86L1.82%2018a2%202%200%200%200%201.71%203h16.94a2%202%200%200%200%201.71-3L13.71%203.86a2%202%200%200%200-3.42%200zM12%209v4M12%2017h.01%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over .x-btn-text[style*="alert.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM10.29%203.86L1.82%2018a2%202%200%200%200%201.71%203h16.94a2%202%200%200%200%201.71-3L13.71%203.86a2%202%200%200%200-3.42%200zM12%209v4M12%2017h.01%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-text[style*="search.png"]::before,button[style*="search.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM11%203a8%208%200%201%200%200%2016%208%208%200%200%200%200-16zM21%2021l-4.3-4.3%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over .x-btn-text[style*="search.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM11%203a8%208%200%201%200%200%2016%208%208%200%200%200%200-16zM21%2021l-4.3-4.3%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-text[style*="etc_login.png"]::before,button[style*="etc_login.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM15%203h4a2%202%200%200%201%202%202v14a2%202%200%200%201-2%202h-4M10%2017l5-5-5-5M15%2012H3%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over .x-btn-text[style*="etc_login.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM15%203h4a2%202%200%200%201%202%202v14a2%202%200%200%201-2%202h-4M10%2017l5-5-5-5M15%2012H3%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-text[style*="etc_logout.png"]::before,button[style*="etc_logout.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM9%2021H5a2%202%200%200%201-2-2V5a2%202%200%200%201%202-2h4M16%2017l5-5-5-5M21%2012H9%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over .x-btn-text[style*="etc_logout.png"]::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM9%2021H5a2%202%200%200%201-2-2V5a2%202%200%200%201%202-2h4M16%2017l5-5-5-5M21%2012H9%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-text.icon-file::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM14%202H6a2%202%200%200%200-2%202v16a2%202%200%200%200%202%202h12a2%202%200%200%200%202-2V8zM14%202v6h6%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-menu-item-icon.icon-file{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM14%202H6a2%202%200%200%200-2%202v16a2%202%200%200%200%202%202h12a2%202%200%200%200%202-2V8zM14%202v6h6%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over .x-btn-text.icon-file::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM14%202H6a2%202%200%200%200-2%202v16a2%202%200%200%200%202%202h12a2%202%200%200%200%202-2V8zM14%202v6h6%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-text.icon-fileOpen::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM22%2019a2%202%200%200%201-2%202H4a2%202%200%200%201-2-2V5a2%202%200%200%201%202-2h5l2%203h9a2%202%200%200%201%202%202z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-menu-item-icon.icon-fileOpen{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM22%2019a2%202%200%200%201-2%202H4a2%202%200%200%201-2-2V5a2%202%200%200%201%202-2h5l2%203h9a2%202%200%200%201%202%202z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over .x-btn-text.icon-fileOpen::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM22%2019a2%202%200%200%201-2%202H4a2%202%200%200%201-2-2V5a2%202%200%200%201%202-2h5l2%203h9a2%202%200%200%201%202%202z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-text.icon-download::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM21%2015v4a2%202%200%200%201-2%202H5a2%202%200%200%201-2-2v-4M7%2010l5%205%205-5M12%2015V3%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-menu-item-icon.icon-download{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM21%2015v4a2%202%200%200%201-2%202H5a2%202%200%200%201-2-2v-4M7%2010l5%205%205-5M12%2015V3%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over .x-btn-text.icon-download::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM21%2015v4a2%202%200%200%201-2%202H5a2%202%200%200%201-2-2v-4M7%2010l5%205%205-5M12%2015V3%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-text.icon-newfolder::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM22%2019a2%202%200%200%201-2%202H4a2%202%200%200%201-2-2V5a2%202%200%200%201%202-2h5l2%203h9a2%202%200%200%201%202%202zM12%2011v6M9%2014h6%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-menu-item-icon.icon-newfolder{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM22%2019a2%202%200%200%201-2%202H4a2%202%200%200%201-2-2V5a2%202%200%200%201%202-2h5l2%203h9a2%202%200%200%201%202%202zM12%2011v6M9%2014h6%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over .x-btn-text.icon-newfolder::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM22%2019a2%202%200%200%201-2%202H4a2%202%200%200%201-2-2V5a2%202%200%200%201%202-2h5l2%203h9a2%202%200%200%201%202%202zM12%2011v6M9%2014h6%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-text.icon-remove::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM3%206h18M19%206v14a2%202%200%200%201-2%202H7a2%202%200%200%201-2-2V6m3%200V4a2%202%200%200%201%202-2h4a2%202%200%200%201%202%202v2%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-menu-item-icon.icon-remove{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM3%206h18M19%206v14a2%202%200%200%201-2%202H7a2%202%200%200%201-2-2V6m3%200V4a2%202%200%200%201%202-2h4a2%202%200%200%201%202%202v2%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over .x-btn-text.icon-remove::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM3%206h18M19%206v14a2%202%200%200%201-2%202H7a2%202%200%200%201-2-2V6m3%200V4a2%202%200%200%201%202-2h4a2%202%200%200%201%202%202v2%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-text.icon-rename::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM12%2020h9M16.5%203.5a2.12%202.12%200%200%201%203%203L7%2019l-4%201%201-4L16.5%203.5z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-menu-item-icon.icon-rename{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM12%2020h9M16.5%203.5a2.12%202.12%200%200%201%203%203L7%2019l-4%201%201-4L16.5%203.5z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over .x-btn-text.icon-rename::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM12%2020h9M16.5%203.5a2.12%202.12%200%200%201%203%203L7%2019l-4%201%201-4L16.5%203.5z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-text.icon-copy::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM16%204h2a2%202%200%200%201%202%202v14a2%202%200%200%201-2%202H6a2%202%200%200%201-2-2V6a2%202%200%200%201%202-2h2M8%202h8v4H8z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-menu-item-icon.icon-copy{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM16%204h2a2%202%200%200%201%202%202v14a2%202%200%200%201-2%202H6a2%202%200%200%201-2-2V6a2%202%200%200%201%202-2h2M8%202h8v4H8z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over .x-btn-text.icon-copy::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM16%204h2a2%202%200%200%201%202%202v14a2%202%200%200%201-2%202H6a2%202%200%200%201-2-2V6a2%202%200%200%201%202-2h2M8%202h8v4H8z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-text.icon-move::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM5%2012h14M12%205l7%207-7%207%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-menu-item-icon.icon-move{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM5%2012h14M12%205l7%207-7%207%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over .x-btn-text.icon-move::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM5%2012h14M12%205l7%207-7%207%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-text.icon-upload::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM21%2015v4a2%202%200%200%201-2%202H5a2%202%200%200%201-2-2v-4M17%208l-5-5-5%205M12%203v12%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-menu-item-icon.icon-upload{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM21%2015v4a2%202%200%200%201-2%202H5a2%202%200%200%201-2-2v-4M17%208l-5-5-5%205M12%203v12%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over .x-btn-text.icon-upload::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM21%2015v4a2%202%200%200%201-2%202H5a2%202%200%200%201-2-2v-4M17%208l-5-5-5%205M12%203v12%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-text.icon-copyurl::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM10%2013a5%205%200%200%200%207.54.54l3-3a5%205%200%200%200-7.07-7.07l-1.72%201.71M14%2011a5%205%200%200%200-7.54-.54l-3%203a5%205%200%200%200%207.07%207.07l1.71-1.71%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-menu-item-icon.icon-copyurl{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM10%2013a5%205%200%200%200%207.54.54l3-3a5%205%200%200%200-7.07-7.07l-1.72%201.71M14%2011a5%205%200%200%200-7.54-.54l-3%203a5%205%200%200%200%207.07%207.07l1.71-1.71%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over .x-btn-text.icon-copyurl::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM10%2013a5%205%200%200%200%207.54.54l3-3a5%205%200%200%200-7.07-7.07l-1.72%201.71M14%2011a5%205%200%200%200-7.54-.54l-3%203a5%205%200%200%200%207.07%207.07l1.71-1.71%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-text.icon-mailurl::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM4%204h16c1.1%200%202%20.9%202%202v12c0%201.1-.9%202-2%202H4c-1.1%200-2-.9-2-2V6c0-1.1.9-2%202-2zM22%206l-10%207L2%206%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-menu-item-icon.icon-mailurl{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM4%204h16c1.1%200%202%20.9%202%202v12c0%201.1-.9%202-2%202H4c-1.1%200-2-.9-2-2V6c0-1.1.9-2%202-2zM22%206l-10%207L2%206%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over .x-btn-text.icon-mailurl::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM4%204h16c1.1%200%202%20.9%202%202v12c0%201.1-.9%202-2%202H4c-1.1%200-2-.9-2-2V6c0-1.1.9-2%202-2zM22%206l-10%207L2%206%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-text.icon-onetimeurl::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM12%202v2M12%2020v2M4.93%204.93l1.41%201.41M17.66%2017.66l1.41%201.41M2%2012h2M20%2012h2M4.93%2019.07l1.41-1.41M17.66%206.34l1.41-1.41M12%208a4%204%200%201%201%200%208%204%204%200%200%201%200-8z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-menu-item-icon.icon-onetimeurl{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM12%202v2M12%2020v2M4.93%204.93l1.41%201.41M17.66%2017.66l1.41%201.41M2%2012h2M20%2012h2M4.93%2019.07l1.41-1.41M17.66%206.34l1.41-1.41M12%208a4%204%200%201%201%200%208%204%204%200%200%201%200-8z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over .x-btn-text.icon-onetimeurl::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM12%202v2M12%2020v2M4.93%204.93l1.41%201.41M17.66%2017.66l1.41%201.41M2%2012h2M20%2012h2M4.93%2019.07l1.41-1.41M17.66%206.34l1.41-1.41M12%208a4%204%200%201%201%200%208%204%204%200%200%201%200-8z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-text.icon-thumb-clear::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM3%206h18M8%206V4a2%202%200%200%201%202-2h4a2%202%200%200%201%202%202v2M19%206l-1%2014a2%202%200%200%201-2%202H8a2%202%200%200%201-2-2L5%206%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-menu-item-icon.icon-thumb-clear{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM3%206h18M8%206V4a2%202%200%200%201%202-2h4a2%202%200%200%201%202%202v2M19%206l-1%2014a2%202%200%200%201-2%202H8a2%202%200%200%201-2-2L5%206%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over .x-btn-text.icon-thumb-clear::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM3%206h18M8%206V4a2%202%200%200%201%202-2h4a2%202%200%200%201%202%202v2M19%206l-1%2014a2%202%200%200%201-2%202H8a2%202%200%200%201-2-2L5%206%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-text.icon-view::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM1%2012s4-8%2011-8%2011%208%2011%208-4%208-11%208-11-8-11-8zM12%209a3%203%200%201%201%200%206%203%203%200%200%201%200-6z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-menu-item-icon.icon-view{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM1%2012s4-8%2011-8%2011%208%2011%208-4%208-11%208-11-8-11-8zM12%209a3%203%200%201%201%200%206%203%203%200%200%201%200-6z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over .x-btn-text.icon-view::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM1%2012s4-8%2011-8%2011%208%2011%208-4%208-11%208-11-8-11-8zM12%209a3%203%200%201%201%200%206%203%203%200%200%201%200-6z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-text.icon-view-list::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM8%206h13M8%2012h13M8%2018h13M3%206h.01M3%2012h.01M3%2018h.01%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-menu-item-icon.icon-view-list{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM8%206h13M8%2012h13M8%2018h13M3%206h.01M3%2012h.01M3%2018h.01%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over .x-btn-text.icon-view-list::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM8%206h13M8%2012h13M8%2018h13M3%206h.01M3%2012h.01M3%2018h.01%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-text.icon-view-small::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM3%203h7v7H3zM14%203h7v7h-7zM14%2014h7v7h-7zM3%2014h7v7H3z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-menu-item-icon.icon-view-small{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM3%203h7v7H3zM14%203h7v7h-7zM14%2014h7v7h-7zM3%2014h7v7H3z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over .x-btn-text.icon-view-small::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM3%203h7v7H3zM14%203h7v7h-7zM14%2014h7v7h-7zM3%2014h7v7H3z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-text.icon-view-medium::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM3%203h8v8H3zM13%203h8v8h-8zM3%2013h8v8H3zM13%2013h8v8h-8z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-menu-item-icon.icon-view-medium{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM3%203h8v8H3zM13%203h8v8h-8zM3%2013h8v8H3zM13%2013h8v8h-8z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over .x-btn-text.icon-view-medium::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM3%203h8v8H3zM13%203h8v8h-8zM3%2013h8v8H3zM13%2013h8v8h-8z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-text.icon-view-large::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM3%203h18v18H3z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-menu-item-icon.icon-view-large{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM3%203h18v18H3z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over .x-btn-text.icon-view-large::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM3%203h18v18H3z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-text.icon-help::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM12%2022a10%2010%200%201%201%200-20%2010%2010%200%200%201%200%2020zM9.09%209a3%203%200%200%201%205.83%201c0%202-3%203-3%203M12%2017h.01%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-menu-item-icon.icon-help{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM12%2022a10%2010%200%201%201%200-20%2010%2010%200%200%201%200%2020zM9.09%209a3%203%200%200%201%205.83%201c0%202-3%203-3%203M12%2017h.01%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over .x-btn-text.icon-help::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM12%2022a10%2010%200%201%201%200-20%2010%2010%200%200%201%200%2020zM9.09%209a3%203%200%200%201%205.83%201c0%202-3%203-3%203M12%2017h.01%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-text.icon-settings::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM12%2015a3%203%200%201%200%200-6%203%203%200%200%200%200%206zM19.4%2015a1.65%201.65%200%200%200%20.33%201.82l.06.06a2%202%200%201%201-2.83%202.83l-.06-.06a1.65%201.65%200%200%200-1.82-.33%201.65%201.65%200%200%200-1%201.51V21a2%202%200%201%201-4%200v-.09A1.65%201.65%200%200%200%209%2019.4a1.65%201.65%200%200%200-1.82.33l-.06.06a2%202%200%201%201-2.83-2.83l.06-.06A1.65%201.65%200%200%200%204.68%2015a1.65%201.65%200%200%200-1.51-1H3a2%202%200%201%201%200-4h.09A1.65%201.65%200%200%200%204.6%209a1.65%201.65%200%200%200-.33-1.82l-.06-.06a2%202%200%201%201%202.83-2.83l.06.06A1.65%201.65%200%200%200%209%204.68a1.65%201.65%200%200%200%201-1.51V3a2%202%200%201%201%204%200v.09a1.65%201.65%200%200%200%201%201.51%201.65%201.65%200%200%200%201.82-.33l.06-.06a2%202%200%201%201%202.83%202.83l-.06.06A1.65%201.65%200%200%200%2019.4%209a1.65%201.65%200%200%200%201.51%201H21a2%202%200%201%201%200%204h-.09a1.65%201.65%200%200%200-1.51%201z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-menu-item-icon.icon-settings{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%2523e8f2ec%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM12%2015a3%203%200%201%200%200-6%203%203%200%200%200%200%206zM19.4%2015a1.65%201.65%200%200%200%20.33%201.82l.06.06a2%202%200%201%201-2.83%202.83l-.06-.06a1.65%201.65%200%200%200-1.82-.33%201.65%201.65%200%200%200-1%201.51V21a2%202%200%201%201-4%200v-.09A1.65%201.65%200%200%200%209%2019.4a1.65%201.65%200%200%200-1.82.33l-.06.06a2%202%200%201%201-2.83-2.83l.06-.06A1.65%201.65%200%200%200%204.68%2015a1.65%201.65%200%200%200-1.51-1H3a2%202%200%201%201%200-4h.09A1.65%201.65%200%200%200%204.6%209a1.65%201.65%200%200%200-.33-1.82l-.06-.06a2%202%200%201%201%202.83-2.83l.06.06A1.65%201.65%200%200%200%209%204.68a1.65%201.65%200%200%200%201-1.51V3a2%202%200%201%201%204%200v.09a1.65%201.65%200%200%200%201%201.51%201.65%201.65%200%200%200%201.82-.33l.06-.06a2%202%200%201%201%202.83%202.83l-.06.06A1.65%201.65%200%200%200%2019.4%209a1.65%201.65%200%200%200%201.51%201H21a2%202%200%201%201%200%204h-.09a1.65%201.65%200%200%200-1.51%201z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
.x-btn-over .x-btn-text.icon-settings::before{background-color:transparent!important;background-image:url("data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%27%20viewBox%3D%270%200%2024%2024%27%20fill%3D%27none%27%20stroke%3D%27%25233ddea0%27%20stroke-width%3D%272%27%20stroke-linecap%3D%27round%27%20stroke-linejoin%3D%27round%27%3EM12%2015a3%203%200%201%200%200-6%203%203%200%200%200%200%206zM19.4%2015a1.65%201.65%200%200%200%20.33%201.82l.06.06a2%202%200%201%201-2.83%202.83l-.06-.06a1.65%201.65%200%200%200-1.82-.33%201.65%201.65%200%200%200-1%201.51V21a2%202%200%201%201-4%200v-.09A1.65%201.65%200%200%200%209%2019.4a1.65%201.65%200%200%200-1.82.33l-.06.06a2%202%200%201%201-2.83-2.83l.06-.06A1.65%201.65%200%200%200%204.68%2015a1.65%201.65%200%200%200-1.51-1H3a2%202%200%201%201%200-4h.09A1.65%201.65%200%200%200%204.6%209a1.65%201.65%200%200%200-.33-1.82l-.06-.06a2%202%200%201%201%202.83-2.83l.06.06A1.65%201.65%200%200%200%209%204.68a1.65%201.65%200%200%200%201-1.51V3a2%202%200%201%201%204%200v.09a1.65%201.65%200%200%200%201%201.51%201.65%201.65%200%200%200%201.82-.33l.06-.06a2%202%200%201%201%202.83%202.83l-.06.06A1.65%201.65%200%200%200%2019.4%209a1.65%201.65%200%200%200%201.51%201H21a2%202%200%201%201%200%204h-.09a1.65%201.65%200%200%200-1.51%201z%3C%2Fsvg%3E")!important;background-size:contain!important;background-repeat:no-repeat!important;background-position:center!important;-webkit-mask-image:none!important;mask-image:none!important}
#sm-settings-nas-row{margin:14px 4px 6px;padding:12px 0 4px;border-top:1px solid var(--sm-line)}
#sm-settings-nas-row .sm-settings-nas-label{font-size:13px;font-weight:600;color:var(--sm-text);margin-bottom:8px}
#sm-settings-nas-row .sm-settings-nas-hint{font-size:11px;color:var(--sm-muted);margin-top:8px;line-height:1.4}
#sm-settings-nas-row .sm-settings-nas-btn,#sm-settings-nas-dl{
  appearance:none;border:1px solid rgba(61,222,160,.35)!important;border-radius:10px!important;
  background:var(--sm-accent-dim)!important;color:var(--sm-accent)!important;
  font:600 13px Sora,system-ui,sans-serif!important;padding:10px 14px!important;cursor:pointer;
  min-height:40px;width:100%;box-sizing:border-box;text-align:left}
#sm-settings-nas-row .sm-settings-nas-btn:hover,#sm-settings-nas-dl:hover{background:rgba(61,222,160,.22)!important}

"""

NAS_FILES_SNIPPET = (
    # Do NOT inject <base href> — WebAccess /ui/ uses relative assets that must
    # resolve against /nas-files/ui/, not /nas-files/.
    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1, minimum-scale=1, maximum-scale=1, user-scalable=no, viewport-fit=cover\" />"
    "<link rel=\"preconnect\" href=\"https://fonts.googleapis.com\" />"
    "<link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin />"
    "<link href=\"https://fonts.googleapis.com/css2?family=Sora:wght@400;500;600;700&display=swap\" rel=\"stylesheet\" />"
    "<style id=\"sm-nas-mobile\">"
    + NAS_FILES_MOBILE_CSS
    + "</style>"
    "<script id=\"sm-nas-files-js\">(function(){"
    f"var P='{NAS_FILES_PREFIX}';"
    "try{document.documentElement.classList.add('sm-auth-top');}catch(e){}"
    "try{document.documentElement.style.setProperty('zoom','1','important');"
    "document.body&&document.body.style.setProperty('zoom','1','important');}catch(e){}"
    "function smPinCss(){try{var s=document.getElementById('sm-nas-mobile');"
    "if(!s)return;var h=document.head||document.getElementsByTagName('head')[0];"
    "if(h)h.appendChild(s);}catch(e){}}"
    "smPinCss();"
    "if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',smPinCss,false);"
    "window.addEventListener('load',smPinCss,false);"
    "function smEnsureStUploadInput(){"
    "try{"
    "if(document.getElementById('sm-st-upload-input'))return;"
    "var wrap=document.createElement('label');"
    "wrap.id='sm-st-upload-wrap';"
    "wrap.setAttribute('for','sm-st-upload-input');"
    "wrap.style.cssText='position:fixed;left:0;top:0;width:1px;height:1px;overflow:hidden;opacity:0.01;z-index:2147483647;';"
    "var input=document.createElement('input');"
    "input.type='file';input.id='sm-st-upload-input';input.multiple=true;"
    "input.setAttribute('accept','*/*');"
    "wrap.appendChild(input);document.body.appendChild(wrap);"
    "input.onchange=function(){try{if(window.Ext&&Ext.app&&Ext.app.Util&&Ext.app.Util._smDoUpload)Ext.app.Util._smDoUpload(input);}catch(e){}};"
    "}catch(e){}}"
    "smEnsureStUploadInput();"
    "if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',smEnsureStUploadInput,false);"
    "window.addEventListener('load',smEnsureStUploadInput,false);"
    # Move admin/Logout into #menu-bar and collapse the second toolbar (#icon-panel).
    "function smAuthSlot(){"
    "var slot=document.getElementById('sm-auth-slot');"
    "if(slot)return slot;"
    "var menu=document.getElementById('menu-bar');"
    "if(!menu)return null;"
    "slot=document.createElement('div');"
    "slot.id='sm-auth-slot';"
    "menu.appendChild(slot);"
    "return slot;}"
    "function smAuthCell(el){"
    "if(!el)return null;"
    "var n=el;"
    "while(n&&n.parentElement){"
    "var p=n.parentElement;"
    "if(p.id==='icon-panel'||p.id==='sm-auth-slot'||p.id==='menu-bar')return n;"
    "if(n.tagName==='TD'&&String(n.className||'').indexOf('x-toolbar-cell')>=0)return n;"
    "n=p;"
    "}"
    "return el;}"
    "function smHideIconBar(){"
    "try{document.documentElement.classList.add('sm-auth-top');}catch(e){}"
    "var actionIds=['btn_open','btn_download','btn_newfolder','btn_remove','btn_rename','btn_copy','btn_move','btn_upload','btn_clearthumb','btn_mailurl','btn_onetimeurl'];"
    "try{"
    "if(window.Ext&&Ext.getCmp){"
    "var icon=Ext.getCmp('icon-panel');"
    "if(icon){"
    "for(var ai=0;ai<actionIds.length;ai++){"
    "var act=Ext.getCmp(actionIds[ai]);"
    "if(act){try{act.hide();}catch(e){}}"
    "}"
    "try{icon.hide();}catch(e){}"
    "try{icon.setHeight(0);}catch(e){}"
    "try{icon.setVisible(false);}catch(e){}"
    "try{if(icon.ownerCt&&icon.ownerCt.doLayout)icon.ownerCt.doLayout(true,true);}catch(e){}"
    "}"
    "}"
    "}catch(e){}"
    "var el=document.getElementById('icon-panel');"
    "if(el){"
    "el.style.display='none';"
    "el.style.height='0';"
    "el.style.minHeight='0';"
    "el.style.overflow='hidden';"
    "el.style.border='0';"
    "el.style.padding='0';"
    "el.style.margin='0';"
    "}"
    "}"
    "function smMergeNaviBar(){"
    "try{"
    "document.documentElement.classList.add('sm-merged-chrome');"
    "document.documentElement.classList.add('sm-win-nav');"
    "try{smEnsureWinExplorerBar();}catch(e){}"
    "if(window.__smNaviMerged)return true;"
    "if(!window.Ext||!Ext.getCmp)return false;"
    "var nav=Ext.getCmp('control-panel');"
    "if(nav){"
    "try{"
    "nav.items.each(function(it){"
    "if(!it)return;"
    "var id=(it.id||'')+'';"
    "if(id==='alertButton'||id.toLowerCase().indexOf('history')>=0){"
    "try{if(it.hide)it.hide();}catch(e){}"
    "}"
    "});"
    "}catch(e){}"
    "}"
    "window.__smNaviMerged=true;"
    "try{smEnsureWinExplorerBar();}catch(e){}"
    "try{smHookWinLocation();}catch(e){}"
    "try{smEnsureWinAddress();}catch(e){}"
    "try{if(typeof update_location_bar==='function'&&window.Ext&&Ext.getCmp){"
    "var _smTree=Ext.getCmp('tree-panel');"
    "var _smNode=_smTree&&_smTree.getSelectionModel().getSelectedNode();"
    "if(_smNode&&_smNode.path){update_location_bar(_smNode.path);smRenderWinAddress(_smNode.path);}"
    "else{update_location_bar('/');smRenderWinAddress('/');}"
    "}}catch(e){}"
    "return true;"
    "}catch(e){return false;}}"
    "function smRefreshCurrentFolder(){"
    "try{"
    "if(!window.Ext||!Ext.getCmp)return;"
    "var tree=Ext.getCmp('tree-panel');"
    "var node=tree&&tree.getSelectionModel().getSelectedNode();"
    "if(!node){node=tree&&tree.getNodeById('/');}"
    "if(!node)return;"
    "if(typeof addRecordWithPath==='function')addRecordWithPath(node,function(){});"
    "else if(typeof selectTreePath_absolute==='function')selectTreePath_absolute(node.path||'/');"
    "}catch(e){}"
    "}"
    "function smRunSearch(word){"
    "try{"
    "word=String(word||'').trim();"
    "if(!word)return;"
    "var tf=document.getElementById('search-textbox');"
    "if(tf)tf.value=word;"
    "try{if(window.Ext&&Ext.getCmp){var c=Ext.getCmp('search-textbox');if(c&&c.setValue)c.setValue(word);}}catch(e){}"
    "if(typeof search==='function')search(word);"
    "}catch(e){}"
    "}"
    "function smEnsureWinExplorerBar(){"
    "try{"
    "document.documentElement.classList.add('sm-win-nav');"
    "var cp=document.getElementById('control-panel');"
    "if(!cp)return;"
    "var row=document.getElementById('sm-win-explorer-bar');"
    "if(!row){"
    "row=document.createElement('div');"
    "row.id='sm-win-explorer-bar';"
    "var btns=document.createElement('div');"
    "btns.className='sm-win-nav-btns';"
    "function mkBtn(cls,title,fn){"
    "var b=document.createElement('button');"
    "b.type='button';b.className='sm-win-nav-btn '+cls;b.title=title;"
    "b.setAttribute('aria-label',title);"
    "b.addEventListener('click',function(ev){ev.preventDefault();try{fn();}catch(e){}});"
    "btns.appendChild(b);return b;"
    "}"
    "mkBtn('sm-win-back','Back',function(){if(typeof historyBack==='function')historyBack();});"
    "mkBtn('sm-win-fwd','Forward',function(){if(typeof historyForward==='function')historyForward();});"
    "mkBtn('sm-win-up','Up',function(){if(typeof goUp==='function')goUp();else if(typeof Ext!=='undefined'&&Ext.getCmp){var u=Ext.getCmp('navi-button-up');if(u&&u.handler)u.handler.call(u);}});"
    "mkBtn('sm-win-ref','Refresh',smRefreshCurrentFolder);"
    "row.appendChild(btns);"
    "var searchWrap=document.createElement('div');"
    "searchWrap.id='sm-win-search-wrap';"
    "var sIn=document.createElement('input');"
    "sIn.type='search';sIn.id='sm-win-search-input';sIn.autocomplete='off';sIn.spellcheck=false;"
    "sIn.placeholder='Search Home';"
    "sIn.addEventListener('keydown',function(ev){"
    "if(ev.key==='Enter'){ev.preventDefault();smRunSearch(sIn.value);}"
    "});"
    "searchWrap.appendChild(sIn);"
    "row.appendChild(searchWrap);"
    "cp.insertBefore(row,cp.firstChild);"
    "}"
    # Keep Ext location-bar in DOM for APIs, but park it outside the visible flex row.
    "var loc=document.getElementById('location-bar');"
    "if(loc&&loc.parentNode===row){"
    "try{cp.appendChild(loc);}catch(e){}"
    "}"
    "try{smSyncWinHeaderLayout();}catch(e){}"
    "}catch(e){}"
    "}"
    "function smSyncWinHeaderLayout(){"
    "try{"
    "var cp=document.getElementById('control-panel');"
    "var hp=document.getElementById('headerPanel');"
    "var menu=document.getElementById('menu-bar');"
    "var row=document.getElementById('sm-win-explorer-bar');"
    "if(!cp)return;"
    "cp.style.height='auto';cp.style.minHeight='0';cp.style.maxHeight='none';"
    "cp.style.overflow='visible';cp.style.paddingTop='4px';cp.style.paddingBottom='4px';"
    "cp.style.position='relative';cp.style.zIndex='30';"
    "if(row){row.style.height='auto';row.style.minHeight='34px';}"
    "var topEdge=0;"
    "try{topEdge=(hp&&hp.getBoundingClientRect().top)||0;}catch(e){}"
    "var bottom=0;"
    "try{"
    "if(menu)bottom=Math.max(bottom,menu.getBoundingClientRect().bottom);"
    "bottom=Math.max(bottom,cp.getBoundingClientRect().bottom);"
    "if(row)bottom=Math.max(bottom,row.getBoundingClientRect().bottom);"
    "}catch(e){}"
    "var headerH=Math.max(78,Math.round(bottom-topEdge));"
    "if(hp){"
    "hp.style.height=headerH+'px';"
    "hp.style.minHeight=headerH+'px';"
    "hp.style.overflow='visible';"
    "hp.style.position='relative';"
    "hp.style.zIndex='25';"
    "}"
    "try{"
    "if(window.Ext&&Ext.getCmp){"
    "var _smCp=Ext.getCmp('control-panel');"
    "if(_smCp){"
    "var _smCpH=Math.max(38,(row&&row.offsetHeight)||34)+8;"
    "try{_smCp.height=_smCpH;}catch(e){}"
    "try{if(_smCp.setHeight)_smCp.setHeight(_smCpH);}catch(e){}"
    "}"
    "}"
    "}catch(e){}"
    "var ids=['main-panel','left-panel'];"
    "for(var i=0;i<ids.length;i++){"
    "var el=document.getElementById(ids[i]);"
    "if(!el)continue;"
    "var cur=parseInt(el.style.top||'0',10);"
    "if(isNaN(cur))cur=0;"
    "if(cur<headerH-1){"
    "el.style.top=headerH+'px';"
    "try{"
    "var vh=Math.max(document.documentElement.clientHeight||0,window.innerHeight||0);"
    "if(vh>headerH+40)el.style.height=(vh-headerH)+'px';"
    "}catch(e){}"
    "}"
    "try{"
    "if(window.Ext&&Ext.getCmp){"
    "var cmp=Ext.getCmp(ids[i]);"
    "if(cmp){"
    "cmp.y=headerH;"
    "try{if(cmp.setPagePosition)cmp.setPagePosition(cmp.getPosition(true)[0],headerH);}"
    "catch(e1){try{if(cmp.setPosition)cmp.setPosition(cmp.x||0,headerH);}catch(e2){}}"
    "}"
    "}"
    "}catch(e){}"
    "}"
    "try{"
    "var vp=typeof smFindViewport==='function'?smFindViewport():null;"
    "if(vp&&vp.doLayout)vp.doLayout(true,true);"
    "}catch(e){}"
    # Re-assert tops after Ext layout — it often parks center/west under the nav.
    "try{"
    "var hp2=document.getElementById('headerPanel');"
    "var headerH2=hp2?Math.round(hp2.getBoundingClientRect().height):headerH;"
    "if(!(headerH2>60))headerH2=headerH;"
    "var _smPush=['main-panel','left-panel'];"
    "for(var _pi=0;_pi<_smPush.length;_pi++){"
    "var el2=document.getElementById(_smPush[_pi]);"
    "if(!el2)continue;"
    "el2.style.top=headerH2+'px';"
    "try{"
    "var vh2=Math.max(document.documentElement.clientHeight||0,window.innerHeight||0);"
    "if(vh2>headerH2+40)el2.style.height=(vh2-headerH2)+'px';"
    "}catch(e){}"
    "}"
    "}catch(e){}"
    "}catch(e){}"
    "}"
    "function smPathParts(path){"
    "path=String(path||'/');"
    "return path.split('/').filter(function(p){return !!p;});"
    "}"
    "function smPathToDisplay(path){"
    "var parts=smPathParts(path);"
    "return parts.length?('Home > '+parts.join(' > ')):'Home';"
    "}"
    "function smDisplayToPath(text){"
    "text=String(text||'').trim();"
    "if(!text||text==='Home'||text==='Files'||text==='/')return '/';"
    "if(text.charAt(0)==='/')return text.replace(/\\/+/g,'/')||'/';"
    "text=text.replace(/^(Home|Files)\\s*>\\s*/i,'');"
    "var parts=text.split(/\\s*>\\s*/).map(function(p){return p.trim();}).filter(Boolean);"
    "return parts.length?('/'+parts.join('/')):'/';"
    "}"
    "function smUpdateSearchPlaceholder(path){"
    "try{"
    "var parts=smPathParts(path);"
    "var label=parts.length?parts[parts.length-1]:'Home';"
    "var ph='Search '+label;"
    "var sIn=document.getElementById('sm-win-search-input');"
    "if(sIn){sIn.placeholder=ph;sIn.setAttribute('aria-label',ph);}"
    "var tf=document.getElementById('search-textbox');"
    "if(tf){tf.setAttribute('placeholder',ph);}"
    "}catch(e){}"
    "}"
    "function smNavigatePath(path){"
    "try{"
    "path=smDisplayToPath(path);"
    "if(typeof selectTreePath_absolute==='function')selectTreePath_absolute(path);"
    "else if(typeof update_location_bar==='function')update_location_bar(path);"
    "}catch(e){}"
    "}"
    "function smWinClosest(el,sel){"
    "try{"
    "if(!el)return null;"
    "if(el.closest)return el.closest(sel);"
    "var cur=el;"
    "while(cur&&cur.nodeType===1){"
    "if(cur.id==='sm-win-address'&&sel.indexOf('sm-win-address')>=0)return cur;"
    "if(sel.charAt(0)==='.'&&cur.classList&&cur.classList.contains(sel.slice(1)))return cur;"
    "cur=cur.parentElement;"
    "}"
    "}catch(e){}"
    "return null;"
    "}"
    "function smWinHostOk(host,bar){"
    "try{"
    "if(!host||!bar)return false;"
    "if(!bar.contains(host))return false;"
    "var r=host.getBoundingClientRect();"
    "if(!r)return true;"
    "if(r.height>48)return false;"
    "return true;"
    "}catch(e){return false;}"
    "}"
    "function smCurrentNasPath(){"
    "try{"
    "if(window.Ext&&Ext.getCmp){"
    "var tree=Ext.getCmp('tree-panel');"
    "var node=tree&&tree.getSelectionModel().getSelectedNode();"
    "if(node&&node.path)return String(node.path);"
    "}"
    "}catch(e){}"
    "try{"
    "var host=document.getElementById('sm-win-address');"
    "if(host&&host.dataset&&host.dataset.path)return String(host.dataset.path);"
    "}catch(e){}"
    "return '/';"
    "}"
    "function smMountWinAddressHost(){"
    "try{"
    "smEnsureWinExplorerBar();"
    "var row=document.getElementById('sm-win-explorer-bar');"
    "if(!row)return null;"
    "var host=document.getElementById('sm-win-address');"
    "if(host&&!row.contains(host)){"
    "try{host.parentNode&&host.parentNode.removeChild(host);}catch(e){}"
    "host=null;"
    "}"
    "if(!host){"
    "host=document.createElement('div');"
    "host.id='sm-win-address';"
    "host.addEventListener('click',function(ev){"
    "var t=ev.target;"
    "if(smWinClosest(t,'.sm-win-crumb')||(t&&t.classList&&t.classList.contains('sm-win-edit')))return;"
    "host.classList.add('is-editing');"
    "var edit=host.querySelector('.sm-win-edit');"
    "if(edit){"
    "edit.value=smPathToDisplay(host.dataset.path||'/');"
    "edit.focus();edit.select();"
    "}"
    "});"
    "}"
    "var searchWrap=document.getElementById('sm-win-search-wrap');"
    "if(host.parentNode!==row||(searchWrap&&host.nextSibling!==searchWrap)){"
    "if(searchWrap)row.insertBefore(host,searchWrap);"
    "else row.appendChild(host);"
    "}"
    "host.classList.remove('sm-win-misplaced');"
    "try{host.style.display='';host.style.pointerEvents='';}catch(e){}"
    "return host;"
    "}catch(e){return null;}"
    "}"
    "function smRenderWinAddress(path){"
    "try{"
    "var host=smMountWinAddressHost();"
    "if(!host)return;"
    "path=String(path||'/');"
    "if(!path||path.charAt(0)!=='/')path='/'+(path||'');"
    "path=path.replace(/\\/+/g,'/')||'/';"
    "if(path.length>1&&path.charAt(path.length-1)==='/')path=path.slice(0,-1);"
    "if(host.dataset.path===path&&host.querySelector('.sm-win-crumb')){"
    "try{smUpdateSearchPlaceholder(path);}catch(e){}"
    "return;"
    "}"
    "host.dataset.path=path;"
    "host.classList.remove('is-editing');"
    "while(host.firstChild)host.removeChild(host.firstChild);"
    "var parts=smPathParts(path);"
    "var crumbs=[{name:'Home',path:'/'}];"
    "var acc='';"
    "for(var i=0;i<parts.length;i++){"
    "acc+='/'+parts[i];"
    "crumbs.push({name:parts[i],path:acc});"
    "}"
    "for(var c=0;c<crumbs.length;c++){"
    "if(c>0){"
    "var ch=document.createElement('span');"
    "ch.className='sm-win-chev';"
    "ch.textContent='\\u203A';"
    "host.appendChild(ch);"
    "}"
    "var btn=document.createElement('button');"
    "btn.type='button';"
    "btn.className='sm-win-crumb'+(c===crumbs.length-1?' is-current':'');"
    "btn.textContent=crumbs[c].name;"
    "btn.title=crumbs[c].path;"
    "btn.dataset.path=crumbs[c].path;"
    "if(c!==crumbs.length-1){"
    "btn.addEventListener('click',function(ev){"
    "ev.preventDefault();ev.stopPropagation();"
    "smNavigatePath(ev.currentTarget.dataset.path);"
    "});"
    "}"
    "host.appendChild(btn);"
    "}"
    # Trailing chevron like Windows Explorer after the current folder
    "var trail=document.createElement('span');"
    "trail.className='sm-win-chev';"
    "trail.textContent='\\u203A';"
    "host.appendChild(trail);"
    "var edit=document.createElement('input');"
    "edit.type='text';"
    "edit.className='sm-win-edit';"
    "edit.spellcheck=false;"
    "edit.value=smPathToDisplay(path);"
    "edit.addEventListener('keydown',function(ev){"
    "if(ev.key==='Enter'){"
    "ev.preventDefault();"
    "smNavigatePath(edit.value);"
    "host.classList.remove('is-editing');"
    "}"
    "else if(ev.key==='Escape'){"
    "ev.preventDefault();"
    "host.classList.remove('is-editing');"
    "smRenderWinAddress(host.dataset.path||'/');"
    "}"
    "});"
    "edit.addEventListener('blur',function(){"
    "setTimeout(function(){"
    "if(!host.classList.contains('is-editing'))return;"
    "host.classList.remove('is-editing');"
    "smRenderWinAddress(host.dataset.path||'/');"
    "},120);"
    "});"
    "host.appendChild(edit);"
    "try{smUpdateSearchPlaceholder(path);}catch(e){}"
    "}catch(e){}"
    "}"
    "function smEnsureWinAddress(optPath){"
    "try{"
    "document.documentElement.classList.add('sm-win-nav');"
    "var host=smMountWinAddressHost();"
    "if(!host)return;"
    "if(optPath!=null&&optPath!==''){"
    "smRenderWinAddress(String(optPath));"
    "}else if(!host.querySelector('.sm-win-crumb')){"
    "smRenderWinAddress(smCurrentNasPath());"
    "}"
    "}catch(e){}"
    "}"
    "function smHookWinLocation(){"
    "try{"
    "if(window.__smLocHooked)return true;"
    "if(typeof update_location_bar!=='function')return false;"
    "window.__smLocHooked=true;"
    "var _smOrigLoc=update_location_bar;"
    "update_location_bar=function(path){"
    "var ret;"
    "try{ret=_smOrigLoc.apply(this,arguments);}catch(e){ret=undefined;}"
    "try{smRenderWinAddress(path||'/');}catch(e){}"
    "return ret;"
    "};"
    "try{"
    "if(window.Ext&&Ext.getCmp){"
    "var tree=Ext.getCmp('tree-panel');"
    "if(tree&&tree.getSelectionModel&&!tree.__smWinPathHook){"
    "tree.__smWinPathHook=true;"
    "tree.getSelectionModel().on('selectionchange',function(sm,node){"
    "try{if(node&&node.path)smRenderWinAddress(node.path);}catch(e){}"
    "});"
    "}"
    "}"
    "}catch(e){}"
    "return true;"
    "}catch(e){return false;}"
    "}"
    "function smMoveAuthToTop(){"
    "try{"
    "var user=document.getElementById('userName');"
    "var login=document.getElementById('login_button');"
    "var logout=document.getElementById('logout_button');"
    "var menu=document.getElementById('menu-bar');"
    "if(!menu||(!user&&!login&&!logout))return false;"
    # Prefer Ext component relocate when toolbars are ready.
    "try{"
    "if(window.Ext&&Ext.getCmp){"
    "var menuCmp=Ext.getCmp('menu-bar');"
    "var iconCmp=Ext.getCmp('icon-panel');"
    "function take(id){"
    "var c=Ext.getCmp(id);if(!c)return null;"
    "try{if(c.ownerCt&&c.ownerCt!==menuCmp&&c.ownerCt.remove)c.ownerCt.remove(c,false);}catch(e){}"
    "return c;}"
    "if(menuCmp&&!window.__smAuthExt){"
    "var u=take('userName'),li=take('login_button'),lo=take('logout_button');"
    "if(u||li||lo){"
    "try{if(!Ext.getCmp('sm-auth-fill'))menuCmp.add({xtype:'tbfill',id:'sm-auth-fill'});}catch(e){}"
    "try{if(u)menuCmp.add(u);}catch(e){}"
    "try{if(li)menuCmp.add(li);}catch(e){}"
    "try{if(lo)menuCmp.add(lo);}catch(e){}"
    "try{menuCmp.doLayout();}catch(e){}"
    "window.__smAuthExt=true;"
    "}"
    "}"
    "}"
    "}catch(e){}"
    "var slot=smAuthSlot();"
    "if(!slot){smHideIconBar();return !!window.__smAuthExt;}"
    "var moved=false;"
    "function park(id){"
    "var el=document.getElementById(id);"
    "if(!el)return;"
    "if(slot.contains(el))return;"
    "var cell=smAuthCell(el);"
    "if(!cell)return;"
    "if(cell.parentNode===slot)return;"
    "slot.appendChild(cell);"
    "moved=true;"
    "}"
    "park('userName');park('login_button');park('logout_button');"
    "smHideIconBar();"
    "if(moved||window.__smAuthExt){"
    "window.__smAuthMoved=true;"
    "}"
    "return true;"
    "}catch(e){return false;}}"
    "try{window.smMoveAuthToTop=smMoveAuthToTop;window.smHideIconBar=smHideIconBar;window.smMergeNaviBar=smMergeNaviBar;window.smPathToDisplay=smPathToDisplay;window.smDisplayToPath=smDisplayToPath;window.smEnsureWinAddress=smEnsureWinAddress;window.smRenderWinAddress=smRenderWinAddress;window.smMountWinAddressHost=smMountWinAddressHost;window.smNavigatePath=smNavigatePath;window.smEnsureWinExplorerBar=smEnsureWinExplorerBar;window.smSyncWinHeaderLayout=smSyncWinHeaderLayout;window.smRefreshCurrentFolder=smRefreshCurrentFolder;window.smUpdateSearchPlaceholder=smUpdateSearchPlaceholder;window.smRunSearch=smRunSearch;window.smHookWinLocation=smHookWinLocation;window.smCurrentNasPath=smCurrentNasPath;}catch(e){}"
    "function smKickFilesLoad(){"
    "try{"
    "if(window.__smKickFilesDone)return true;"
    "if(window.__smKickFilesPending)return false;"
    "window.__smKickTries=(window.__smKickTries||0)+1;"
    "if(window.__smKickTries>3){"
    "window.__smKickFilesDone=true;"
    "try{if(typeof smClearStuckMask==='function')smClearStuckMask();}catch(e){}"
    "return true;"
    "}"
    "if(!window.Ext||!Ext.getCmp)return false;"
    "var tree=Ext.getCmp('tree-panel');"
    "if(!tree)return false;"
    "var node=tree.getSelectionModel().getSelectedNode();"
    "if(!node){node=tree.getNodeById('/');if(node)try{tree.getSelectionModel().select(node);}catch(e){}}"
    "if(!node)return false;"
    "var dir=node;"
    "try{if(dir.isLeaf&&dir.isLeaf())dir=dir.parentNode;}catch(e){}"
    "if(!dir)return false;"
    "window.__smKickFilesPending=true;"
    "function smKickDone(){"
    "window.__smKickFilesDone=true;"
    "window.__smKickFilesPending=false;"
    "try{if(window.loadingAnimation&&loadingAnimation.hideAll)loadingAnimation.hideAll();}catch(e){}"
    "try{if(typeof smClearStuckMask==='function')smClearStuckMask();}catch(e){}"
    "}"
    "if(typeof addRecordWithPath==='function'){"
    "addRecordWithPath(dir,smKickDone);"
    "}else{"
    "var main=Ext.getCmp('main-panel');"
    "if(!main||typeof main.getComponent!=='function'){window.__smKickFilesPending=false;return false;}"
    "var view=main.getComponent(0);"
    "if(!view||typeof view.updateView!=='function'){window.__smKickFilesPending=false;return false;}"
    "view.updateView(node,smKickDone);"
    "}"
    "setTimeout(function(){"
    "if(window.__smKickFilesDone)return;"
    "window.__smKickFilesPending=false;"
    "try{if(window.loadingAnimation&&loadingAnimation.hideAll)loadingAnimation.hideAll();}catch(e){}"
    "try{if(typeof smClearStuckMask==='function')smClearStuckMask();}catch(e){}"
    "try{if(typeof smKickFilesLoad==='function')smKickFilesLoad();}catch(e){}"
    "},8000);"
    "return true;"
    "}catch(e){window.__smKickFilesPending=false;return false;}}"
    "try{window.smKickFilesLoad=smKickFilesLoad;}catch(e){}"
    "try{smHideIconBar();}catch(e){}"
    "try{"
    "var _smAuthN=0;"
    "var _smAuthT=setInterval(function(){"
    "smMoveAuthToTop();smHideIconBar();smMergeNaviBar();smHookWinLocation();"
    "if(!window.__smKickFilesDone&&!window.__smKickFilesPending)smKickFilesLoad();"
    "if(++_smAuthN>=24||(window.__smNaviMerged&&window.__smKickFilesDone))clearInterval(_smAuthT);"
    "},400);"
    "if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',function(){smMoveAuthToTop();smMergeNaviBar();smKickFilesLoad();},false);"
    "window.addEventListener('load',function(){smMoveAuthToTop();smHideIconBar();smMergeNaviBar();smKickFilesLoad();},false);"
    "}catch(e){}"
    "function smMsgVisible(){"
    "try{"
    "var boxes=document.querySelectorAll('.x-msgbox,.x-sheet');"
    "for(var i=0;i<boxes.length;i++){"
    "var el=boxes[i];"
    "var cls=String(el.className||'');"
    "if(cls.indexOf('x-hidden')>=0||cls.indexOf('x-item-hidden')>=0)continue;"
    "return true;"
    "}"
    "}catch(e){}"
    "return false;}"
    "function smClearDialogInlineStyles(root){"
    "try{"
    "var nodes=root?[root]:[];"
    "if(root&&root.querySelectorAll){"
    "var kids=root.querySelectorAll('.x-docked-bottom,.x-toolbar,.x-button,.x-input-el,input,textarea,.x-field-input,.x-msgbox-body,.x-body');"
    "for(var i=0;i<kids.length;i++)nodes.push(kids[i]);"
    "}"
    "for(var n=0;n<nodes.length;n++){"
    "var el=nodes[n];if(!el||!el.style)continue;"
    "el.style.removeProperty('display');"
    "el.style.removeProperty('visibility');"
    "el.style.removeProperty('opacity');"
    "el.style.removeProperty('pointer-events');"
    "el.style.removeProperty('height');"
    "el.style.removeProperty('min-height');"
    "el.style.removeProperty('overflow');"
    "}"
    "}catch(e){}}"
    "function smRestoreDialogs(){"
    "try{"
    "var boxes=document.querySelectorAll('.x-msgbox,.x-sheet');"
    "for(var i=0;i<boxes.length;i++){"
    "var el=boxes[i];"
    "var cls=String(el.className||'');"
    "if(cls.indexOf('x-hidden')>=0||cls.indexOf('x-item-hidden')>=0)continue;"
    "smClearDialogInlineStyles(el);"
    "}"
    "}catch(e){}}"
    "function smHideOrphanDialogs(){"
    "try{"
    "/* Class-based hide only — never sticky inline !important (breaks Ext.Msg reuse / rename). */"
    "var boxes=document.querySelectorAll('.x-msgbox,.x-sheet');"
    "for(var i=0;i<boxes.length;i++){"
    "var el=boxes[i];"
    "var cls=String(el.className||'');"
    "if(cls.indexOf('x-hidden')<0&&cls.indexOf('x-item-hidden')<0){"
    "smClearDialogInlineStyles(el);"
    "}"
    "}"
    "}catch(e){}}"
    "function smClearStuckMask(){"
    "try{"
    "smHideOrphanDialogs();"
    "if(smMsgVisible()){smRestoreDialogs();return;}"
    "try{if(window.loadingAnimation&&loadingAnimation.hideAll)loadingAnimation.hideAll();}catch(e){}"
    "try{if(window.Ext&&Ext.getBody)Ext.getBody().unmask();}catch(e){}"
    "var lm=document.getElementById('loading-main');"
    "var lmk=document.getElementById('loading-mask');"
    "if(lm){lm.style.display='none';lm.style.visibility='hidden';}"
    "if(lmk){lmk.style.display='none';lmk.style.visibility='hidden';}"
    "if(window.Ext&&Ext.app){"
    "try{if(Ext.app.Util&&Ext.app.Util.hideMask)Ext.app.Util.hideMask();}catch(e){}"
    "try{if(Ext.app.loadMask&&Ext.app.loadMask.hide)Ext.app.loadMask.hide();}catch(e){}"
    "}"
    "var nodes=document.querySelectorAll('.x-mask,.x-mask-msg,.x-loading-spinner,.x-loading-spinner-outer');"
    "for(var i=0;i<nodes.length;i++){"
    "var n=nodes[i];"
    "try{if(n.closest&&(n.closest('.x-msgbox')||n.closest('.x-sheet')))continue;}catch(e){}"
    "n.classList.add('sm-nas-mask-clear');"
    "n.style.display='none';"
    "n.style.pointerEvents='none';"
    "n.style.visibility='hidden';"
    "}"
    "}catch(e){}}"
    "function smDisableDisplayingOverlay(){"
    "try{"
    "var hide=function(){"
    "try{var lm=document.getElementById('loading-main');if(lm){lm.style.setProperty('display','none','important');lm.style.setProperty('visibility','hidden','important');}}catch(e){}"
    "try{var lmk=document.getElementById('loading-mask');if(lmk){lmk.style.setProperty('display','none','important');lmk.style.setProperty('visibility','hidden','important');}}catch(e){}"
    "try{if(window.Ext&&Ext.getBody)Ext.getBody().unmask();}catch(e){}"
    "};"
    "hide();"
    "if(window.loadingAnimation){"
    "try{loadingAnimation.show=function(){hide();return;};}catch(e){}"
    "try{loadingAnimation.changeText=function(){return;};}catch(e){}"
    "try{if(loadingAnimation.hideAll)loadingAnimation.hideAll();}catch(e){}"
    "}"
    "}catch(e){}}"
    "try{"
    "smDisableDisplayingOverlay();"
    "setInterval(smDisableDisplayingOverlay,4000);"
    "setTimeout(smClearStuckMask,2500);"
    "setTimeout(smClearStuckMask,8000);"
    "var _smMaskClickAt=0;"
    "document.addEventListener('touchstart',function(ev){"
    "try{var t=ev&&ev.target;if(t&&t.closest&&t.closest('.x-msgbox,.x-sheet,input,textarea,.x-input-el,.x-field,#sm-win-address')){smRestoreDialogs();return;}}catch(e){}"
    "var now=Date.now();if(now-_smMaskClickAt<1500)return;_smMaskClickAt=now;"
    "smClearStuckMask();"
    "},true);"
    "document.addEventListener('click',function(ev){"
    "try{var t=ev&&ev.target;if(t&&t.closest&&t.closest('.x-msgbox,.x-sheet,input,textarea,.x-input-el,.x-field,#sm-win-address')){smRestoreDialogs();return;}}catch(e){}"
    "var now=Date.now();if(now-_smMaskClickAt<1500)return;_smMaskClickAt=now;"
    "smClearStuckMask();"
    "},true);"
    "function smHookMsgShow(){"
    "try{"
    "if(!window.Ext||!Ext.Msg||Ext.Msg.__smShowHooked)return;"
    "Ext.Msg.__smShowHooked=true;"
    "Ext.Msg.on('show',function(){setTimeout(smRestoreDialogs,0);setTimeout(smRestoreDialogs,50);setTimeout(smRestoreDialogs,200);});"
    "Ext.Msg.on('hide',function(){setTimeout(smHideOrphanDialogs,0);});"
    "}catch(e){}}"
    "smHookMsgShow();"
    "setTimeout(smHookMsgShow,500);"
    "setTimeout(smHookMsgShow,1500);"
    "}catch(e){}"
    "try{window.smRestoreDialogs=smRestoreDialogs;window.smHideOrphanDialogs=smHideOrphanDialogs;window.smDisableDisplayingOverlay=smDisableDisplayingOverlay;}catch(e){}"
    "function smIsNasSettingsWindow(winEl){"
    "try{"
    "if(!winEl||!winEl.classList||!winEl.classList.contains('x-window'))return false;"
    "var cls=String(winEl.className||'');"
    "if(cls.indexOf('x-hidden')>=0||cls.indexOf('x-item-hidden')>=0)return false;"
    "if(winEl.id==='login-window')return false;"
    "var header=winEl.querySelector('.x-window-header-text');"
    "var title=String((header&&(header.textContent||header.innerText))||'').trim().toLowerCase();"
    "if(title.indexOf('settings')<0)return false;"
    "var body=winEl.querySelector('.x-window-body')||winEl;"
    "var txt=String(body.textContent||'').toLowerCase();"
    "return txt.indexOf('display language')>=0||txt.indexOf('select a display language')>=0;"
    "}catch(e){return false;}}"
    "function smSaveDownload(url,filename,onDone){"
    "var done=onDone||function(){};"
    "fetch(url,{credentials:'include'})"
    ".then(function(res){if(!res.ok)throw new Error('download failed ('+res.status+')');return res.blob();})"
    ".then(function(blob){"
    "var obj=URL.createObjectURL(blob);"
    "var a=document.createElement('a');"
    "a.href=obj;a.download=filename;a.rel='noopener';"
    "(document.body||document.documentElement).appendChild(a);"
    "a.click();a.remove();"
    "setTimeout(function(){try{URL.revokeObjectURL(obj);}catch(e){}},1500);"
    "done(null);"
    "})"
    ".catch(function(err){done(err||new Error('download failed'));});}"
    "function smDownloadNasBundle(){"
    "try{"
    "var base='';"
    "try{base=(window.top&&window.top.location&&window.top.location.origin)||window.location.origin||'';}catch(e){base=window.location.origin||'';}"
    "fetch((base||'')+'/api/nas/download-token',{credentials:'include'})"
    ".then(function(res){return res.json().then(function(data){return {res:res,data:data};});})"
    ".then(function(o){"
    "if(!o.res.ok||!o.data||!o.data.ok||!o.data.token)throw new Error('login required');"
    "var path=o.data.setup||o.data.cmd||('/api/nas/windows-setup?t='+encodeURIComponent(o.data.token));"
    "return smSaveDownload((base||'')+path,'Setup-ServerManagerNas.cmd',function(err){"
    "if(err)throw err;"
    "try{alert('Downloaded Setup-ServerManagerNas.cmd\\n\\nOpen your Downloads folder and double-click it. Click Yes on the Windows security prompt.');}catch(e){}"
    "});"
    "})"
    ".catch(function(){try{alert('Log in to the portal first, then click Download Setup again.');}catch(e){}});"
    "}catch(e){try{alert('Download failed. Log in to the portal and try again.');}catch(e2){}}}"
    "function smDownloadNasPs1(){smDownloadNasBundle();}"
    "function smInjectNasSettingsDownload(winEl){"
    "try{"
    "if(!smIsNasSettingsWindow(winEl))return;"
    "var body=winEl.querySelector('.x-window-body')||winEl.querySelector('.x-window-mc')||winEl;"
    "if(!body||body.querySelector('#sm-settings-nas-row'))return;"
    "var row=document.createElement('div');"
    "row.id='sm-settings-nas-row';"
    "var label=document.createElement('div');"
    "label.className='sm-settings-nas-label';"
    "label.textContent='Windows File Explorer:';"
    "var btn=document.createElement('button');"
    "btn.type='button';btn.id='sm-settings-nas-dl';btn.className='sm-settings-nas-btn';"
    "btn.textContent='Download Setup';"
    "btn.addEventListener('click',function(ev){ev.preventDefault();ev.stopPropagation();smDownloadNasBundle();});"
    "var hint=document.createElement('div');"
    "hint.className='sm-settings-nas-hint';"
    "hint.textContent='Downloads one Setup-ServerManagerNas.cmd file. Double-click it from Downloads (allow admin if asked).';"
    "row.appendChild(label);row.appendChild(btn);row.appendChild(hint);"
    "body.appendChild(row);"
    "}catch(e){}}"
    "function smScanNasSettingsWindows(){"
    "try{"
    "var wins=document.querySelectorAll('.x-window');"
    "for(var i=0;i<wins.length;i++)smInjectNasSettingsDownload(wins[i]);"
    "}catch(e){}}"
    "function smWatchNasSettingsWindows(){"
    "if(window.__smNasSettingsWatch)return;"
    "window.__smNasSettingsWatch=true;"
    "smScanNasSettingsWindows();"
    "try{"
    "var mo=new MutationObserver(function(){setTimeout(smScanNasSettingsWindows,0);});"
    "mo.observe(document.body||document.documentElement,{childList:true,subtree:true,attributes:true,attributeFilter:['class','style']});"
    "}catch(e){setInterval(smScanNasSettingsWindows,1500);}"
    "document.addEventListener('click',function(){setTimeout(smScanNasSettingsWindows,80);setTimeout(smScanNasSettingsWindows,400);},true);"
    "}"
    "smWatchNasSettingsWindows();"
    "try{window.smDownloadNasPs1=smDownloadNasPs1;window.smScanNasSettingsWindows=smScanNasSettingsWindows;}catch(e){}"
    # Keep Ext.Viewport sized to the iframe — parent layout changes often skip window.resize.
    "function smNasViewSize(){"
    "var w=Math.max(document.documentElement.clientWidth||0,window.innerWidth||0);"
    "var h=Math.max(document.documentElement.clientHeight||0,window.innerHeight||0);"
    "try{if(window.visualViewport){"
    "w=Math.max(w,Math.floor(visualViewport.width)||0);"
    "h=Math.max(h,Math.floor(visualViewport.height)||0);}}catch(e){}"
    "return {w:w,h:h};}"
    "function smPatchExtDom(){"
    "try{"
    "if(!window.Ext||!Ext.lib||!Ext.lib.Dom)return false;"
    "if(Ext.lib.Dom.__smPatched)return true;"
    "Ext.lib.Dom.getViewWidth=function(){return smNasViewSize().w;};"
    "Ext.lib.Dom.getViewHeight=function(){return smNasViewSize().h;};"
    "Ext.lib.Dom.__smPatched=true;"
    "return true;"
    "}catch(e){return false;}}"
    "function smFindViewport(){"
    "var vp=null;"
    "try{"
    "if(window.Ext&&Ext.ComponentMgr&&Ext.ComponentMgr.all&&Ext.ComponentMgr.all.each){"
    "Ext.ComponentMgr.all.each(function(c){"
    "try{"
    "if(!c)return;"
    "if(c.getXType&&c.getXType()==='viewport'){vp=c;return false;}"
    "if(c.layout&&(c.layout.type==='border'||c.layout==='border')&&c.el&&c.el.hasClass&&c.el.hasClass('x-viewport')){vp=c;return false;}"
    "}catch(e){}"
    "});}"
    "}catch(e){}"
    "return vp;}"
    "function smNasDataViewRoot(panelId){"
    "try{"
    "var panel=document.getElementById(panelId);"
    "if(!panel)return null;"
    "var bl=panel.querySelector('.x-border-layout-ct');"
    "if(!bl)return null;"
    "for(var i=0;i<bl.children.length;i++){"
    "var c=bl.children[i];"
    "if(!c||!c.classList)continue;"
    "if(c.classList.contains('x-toolbar'))continue;"
    "if(c.querySelector('.icon-thumbnail')||c.classList.contains('x-border-panel'))return c;"
    "}"
    "}catch(e){}"
    "return null;}"
    "function smFixIconGridLabels(){"
    "try{"
    "if(window.__smFixGridBusy)return;"
    "window.__smFixGridBusy=true;"
    "try{smFixSideBySideRows();}catch(e){}"
    "var tilePanels=['icon-panel-small','icon-panel-medium','icon-panel-large'];"
    "for(var p=0;p<tilePanels.length;p++){"
    "var root=smNasDataViewRoot(tilePanels[p]);"
    "if(!root)continue;"
    "var min=tilePanels[p].indexOf('small')>=0?88:tilePanels[p].indexOf('large')>=0?208:128;"
    "try{"
    "var bl=root.closest('.x-border-layout-ct');"
    "if(bl){"
    "bl.style.setProperty('width','100%','important');bl.style.setProperty('max-width','100%','important');"
    "var tb=bl.querySelector(':scope > .x-toolbar');"
    "if(tb){"
    "tb.style.setProperty('display','none','important');"
    "tb.style.setProperty('visibility','hidden','important');"
    "tb.style.setProperty('height','0','important');"
    "tb.style.setProperty('min-height','0','important');"
    "tb.style.setProperty('max-height','0','important');"
    "tb.style.setProperty('overflow','hidden','important');"
    "tb.style.setProperty('padding','0','important');"
    "tb.style.setProperty('margin','0','important');"
    "tb.style.setProperty('border','0','important');"
    "}"
    "}"
    "root.style.setProperty('display','grid','important');"
    "root.style.setProperty('grid-template-columns','repeat(auto-fill,minmax('+min+'px,1fr))','important');"
    "root.style.setProperty('gap','10px 12px','important');"
    "root.style.setProperty('position','relative','important');"
    "root.style.setProperty('width','100%','important');"
    "root.style.setProperty('min-width','100%','important');"
    "root.style.setProperty('max-width','100%','important');"
    "root.style.setProperty('height','auto','important');"
    "root.style.setProperty('min-height','0','important');"
    "root.style.setProperty('left','0','important');"
    "root.style.setProperty('top','0','important');"
    "}catch(e){}"
    "root.querySelectorAll(':scope > .icon-thumbnail').forEach(function(el){"
    "try{"
    "el.style.setProperty('position','static','important');"
    "el.style.setProperty('float','none','important');"
    "el.style.setProperty('left','auto','important');"
    "el.style.setProperty('top','auto','important');"
    "el.style.setProperty('width','auto','important');"
    "el.style.setProperty('max-width','none','important');"
    "el.style.setProperty('margin','0','important');"
    "el.style.setProperty('padding','0','important');"
    "el.style.removeProperty('flex');"
    "el.style.removeProperty('height');"
    "}catch(e){}"
    "});"
    "}"
    "var side=smNasDataViewRoot('sidebyside-panel');"
    "if(side){"
    "try{"
    "side.style.setProperty('display','block','important');"
    "side.style.setProperty('width','100%','important');"
    "side.style.setProperty('max-width','100%','important');"
    "side.style.setProperty('box-sizing','border-box','important');"
    # Keep Ext border-layout top/left/height so the sort toolbar is not covered.
    "side.style.removeProperty('min-width');"
    "try{"
    "var ct=side.parentElement;"
    "var tb=ct&&ct.querySelector(':scope > .x-toolbar');"
    "if(tb){"
    "var th=Math.max(32,Math.round(tb.getBoundingClientRect().height||40));"
    "var top=parseInt(side.style.top||'0',10); if(isNaN(top))top=0;"
    "if(top<th-1)side.style.top=th+'px';"
    "var ch=ct.getBoundingClientRect().height||0;"
    "if(ch>th+40)side.style.height=Math.max(120,Math.round(ch-th))+'px';"
    "}"
    "}catch(e){}"
    "}catch(e){}"
    "side.querySelectorAll(':scope > .icon-thumbnail').forEach(function(el){"
    "try{"
    "el.style.setProperty('position','static','important');"
    "el.style.setProperty('float','none','important');"
    "el.style.setProperty('left','auto','important');"
    "el.style.setProperty('top','auto','important');"
    "el.style.setProperty('width','100%','important');"
    "el.style.setProperty('max-width','100%','important');"
    "el.style.removeProperty('flex');"
    "el.style.removeProperty('height');"
    "}catch(e){}"
    "});"
    "}"
    "}catch(e){}"
    "finally{window.__smFixGridBusy=false;}"
    "}"
    "function smSideBySideStore(){"
    "try{"
    "if(!window.Ext||!Ext.getCmp)return null;"
    "var p=Ext.getCmp('sidebyside-panel');"
    "if(!p)return null;"
    "var dv=null;"
    "try{dv=p.getDataView&&p.getDataView();}catch(e){}"
    "if(!dv)dv=p.view;"
    "return (dv&&dv.store)||null;"
    "}catch(e){return null;}"
    "}"
    "function smFixSideBySideRows(){"
    "try{"
    "var panel=document.getElementById('sidebyside-panel');"
    "if(!panel)return;"
    "var store=smSideBySideStore();"
    "var thumbs=panel.querySelectorAll('.icon-thumbnail');"
    "function smRecGet(rec,key){"
    "try{if(rec&&rec.get)return rec.get(key);}catch(e){}"
    "try{if(rec&&rec.data)return rec.data[key];}catch(e){}"
    "return null;"
    "}"
    "function smFmtSideDate(v){"
    "try{"
    "if(v==null||v==='')return '';"
    "if(Object.prototype.toString.call(v)==='[object Date]'&&!isNaN(v.getTime())){"
    "function z(n){n=String(n);return n.length<2?('0'+n):n;}"
    "return v.getFullYear()+'/'+z(v.getMonth()+1)+'/'+z(v.getDate())+' '+z(v.getHours())+':'+z(v.getMinutes());"
    "}"
    "var s=String(v);"
    "if(/GMT|UTC|Coordinated Universal Time/i.test(s)){"
    "var d=new Date(s);"
    "if(!isNaN(d.getTime()))return smFmtSideDate(d);"
    "}"
    "return s;"
    "}catch(e){return String(v||'');}"
    "}"
    "for(var i=0;i<thumbs.length;i++){"
    "var thumb=thumbs[i];"
    "var info=thumb.querySelector('.icon-info');"
    "if(!info)continue;"
    "var nameEl=info.querySelector('.x-editable');"
    "var spans=[];"
    "var kids=info.children;"
    "for(var k=0;k<kids.length;k++){"
    "if(kids[k].classList&&kids[k].classList.contains('x-editable'))continue;"
    "if(kids[k].tagName==='SPAN')spans.push(kids[k]);"
    "}"
    "var rec=null;"
    "try{if(store&&store.getAt)rec=store.getAt(i);}catch(e){}"
    "var fullName='';"
    "var sizeText='';"
    "var dateText='';"
    "var typeText='';"
    "var isDir=false;"
    "if(rec){"
    "fullName=String(smRecGet(rec,'name')||smRecGet(rec,'text')||'');"
    "isDir=!!smRecGet(rec,'directory');"
    "sizeText=String(smRecGet(rec,'size_string')||'');"
    "dateText=smFmtSideDate(smRecGet(rec,'dateString')||smRecGet(rec,'time_string')||smRecGet(rec,'mtime')||'');"
    "if(isDir)typeText='Folder';"
    "else{"
    "var ext=String(smRecGet(rec,'extension')||'');"
    "typeText=ext?ext.replace(/^\\./,'').toUpperCase():'File';"
    "}"
    "if(!sizeText){"
    "if(isDir)sizeText='—';"
    "else{"
    "var sz=smRecGet(rec,'size');"
    "sizeText=(sz==null||sz==='')?'—':String(sz);"
    "}"
    "}"
    "}"
    "if(nameEl){"
    "if(fullName){"
    "if((nameEl.textContent||'')!==fullName)nameEl.textContent=fullName;"
    "nameEl.setAttribute('title',fullName);"
    "}else{"
    "var cur=(nameEl.textContent||'').trim();"
    "if(cur)nameEl.setAttribute('title',cur);"
    "}"
    "}"
    "if(!dateText&&spans[1])dateText=smFmtSideDate((spans[1].textContent||'').trim());"
    "if(sizeText==='--'||sizeText==='-'||sizeText==='')sizeText='—';"
    "while(spans.length<3){"
    "var ns=document.createElement('span');"
    "info.appendChild(ns);"
    "spans.push(ns);"
    "}"
    "spans[0].textContent=sizeText;"
    "spans[0].classList.add('sm-nas-col-size');"
    "spans[0].classList.remove('sm-nas-size-empty');"
    "if(sizeText==='—')spans[0].classList.add('sm-nas-size-empty');"
    "spans[1].textContent=dateText;"
    "spans[1].classList.add('sm-nas-col-date');"
    "spans[2].textContent=typeText||'';"
    "spans[2].classList.add('sm-nas-col-type');"
    "}"
    "}catch(e){}"
    "}"
    "function smScheduleFixIconGrid(){"
    "try{"
    "if(window.__smFixGridTimer)return;"
    "window.__smFixGridTimer=setTimeout(function(){"
    "window.__smFixGridTimer=null;"
    "try{smFixIconGridLabels();}catch(e){}"
    "},80);"
    "}catch(e){try{smFixIconGridLabels();}catch(e2){}}"
    "}"
    "function smPatchDataViewRefresh(){"
    "try{"
    "if(window.__smDvPatched||!window.Ext||!Ext.DataView)return;"
    "var orig=Ext.DataView.prototype.refresh;"
    "if(!orig)return;"
    "Ext.DataView.prototype.refresh=function(){"
    "var out=orig.apply(this,arguments);"
    "try{"
    "if(this.el&&this.el.dom){"
    "this.el.dom.style.setProperty('width','100%','important');"
    "this.el.dom.style.setProperty('max-width','100%','important');"
    "}"
    "if(window.smScheduleFixIconGrid)window.smScheduleFixIconGrid();"
    "else if(window.smFixIconGridLabels)window.smFixIconGridLabels();"
    "}catch(e){}"
    "return out;};"
    "window.__smDvPatched=true;"
    "}catch(e){}}"
    "function smWatchIconGrid(){"
    "try{"
    "smPatchDataViewRefresh();"
    "if(window.__smIconGridWatch)return;"
    "window.__smIconGridWatch=true;"
    "function hook(){"
    "['icon-panel-small','icon-panel-medium','icon-panel-large','sidebyside-panel'].forEach(function(pid){"
    "var view=smNasDataViewRoot(pid);"
    "if(!view||view.__smObserved)return;"
    "view.__smObserved=true;"
    "try{"
    # childList only — watching style/class re-triggers smFixIconGridLabels forever
    "new MutationObserver(function(){try{smScheduleFixIconGrid();}catch(e){}})"
    ".observe(view,{childList:true,subtree:true});"
    "}catch(e){}"
    "});"
    "smScheduleFixIconGrid();"
    "}"
    "hook();"
    "setInterval(hook,4000);"
    "}catch(e){}}"
    "function smRefreshFileIconView(){"
    "try{"
    "if(!window.Ext||!Ext.getCmp)return false;"
    "var main=Ext.getCmp('main-panel');"
    "if(!main||typeof main.getComponent!=='function')return false;"
    "var cv=main.getComponent(0);"
    "if(!cv)return false;"
    "var dv=(cv.getDataView&&cv.getDataView())||(cv.view&&cv.view.getView&&cv.view.getView())||null;"
    "if(dv&&dv.refresh){dv.refresh();try{if(window.smScheduleFixIconGrid)smScheduleFixIconGrid();else smFixIconGridLabels();}catch(e){}return true;}"
    "try{if(window.smScheduleFixIconGrid)smScheduleFixIconGrid();else smFixIconGridLabels();}catch(e){}"
    "}catch(e){}"
    "return false;}"
    "function smNasFit(force){"
    "try{"
    "smPatchExtDom();"
    "var sz=smNasViewSize();var w=sz.w;var h=sz.h;"
    "if(!(w>0&&h>0))return;"
    # Avoid resetting Sencha's scroller on every timer tick.
    "if(!force&&window.__smNasFitW===w&&window.__smNasFitH===h)return;"
    "window.__smNasFitW=w;window.__smNasFitH=h;"
    "var narrow=w<=900;"
    "try{document.documentElement.style.height=h+'px';document.documentElement.style.width=w+'px';}catch(e){}"
    "try{if(document.body){document.body.style.height=h+'px';document.body.style.width=w+'px';}}catch(e){}"
    "if(window.Ext){"
    "try{"
    "var fp=Ext.getCmp&&Ext.getCmp('footer-panel');"
    "if(fp){"
    "if(narrow){try{fp.setHeight(0);}catch(e){}try{fp.hide();}catch(e){}}"
    "else{try{fp.setHeight(typeof FOOTER_HEIGHT==='number'?FOOTER_HEIGHT:15);}catch(e){}try{fp.show();}catch(e){}}"
    "}"
    "}catch(e){}"
    "try{if(Ext.EventManager&&Ext.EventManager.fireResize)Ext.EventManager.fireResize(w,h);}catch(e){}"
    "try{if(typeof smMoveAuthToTop==='function')smMoveAuthToTop();}catch(e){}"
    "try{if(typeof smHideIconBar==='function')smHideIconBar();}catch(e){}"
    "try{if(typeof smMergeNaviBar==='function')smMergeNaviBar();}catch(e){}"
    "try{if(typeof smSyncWinHeaderLayout==='function')smSyncWinHeaderLayout();}catch(e){}"
    "try{if(typeof smKickFilesLoad==='function'&&!window.__smKickFilesDone&&!window.__smKickFilesPending)smKickFilesLoad();}catch(e){}"
    "try{if(typeof smWatchIconGrid==='function')smWatchIconGrid();}catch(e){}"
    "var vp=smFindViewport();"
    "if(vp){"
    "try{if(vp.setSize)vp.setSize(w,h);}catch(e){}"
    "try{if(vp.doLayout)vp.doLayout(true,true);}catch(e){}"
    "}"
    "try{if(typeof smScheduleFixIconGrid==='function')smScheduleFixIconGrid();else if(typeof smFixIconGridLabels==='function')smFixIconGridLabels();}catch(e){}"
    "try{"
    "var main=Ext.getCmp&&Ext.getCmp('main-panel');"
    "var left=Ext.getCmp&&Ext.getCmp('left-panel');"
    "var tree=Ext.getCmp&&Ext.getCmp('tree-panel');"
    "var details=Ext.getCmp&&Ext.getCmp('details-panel');"
    "if(main&&main.doLayout)main.doLayout(true,true);"
    "if(left&&left.doLayout)left.doLayout(true,true);"
    "if(narrow&&left){"
    "try{if(left.collapse&&!left.collapsed)left.collapse();}catch(e){}"
    "}"
    "if(narrow&&left&&tree){"
    "var lh=0;"
    "try{lh=(left.getInnerHeight&&left.getInnerHeight())||(left.getSize&&left.getSize().height)||0;}catch(e){}"
    "var dh=0;"
    "try{if(details&&details.isVisible&&details.isVisible())dh=(details.getSize&&details.getSize().height)||0;}catch(e){}"
    "var th=Math.max(160,lh-dh-10);"
    "try{if(tree.setHeight)tree.setHeight(th);}catch(e){}"
    "}"
    "}catch(e){}"
    # Sencha Touch (/nas-files/st/) — resize Stage once per size change only.
    "try{"
    "var stage=(Ext.getCmp&&Ext.getCmp('maindataview'))||(Ext.app&&Ext.app.Stage)||null;"
    "if(stage){"
    "try{if(stage.setSize)stage.setSize(w,h);"
    "else{if(stage.setWidth)stage.setWidth(w);if(stage.setHeight)stage.setHeight(h);}}catch(e){}"
    "try{if(stage.doComponentLayout)stage.doComponentLayout();else if(stage.doLayout)stage.doLayout();}catch(e){}"
    "}"
    "}catch(e){}"
    "try{if(narrow&&typeof window.smPaintScrollPorts==='function')window.smPaintScrollPorts();}catch(e){}"
    "}"
    "var nodes=document.querySelectorAll('.x-viewport');"
    "for(var i=0;i<nodes.length;i++){"
    "nodes[i].style.position='absolute';"
    "nodes[i].style.left='0';"
    "nodes[i].style.top='0';"
    "nodes[i].style.right='0';"
    "nodes[i].style.bottom='0';"
    "nodes[i].style.width=w+'px';"
    "nodes[i].style.height=h+'px';"
    "}"
    "}catch(e){try{console.error('smNasFit',e);}catch(e2){}}}"
    
    "try{window.smNasFit=smNasFit;window.smClearStuckMask=smClearStuckMask;window.smHideOrphanDialogs=smHideOrphanDialogs;window.smRestoreDialogs=smRestoreDialogs;window.smRefreshFileIconView=smRefreshFileIconView;window.smNasDataViewRoot=smNasDataViewRoot;window.smFixIconGridLabels=smFixIconGridLabels;window.smScheduleFixIconGrid=smScheduleFixIconGrid;window.smWatchIconGrid=smWatchIconGrid;}catch(e){}"
    "function smMobileScrollFix(){"
    "if(window.__smMobileScrollFix)return;"
    "window.__smMobileScrollFix=true;"
    "function smNarrow(){return (Math.max(document.documentElement.clientWidth||0,window.innerWidth||0)<=900);}"
    "function smScrollCandidates(){"
    "return document.querySelectorAll('#main-panel .x-panel-body,.icon-panel .x-panel-body,#main-panel .x-grid3-scroller,.x-grid3-scroller,.x-grid3-body');"
    "}"
    "function smPickScroller(from){"
    "var n=from;"
    "while(n&&n!==document.body&&n!==document.documentElement){"
    "try{"
    "if(n.scrollHeight>n.clientHeight+4){"
    "var oy='';try{oy=window.getComputedStyle(n).overflowY||'';}catch(e){}"
    "var cls=String(n.className||'');"
    "if(oy==='auto'||oy==='scroll'||oy==='overlay'||cls.indexOf('x-panel-body')>=0||cls.indexOf('x-grid3-scroller')>=0||cls.indexOf('x-grid3-body')>=0)return n;"
    "}"
    "}catch(e){}"
    "n=n.parentElement;"
    "}"
    "var list=smScrollCandidates();var best=null;var bestExtra=0;"
    "for(var i=0;i<list.length;i++){"
    "var el=list[i];var extra=(el.scrollHeight||0)-(el.clientHeight||0);"
    "if(extra>bestExtra){bestExtra=extra;best=el;}"
    "}"
    "return best;"
    "}"
    "function smKillExtDrag(){"
    "try{"
    "if(!window.Ext||!Ext.ComponentMgr||!Ext.ComponentMgr.all||!Ext.ComponentMgr.all.each)return;"
    "Ext.ComponentMgr.all.each(function(c){"
    "try{"
    "if(!c)return;"
    "if(c.dragZone){try{if(c.dragZone.lock)c.dragZone.lock();}catch(e){}try{if(c.dragZone.destroy)c.dragZone.destroy();}catch(e){}c.dragZone=null;}"
    "if(c.dd){try{if(c.dd.unreg)c.dd.unreg();}catch(e){}c.dd=null;}"
    "if(c.view&&c.view.dragZone){try{if(c.view.dragZone.lock)c.view.dragZone.lock();}catch(e){}try{if(c.view.dragZone.destroy)c.view.dragZone.destroy();}catch(e){}c.view.dragZone=null;}"
    "if(typeof c.enableDragDrop!=='undefined')c.enableDragDrop=false;"
    "if(typeof c.dragConfig!=='undefined')c.dragConfig=false;"
    "}catch(e){}"
    "});"
    "}catch(e){}"
    "}"
    "function smPaintScrollPorts(){"
    "if(!smNarrow())return;"
    "smKillExtDrag();"
    "var list=smScrollCandidates();"
    "for(var i=0;i<list.length;i++){"
    "var el=list[i];"
    "try{"
    "el.style.setProperty('overflow-y','auto','important');"
    "el.style.setProperty('overflow-x','hidden','important');"
    "el.style.setProperty('touch-action','pan-y','important');"
    "el.style.setProperty('-webkit-overflow-scrolling','touch','important');"
    "el.style.setProperty('overscroll-behavior','none','important');el.style.setProperty('overscroll-behavior-y','none','important');"
    "}catch(e){}"
    "}"
    "try{"
    "var main=Ext.getCmp&&Ext.getCmp('main-panel');"
    "if(main&&main.body&&main.body.dom){"
    "var mh=0;"
    "try{mh=(main.getInnerHeight&&main.getInnerHeight())||0;}catch(e){}"
    "if(mh>120){"
    "main.body.dom.style.setProperty('height',mh+'px','important');"
    "main.body.dom.style.setProperty('max-height',mh+'px','important');"
    "}"
    "}"
    "}catch(e){}"
    "}"
    "try{window.smPaintScrollPorts=smPaintScrollPorts;}catch(e){}"
    "try{"
    "document.documentElement.style.setProperty('overscroll-behavior','none','important');"
    "document.documentElement.style.setProperty('overscroll-behavior-y','none','important');"
    "if(document.body){"
    "document.body.style.setProperty('overscroll-behavior','none','important');"
    "document.body.style.setProperty('overscroll-behavior-y','none','important');"
    "}"
    "}catch(e){}"
    "var _sx=0,_sy=0,_sc=null,_track=false,_moved=false,_vert=false;"
    "function smBestScroller(){"
    "var list=smScrollCandidates();var best=null;var bestExtra=-1;"
    "for(var i=0;i<list.length;i++){"
    "var el=list[i];if(!el)continue;"
    "var extra=(el.scrollHeight||0)-(el.clientHeight||0);"
    "if(extra>bestExtra){bestExtra=extra;best=el;}"
    "}"
    "if(best)return best;"
    "try{if(window.Ext&&Ext.getCmp){var m=Ext.getCmp('main-panel');if(m&&m.body&&m.body.dom)return m.body.dom;}}catch(e){}"
    "return document.querySelector('#main-panel .x-panel-body')"
    "||document.querySelector('.icon-panel .x-panel-body')"
    "||document.querySelector('#main-panel .x-grid3-scroller')"
    "||document.querySelector('.x-grid3-scroller');"
    "}"
    "function smClampScroll(el,top){"
    "if(!el)return 0;"
    "var max=Math.max(0,(el.scrollHeight||0)-(el.clientHeight||0));"
    "if(top<0)top=0;if(top>max)top=max;"
    "el.scrollTop=top;return top;"
    "}"
    "document.addEventListener('touchstart',function(ev){"
    "if(!smNarrow()||!ev.touches||ev.touches.length!==1)return;"
    "smPaintScrollPorts();"
    "_sc=smPickScroller(ev.target)||smBestScroller();"
    "_sx=ev.touches[0].clientX;_sy=ev.touches[0].clientY;"
    "_track=true;_moved=false;_vert=false;"
    "},{capture:true,passive:true});"
    "document.addEventListener('touchmove',function(ev){"
    "if(!_track||!ev.touches||ev.touches.length!==1)return;"
    "var x=ev.touches[0].clientX,y=ev.touches[0].clientY;"
    "var dx=x-_sx,dy=y-_sy;"
    "if(!_moved){"
    "if(Math.abs(dy)<4&&Math.abs(dx)<4)return;"
    "_moved=true;"
    "if(Math.abs(dy)<=Math.abs(dx)){_track=false;_vert=false;return;}"
    "_vert=true;smKillExtDrag();"
    "}"
    "if(!_vert)return;"
    "if(!_sc||!_sc.isConnected)_sc=smPickScroller(ev.target)||smBestScroller();"
    "if(!_sc)return;"
    "smClampScroll(_sc,_sc.scrollTop-dy);"
    "_sx=x;_sy=y;"
    "try{ev.stopPropagation();}catch(e){}"
    "try{ev.preventDefault();}catch(e){}"
    "},{capture:true,passive:false});"
    "document.addEventListener('touchend',function(){_track=false;_sc=null;_vert=false;},{capture:true,passive:true});"
    "document.addEventListener('touchcancel',function(){_track=false;_sc=null;_vert=false;},{capture:true,passive:true});"
    "document.addEventListener('wheel',function(ev){"
    "if(!smNarrow())return;"
    "var s=smPickScroller(ev.target);if(!s)return;"
    "s.scrollTop=s.scrollTop+ev.deltaY;"
    "try{ev.preventDefault();}catch(e){}"
    "try{ev.stopPropagation();}catch(e){}"
    "},{capture:true,passive:false});"
    "document.addEventListener('mousedown',function(ev){"
    "if(!smNarrow())return;"
    "smKillExtDrag();"
    "},{capture:true,passive:true});"
    "setTimeout(smPaintScrollPorts,400);"
    "setTimeout(smPaintScrollPorts,1200);"
    "setTimeout(smPaintScrollPorts,3000);"
    "setInterval(smPaintScrollPorts,2000);"
    "}"
    "try{smMobileScrollFix();}catch(e){}"
    "try{smWatchIconGrid();}catch(e){}"
    "try{"
    "function smNasFitDebounced(){"
    "try{"
    "if(window.__smFitDebounce)clearTimeout(window.__smFitDebounce);"
    "window.__smFitDebounce=setTimeout(function(){window.__smFitDebounce=null;smNasFit(true);},120);"
    "}catch(e){try{smNasFit(true);}catch(e2){}}"
    "}"
    "window.addEventListener('resize',smNasFitDebounced,false);"
    "window.addEventListener('orientationchange',function(){setTimeout(smNasFitDebounced,50);},false);"
    "if(window.visualViewport){"
    "visualViewport.addEventListener('resize',smNasFitDebounced,false);}"
    "var _smFitN=0;"
    "var _smFitT=setInterval(function(){"
    "smPatchExtDom();smNasFit(false);"
    "if(++_smFitN>=12)clearInterval(_smFitT);"
    "},700);"
    "if(document.readyState==='complete')setTimeout(function(){smNasFit(true);},0);"
    "else window.addEventListener('load',function(){"
    "setTimeout(function(){smNasFit(true);},0);"
    "setTimeout(function(){smNasFit(true);},500);"
    "setTimeout(function(){smNasFit(true);smClearStuckMask();},1500);"
    "},false);"
    "var _smExtWait=setInterval(function(){"
    "if(window.Ext&&(Ext.onReady||Ext.app)){"
    "clearInterval(_smExtWait);"
    "try{if(Ext.onReady){Ext.onReady(function(){"
    "setTimeout(function(){smMoveAuthToTop();smNasFit(true);},0);"
    "setTimeout(function(){smMoveAuthToTop();smNasFit(true);smClearStuckMask();},500);"
    "setTimeout(function(){smMoveAuthToTop();smMergeNaviBar();smHideIconBar();smKickFilesLoad();smWatchIconGrid();smHookWinLocation();},1200);"
    "setTimeout(function(){smWatchIconGrid();smFixIconGridLabels();smHookWinLocation();},2000);"
    "setTimeout(smClearStuckMask,2000);"
    "});}else{"
    "setTimeout(function(){smMoveAuthToTop();smNasFit(true);smClearStuckMask();},800);"
    "}"
    "}catch(e){}"
    "}"
    "},100);"
    "}catch(e){}"
    "function fix(u){if(typeof u!=='string')return u;"
    "if(!u||u.charAt(0)==='#'||u.indexOf('data:')===0||u.indexOf('blob:')===0||u.indexOf('javascript:')===0)return u;"
    "if(u.indexOf(P+'/')===0||u===P)return u;"
    "if(u.indexOf('http://192.168.8.159:9000')===0)return P+u.slice(26);"
    "if(u.indexOf('https://192.168.8.159:9000')===0)return P+u.slice(27);"
    "if(u.indexOf('https://files.vpstruelord.com')===0)return P+u.slice(30);"
    "if(u.indexOf('http://files.vpstruelord.com')===0)return P+u.slice(29);"
    "if(u.charAt(0)==='/'&&u.charAt(1)!=='/')return P+u;"
    "return u;}"
    "function mediaKind(u){"
    "var path=String(u||'').split('?')[0].split('#')[0];"
    "var name='';"
    "try{name=decodeURIComponent((path.split('/').pop()||''));}catch(e){name=(path.split('/').pop()||'');}"
    "var ext=(name.split('.').pop()||'').toLowerCase();"
    "if(/^(mp4|webm|mov|m4v|ogv|ogg)$/.test(ext))return 'video';"
    "if(/^(mp3|m4a|aac|wav|flac|oga|opus)$/.test(ext))return 'audio';"
    "if(/^(jpe?g|png|gif|webp|bmp|svg)$/.test(ext))return 'image';"
    "if(ext==='pdf')return 'pdf';"
    "return 'other';}"
    "function ensureViewer(){"
    "var v=document.getElementById('sm-nas-viewer');"
    "if(v)return v;"
    "v=document.createElement('div');"
    "v.id='sm-nas-viewer';"
    "v.setAttribute('role','dialog');"
    "v.setAttribute('aria-modal','true');"
    "v.style.cssText='display:none;position:fixed;inset:0;z-index:2147483646;background:rgba(10,15,13,0.96);color:#e8f2ec;font:600 14px Sora,system-ui,sans-serif';"
    "var bar=document.createElement('div');"
    "bar.style.cssText='display:flex;align-items:center;gap:10px;padding:10px 12px;box-sizing:border-box;background:#111916;border-bottom:1px solid rgba(170,210,185,.14)';"
    "var closeBtn=document.createElement('button');"
    "closeBtn.type='button';"
    "closeBtn.id='sm-nas-viewer-close';"
    "closeBtn.setAttribute('aria-label','Close');"
    "closeBtn.textContent='\\u2715';"
    "closeBtn.style.cssText='flex:0 0 auto;min-width:44px;min-height:44px;border:0;border-radius:10px;background:#1e2b25;color:#e8f2ec;font:700 18px Sora,system-ui,sans-serif';"
    "var title=document.createElement('div');"
    "title.id='sm-nas-viewer-title';"
    "title.style.cssText='flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:600';"
    "var dl=document.createElement('a');"
    "dl.id='sm-nas-viewer-dl';"
    "dl.href='#';"
    "dl.textContent='Download';"
    "dl.style.cssText='flex:0 0 auto;min-height:44px;padding:0 14px;display:inline-flex;align-items:center;border-radius:10px;background:#3ddea0;color:#062016;text-decoration:none;font-weight:700';"
    "bar.appendChild(closeBtn);bar.appendChild(title);bar.appendChild(dl);"
    "var body=document.createElement('div');"
    "body.id='sm-nas-viewer-body';"
    "body.style.cssText='position:absolute;left:0;right:0;bottom:0;top:56px;display:flex;align-items:center;justify-content:center;padding:8px;box-sizing:border-box;overflow:auto';"
    "v.appendChild(bar);v.appendChild(body);"
    "(document.body||document.documentElement).appendChild(v);"
    "closeBtn.addEventListener('click',function(ev){ev.preventDefault();closeViewer();});"
    "document.addEventListener('keydown',function(ev){"
    "if(ev.key==='Escape'&&v.style.display==='block')closeViewer();});"
    "return v;}"
    "function closeViewer(){"
    "var v=document.getElementById('sm-nas-viewer');"
    "if(!v)return;"
    "var body=v.querySelector('#sm-nas-viewer-body');"
    "if(body)body.innerHTML='';"
    "v.style.display='none';"
    "try{document.documentElement.style.overflow='';}catch(e){}}"
    "function openInApp(u){"
    "try{"
    "u=fix(String(u||''));"
    "var kind=mediaKind(u);"
    "var path=u.split('?')[0].split('#')[0];"
    "var name='File';"
    "try{name=decodeURIComponent((path.split('/').pop()||'File'))||'File';}catch(e){name=(path.split('/').pop()||'File');}"
    "var dl=u;"
    "if(u.indexOf(P+'/rpc/cat')===0)dl=P+'/rpc/download'+u.slice((P+'/rpc/cat').length);"
    "if(kind==='other'){"
    "var a=document.createElement('a');"
    "a.href=dl;"
    "a.setAttribute('download',name);"
    "a.rel='noopener';"
    "(document.body||document.documentElement).appendChild(a);"
    "a.click();"
    "a.remove();"
    "return null;}"
    "var v=ensureViewer();"
    "v.querySelector('#sm-nas-viewer-title').textContent=name;"
    "var dla=v.querySelector('#sm-nas-viewer-dl');"
    "dla.href=dl;"
    "dla.setAttribute('download',name);"
    "var body=v.querySelector('#sm-nas-viewer-body');"
    "body.innerHTML='';"
    "if(kind==='video'){"
    "var el=document.createElement('video');"
    "el.controls=true;"
    "el.setAttribute('playsinline','');"
    "el.setAttribute('webkit-playsinline','');"
    "el.preload='metadata';"
    "el.src=u;"
    "el.style.cssText='width:100%;height:100%;max-height:100%;background:#000;object-fit:contain';"
    "body.appendChild(el);"
    "try{el.play().catch(function(){});}catch(e){}"
    "}else if(kind==='audio'){"
    "var ae=document.createElement('audio');"
    "ae.controls=true;ae.preload='metadata';ae.src=u;"
    "ae.style.cssText='width:min(100%,480px)';"
    "body.appendChild(ae);"
    "}else if(kind==='image'){"
    "var img=document.createElement('img');"
    "img.alt=name;img.src=u;"
    "img.style.cssText='max-width:100%;max-height:100%;object-fit:contain';"
    "body.appendChild(img);"
    "}else if(kind==='pdf'){"
    "var fr=document.createElement('iframe');"
    "fr.title=name;fr.src=u;"
    "fr.style.cssText='width:100%;height:100%;border:0;background:#fff';"
    "body.appendChild(fr);"
    "}"
    "v.style.display='block';"
    "try{document.documentElement.style.overflow='hidden';}catch(e){}"
    "}catch(e){try{console.error('sm-nas-viewer',e);}catch(e2){}}"
    "return null;}"
    "function openFixed(u,n){"
    "u=fix(String(u||''));"
    "if(u.indexOf(P+'/rpc/cat')===0||u.indexOf(P+'/rpc/download')===0)"
    "return openInApp(u);"
    "var a=document.createElement('a');"
    "a.href=u;"
    "a.target=(n&&n!=='_self')?n:'_blank';"
    "a.rel='noopener noreferrer';"
    "(document.body||document.documentElement).appendChild(a);"
    "a.click();"
    "a.remove();"
    "return null;}"
    # Patch window.open FIRST so later setup failures cannot leave native open intact.
    "try{"
    "var _open=window.open;"
    "window.open=function(u,n,f){"
    "try{"
    "if(typeof u==='string'){"
    "var fixed=fix(u);"
    "if(fixed.indexOf(P+'/rpc/cat')===0||fixed.indexOf(P+'/rpc/download')===0)"
    "return openInApp(fixed);"
    "u=fixed;"
    "}"
    "}catch(e){try{console.error('sm-nas-open',e);}catch(e2){}}"
    "return _open.call(window,u,n,f);};"
    "}catch(e){}"
    "try{document.addEventListener('click',function(ev){"
    "var t=ev.target;"
    "while(t&&t.tagName!=='A')t=t.parentElement;"
    "if(!t)return;"
    "var href='';"
    "try{href=t.getAttribute('href')||t.href||'';}catch(e){return;}"
    "href=fix(String(href));"
    "if(href.indexOf(P+'/rpc/cat')!==0&&href.indexOf(P+'/rpc/download')!==0)return;"
    "ev.preventDefault();"
    "ev.stopPropagation();"
    "openInApp(href);"
    "},true);}catch(e){}"
    "var xo=XMLHttpRequest.prototype.open;"
    "XMLHttpRequest.prototype.open=function(m,u){try{arguments[1]=fix(u);}catch(e){}"
    "return xo.apply(this,arguments);};"
    "if(window.fetch){var _f=window.fetch;window.fetch=function(i,n){"
    "try{if(typeof i==='string')i=fix(i);else if(i&&i.url)i=new Request(fix(i.url),i);}catch(e){}"
    "return _f.call(this,i,n);};}"
    "var _ps=history.pushState.bind(history), _rs=history.replaceState.bind(history);"
    "history.pushState=function(s,t,u){try{if(typeof u==='string')u=fix(u);}catch(e){} return _ps(s,t,u);};"
    "history.replaceState=function(s,t,u){try{if(typeof u==='string')u=fix(u);}catch(e){} return _rs(s,t,u);};"
    "try{"
    "var _assign=window.location.assign.bind(window.location);"
    "window.location.assign=function(u){return _assign(fix(String(u)));};"
    "var _replace=window.location.replace.bind(window.location);"
    "window.location.replace=function(u){return _replace(fix(String(u)));};"
    "}catch(e){}"
    # Icons use absolute /ui/images/... from base_config; patch element src/href.
    "try{"
    "var _sa=Element.prototype.setAttribute;"
    "Element.prototype.setAttribute=function(n,v){"
    "if((n==='src'||n==='href')&&typeof v==='string')v=fix(v);"
    "return _sa.call(this,n,v);};"
    "}catch(e){}"
    "try{"
    "var idesc=Object.getOwnPropertyDescriptor(HTMLImageElement.prototype,'src');"
    "if(idesc&&idesc.set){Object.defineProperty(HTMLImageElement.prototype,'src',{"
    "configurable:true,enumerable:true,"
    "get:function(){return idesc.get.call(this);},"
    "set:function(v){idesc.set.call(this,fix(String(v)));}});}"
    "}catch(e){}"
    "try{"
    "var _submit=HTMLFormElement.prototype.submit;"
    "HTMLFormElement.prototype.submit=function(){"
    "try{if(this.action)this.setAttribute('action',fix(String(this.action)));}catch(e){}"
    "return _submit.apply(this,arguments);};"
    "var desc=Object.getOwnPropertyDescriptor(HTMLFormElement.prototype,'action')||"
    "Object.getOwnPropertyDescriptor(HTMLButtonElement.prototype,'formAction');"
    "if(desc&&desc.set){Object.defineProperty(HTMLFormElement.prototype,'action',{"
    "configurable:true,enumerable:true,"
    "get:function(){return desc.get.call(this);},"
    "set:function(v){desc.set.call(this,fix(String(v)));}});}"
    "}catch(e){}"
    "window.addEventListener('message',function(ev){"
    "var d=ev&&ev.data;if(!d)return;"
    "if(d.type==='sm-nas-files-upload-start'){"
    "try{if(window.Ext&&Ext.app&&Ext.app.Util&&Ext.app.Util.setMask)Ext.app.Util.setMask();}catch(e){}"
    "return;}"
    "if(d.type!=='sm-nas-files-upload-done')return;"
    "try{"
    "if(window.Ext&&Ext.app&&Ext.app.Util&&Ext.app.Util.hideMask)Ext.app.Util.hideMask();"
    "var el=window.__smUploadActionsEl;"
    "try{if(el&&el.actions)el.actions.hide();}catch(e){}"
    "window.__smUploadActionsEl=null;"
    "var response=d.response;"
    "if((!response||typeof response!=='object')&&d.raw&&window.Ext&&Ext.app&&Ext.app.Util&&Ext.app.Util._smParseRpc){"
    "response=Ext.app.Util._smParseRpc(d.raw);"
    "}"
    "var ok=d.success;"
    "if(!ok&&response&&(response.success===true||response.success==='true'||response.success===1))ok=true;"
    "if(window.Ext&&Ext.app&&Ext.app.Util&&Ext.app.Util._smUploadFinish){"
    "Ext.app.Util._smUploadFinish(response,d.raw,ok);"
    "}else if(ok){"
    "try{if(Ext.app.isPanel&&Ext.app.isPanel.getComponent('data_view'))Ext.app.isPanel.getComponent('data_view').setData();}catch(e){}"
    "Ext.app.alert('Done','Upload complete');"
    "}else{"
    "Ext.app.alert('Error',(response&&response.msg)?String(response.msg):(d.raw||d.error||'upload failed'));"
    "}"
    "}catch(e){}"
    "},false);"
    "})();</script>"
)


def _nas_files_rewrite_location(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return raw
    if raw.startswith(NAS_FILES_PREFIX + "/") or raw == NAS_FILES_PREFIX:
        return raw
    lower = raw.lower()
    for prefix in (
        NAS_FILES_UPSTREAM,
        "http://192.168.8.159:9000",
        "https://192.168.8.159:9000",
        "https://files.vpstruelord.com",
        "http://files.vpstruelord.com",
    ):
        if lower.startswith(prefix.lower()):
            rest = raw[len(prefix) :]
            if not rest.startswith("/"):
                rest = "/" + rest
            return NAS_FILES_PREFIX + rest
    if raw.startswith("/"):
        return NAS_FILES_PREFIX + raw
    return raw


def _nas_files_rewrite_set_cookie(value: str) -> str:
    """Normalize upstream Set-Cookie to the same Path=/; Secure shape as SSO."""
    parts = [p.strip() for p in value.split(";") if p.strip()]
    if not parts:
        return value
    name = parts[0].split("=", 1)[0].strip().lower()
    if name == "webaxs_session":
        raw_val = parts[0].split("=", 1)[1].strip() if "=" in parts[0] else ""
        # Expiry / empty value → clear all variants.
        low_join = ";".join(parts).lower()
        if (not raw_val) or "max-age=0" in low_join or "expires=" in low_join:
            # Caller may send multiple; return one clear and rely on SSO clears.
            return "webaxs_session=; Path=/; SameSite=Lax; Secure; Max-Age=0"
        return _webaxs_cookie_header(raw_val)

    out = [parts[0]]
    saw_path = False
    saw_secure = False
    saw_samesite = False
    for part in parts[1:]:
        low = part.lower()
        if low.startswith("path="):
            out.append(f"Path={NAS_FILES_PREFIX}/")
            saw_path = True
        elif low.startswith("domain="):
            continue
        elif low == "secure":
            saw_secure = True
            out.append(part)
        elif low.startswith("samesite="):
            saw_samesite = True
            out.append(part)
        else:
            out.append(part)
    if not saw_path:
        out.append(f"Path={NAS_FILES_PREFIX}/")
    if not saw_samesite:
        out.append("SameSite=Lax")
    if not saw_secure:
        out.append("Secure")
    return "; ".join(out)


def _nas_files_rewrite_html_paths(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        attr, quote, path = match.group(1), match.group(2), match.group(3)
        if path.startswith(NAS_FILES_PREFIX + "/") or path == NAS_FILES_PREFIX:
            return match.group(0)
        return f"{attr}={quote}{NAS_FILES_PREFIX}{path}{quote}"

    text = re.sub(
        r"\b(href|src|action)=(['\"])(/(?!/|nas-files/)[^'\"]*)\2",
        repl,
        text,
        flags=re.I,
    )
    # Root redirect page uses location = "/ui/" ... — keep it under the proxy.
    text = re.sub(
        r"""((?:window\.)?location(?:\.href)?\s*=\s*['"])(/(?!/|nas-files/)[^'"]*)""",
        lambda m: f"{m.group(1)}{NAS_FILES_PREFIX}{m.group(2)}",
        text,
        flags=re.I,
    )
    return text


def _nas_files_patch_css(text: str) -> str:
    """Disable Buffalo float tile layout in mainPanel.css (breaks portal flex grid)."""
    if ".icon-panel .icon-thumbnail" not in text:
        return text
    text = text.replace(
        ".icon-panel .icon-thumbnail {\n    float: left;",
        ".icon-panel .icon-thumbnail {\n    float: none;",
    )
    text = text.replace(
        ".icon-panel .icon-thumbnail {\n    float: none;\n    margin: 15px;\n"
        "    margin-right: 0;\n    margin-bottom: 0;\n    padding: 5px;",
        ".icon-panel .icon-thumbnail {\n    float: none;\n    margin: 0;\n    padding: 0;",
    )
    text = text.replace(
        ".icon-panel .icon-info {\n    display: block;\n    padding-top: 20px;\n"
        "    text-align: left;\n    float: right;\n    width: 100px;",
        ".icon-panel .icon-info {\n    display: block;\n    padding-top: 0;\n"
        "    text-align: left;\n    float: none;\n    width: auto;",
    )
    text = text.replace(
        ".icon-panel .icon-side img {\n    float: left;",
        ".icon-panel .icon-side img {\n    float: none;",
    )
    return text


def _nas_files_hook_dataview(text: str) -> str:
    """Wrap Buffalo DataView refresh to re-apply portal tile layout."""
    # Use .replace (not %) — hook JS contains literal '100%' widths.
    hook = (
        "(function(_smDv){if(!_smDv||_smDv.__smGridHook)return;"
        "_smDv.__smGridHook=1;var _smRf=_smDv.refresh;"
        "_smDv.refresh=function(){var _smOut=_smRf.apply(this,arguments);"
        "try{if(_smDv.el&&_smDv.el.dom){"
        "_smDv.el.dom.style.setProperty('width','100%','important');"
        "_smDv.el.dom.style.setProperty('max-width','100%','important');"
        "}"
        "if(window.smScheduleFixIconGrid)window.smScheduleFixIconGrid();"
        "else if(window.smFixIconGridLabels)window.smFixIconGridLabels();}catch(e){}"
        "return _smOut;};})(__SM_DV__);"
    )
    replacements = (
        "var dataView_small = makeDataView(makeTemplate(tpl_small), ICON_SMALL_TEXT_WIDTH, ICON_SMALL_WIDTH, ICON_SMALL_HEIGHT);",
        "var dataView_medium = makeDataView(makeTemplate(tpl_medium), ICON_MEDIUM_TEXT_WIDTH, ICON_MEDIUM_WIDTH, ICON_MEDIUM_HEIGHT);",
        "var dataView_large = makeDataView(makeTemplate(tpl_large), ICON_LARGE_TEXT_WIDTH, ICON_LARGE_WIDTH, ICON_LARGE_HEIGHT);",
        "var dataView_side = makeDataView(makeTemplate(tpl_side), SIDEBYSIDE_INFO_WIDTH, SIDEBYSIDE_WIDTH, SIDEBYSIDE_HEIGHT);",
    )
    for line in replacements:
        var = line.split("=", 1)[0].strip().replace("var ", "").strip()
        hook_js = hook.replace("__SM_DV__", var, 1)
        patched = line + "\n    " + hook_js
        if hook_js not in text:
            text = text.replace(line, patched, 1)
    return text


def _nas_files_rewrite_js_paths(text: str) -> str:
    """Rewrite hardcoded absolute WebAccess paths inside JS sources."""
    # Avoid double-prefixing if already rewritten.
    def repl(match: re.Match[str]) -> str:
        quote, path = match.group(1), match.group(2)
        if path.startswith(NAS_FILES_PREFIX + "/") or path == NAS_FILES_PREFIX:
            return match.group(0)
        return f"{quote}{NAS_FILES_PREFIX}{path}"

    text = re.sub(
        r"""(['"])(/(?:rpc|ui|st|webaxs)(?:/[^'"]*)?)""",
        repl,
        text,
    )
    # Session-timeout handler must clear the Secure cookie SSO sets, otherwise
    # reload keeps the dead session and the UI loops on "Session timeout".
    text = text.replace(
        'document.cookie = "webaxs_session=a; path=/; expires=" + (new Date(0)).toGMTString() + ";";',
        'document.cookie = "webaxs_session=; path=/; Max-Age=0; SameSite=Lax; Secure";'
        'document.cookie = "webaxs_session=; path=/; Max-Age=0; SameSite=Lax";'
        'document.cookie = "webaxs_session=; path=/nas-files/; Max-Age=0; SameSite=Lax; Secure";'
        'document.cookie = "webaxs_session=; path=/nas-files/; Max-Age=0; SameSite=Lax";'
        "try{if(window.top&&window.top!==window){window.top.postMessage({type:'sm-nas-files-reauth'},'*');}}catch(e){}",
    )
    # Only the session-error OK handler should reauth via parent (avoid reload loops).
    text = text.replace(
        "function showErrorMessage(message) {\n"
        "    myAlert(maketextHandle.maketext('error'),\n"
        "\t    message,\n"
        "\t    function() {\n"
        "\t\twindow.location.reload(true);\n"
        "\t    });\n"
        "\n"
        "}",
        "function showErrorMessage(message) {\n"
        "    myAlert(maketextHandle.maketext('error'),\n"
        "\t    message,\n"
        "\t    function() {\n"
        "\t\ttry{if(window.top&&window.top!==window){window.top.postMessage({type:'sm-nas-files-reauth'},'*');return;}}catch(e){}\n"
        "\t\twindow.location.reload(true);\n"
        "\t    });\n"
        "\n"
        "}",
    )
    # HTTP/2 and some reverse proxies leave statusText empty on 200; WebAccess
    # treats that as failure and shows the JSON body in an error dialog.
    text = text.replace(
        "response.status != 200 || response.statusText != \"OK\"",
        "response.status != 200 || (response.statusText && response.statusText != \"OK\")",
    )
    text = text.replace(
        "_response.status != 200 || _response.statusText != \"OK\"",
        "_response.status != 200 || (_response.statusText && _response.statusText != \"OK\")",
    )
    text = _nas_files_patch_removed_toolbar_buttons(text)
    text = _nas_files_hook_dataview(text)
    # Keep Ext location bar in sync, and paint Windows-style breadcrumb overlay.
    text = re.sub(
        r"    locations\.doLayout\(\);\r?\n\}\r?\n\r?\nfunction update_location_bar_search",
        "    try { locations.doLayout(); } catch (_smDl) {}\r\n"
        "    try {\r\n"
        "        var _smTf = Ext.getCmp('location-textfield');\r\n"
        "        if (_smTf) { _smTf.setValue(path || '/'); }\r\n"
        "        try { document.documentElement.classList.add('sm-win-nav'); } catch(e) {}\r\n"
        "        if (typeof smEnsureWinAddress === 'function') smEnsureWinAddress(path || '/');\r\n"
        "        else if (typeof smRenderWinAddress === 'function') smRenderWinAddress(path || '/');\r\n"
        "    } catch(e) {}\r\n"
        "}\r\n\r\nfunction update_location_bar_search",
        text,
        count=1,
    )
    text = re.sub(
        r"function update_location_bar_search\(path, words\) \{[\s\S]*?\r?\n\}\r?\n\r?\n/\*\*\*\*\*\*\* search box",
        "function update_location_bar_search(path, words) {\r\n"
        "    update_location_bar(path);\r\n"
        "    try {\r\n"
        "        if (typeof smRenderWinAddress === 'function') smRenderWinAddress(path || '/');\r\n"
        "        var _smTf = Ext.getCmp('location-textfield');\r\n"
        "        if (_smTf) { _smTf.setValue((path || '/') + ' : \"' + words + '\"'); }\r\n"
        "    } catch(e) {}\r\n"
        "}\r\n\r\n/******* search box",
        text,
        count=1,
    )
    # Guard file-pane update when mainPanel view is mid-layout rebuild.
    text = text.replace(
        "\t\tmainPanel.getComponent(0).updateView(node,",
        "\t\ttry { update_location_bar(node.path); } catch(e) {}\n\t\tvar _smMainView=mainPanel.getComponent(0);if(_smMainView&&_smMainView.updateView)_smMainView.updateView(node,",
    )
    text = re.sub(
        r"addHistory\(node\);\s+mainPanel\.getComponent\(0\)\.updateView\(node,",
        "addHistory(node);\n\t\ttry { update_location_bar(node.path); } catch(e) {}\n\t\tvar _smMainView=mainPanel.getComponent(0);if(_smMainView&&_smMainView.updateView)_smMainView.updateView(node,",
        text,
        count=1,
    )
    # Ensure loading spinner clears on rpc_ls failure.
    text = text.replace(
        "\t   },\n"
        "\t   error_on_rpc_ls\n"
        "\t  );",
        "\t   },\n"
        "\t   function(response, request) {\n"
        "\t       try { loadingAnimation.hideAll(); } catch(e) {}\n"
        "\t       error_on_rpc_ls(response, request);\n"
        "\t   }\n"
        "\t  );",
        1,
    )
    # After toolbar chrome merges, mainPanel.afterlayout may never fire so the
    # "Displaying..." spinner (loadingAnimation) stays up; add a callback fallback.
    text = text.replace(
        "function changeMainView(mode, callback) {\n"
        "\n"
        "    mainPanel.removeAll(true);\n"
        "    mainPanel.purgeListeners();\n"
        "    mainPanel.addListener('afterlayout',\n"
        "\t\t\t  function(_this) {\n"
        "\t\t\t      if (callback) {\n"
        "\t\t\t\t  callback();\n"
        "\t\t\t      }\n"
        "\t\t\t  },\n"
        "\t\t\t  this,\n"
        "\t\t\t  {\n"
        "\t\t\t      single : true\n"
        "\t\t\t  }\n"
        "\t\t\t );",
        "function changeMainView(mode, callback) {\n"
        "\n"
        "    mainPanel.removeAll(true);\n"
        "    mainPanel.purgeListeners();\n"
        "    var _smMainViewCbDone = false;\n"
        "    function _smMainViewFinish() {\n"
        "\tif (_smMainViewCbDone) return;\n"
        "\t_smMainViewCbDone = true;\n"
        "\ttry {\n"
        "\t    mainPanel.doLayout(true, true);\n"
        "\t    var _smCv = mainPanel.getComponent(0);\n"
        "\t    if (_smCv && _smCv.getDataView) {\n"
        "\t\tvar _smDv = _smCv.getDataView();\n"
        "\t\tif (_smDv && _smDv.refresh) _smDv.refresh();\n"
        "\t    } else if (_smCv && _smCv.view && _smCv.view.getView) {\n"
        "\t\tvar _smGv = _smCv.view.getView();\n"
        "\t\tif (_smGv && _smGv.refresh) _smGv.refresh();\n"
        "\t    }\n"
        "\t} catch(e) {}\n"
        "\tif (callback) {\n"
        "\t    callback();\n"
        "\t}\n"
        "    }\n"
        "    mainPanel.addListener('afterlayout',\n"
        "\t\t\t  function(_this) {\n"
        "\t\t\t      _smMainViewFinish();\n"
        "\t\t\t  },\n"
        "\t\t\t  this,\n"
        "\t\t\t  {\n"
        "\t\t\t      single : true\n"
        "\t\t\t  }\n"
        "\t\t\t );\n"
        "    setTimeout(function() {\n"
        "\ttry { mainPanel.doLayout(true, true); } catch(e) {}\n"
        "\t_smMainViewFinish();\n"
        "    }, 2500);",
    )
    # Thumbnail HEAD requests — same empty statusText issue as rpc/ls.
    text = text.replace(
        "response.status == 200 && response.statusText == \"OK\"",
        "response.status == 200 && (!response.statusText || response.statusText == \"OK\")",
    )
    text = text.replace(
        "response.status == 204 && response.statusText == \"No Content\"",
        "response.status == 204 && (!response.statusText || response.statusText == \"No Content\")",
    )
    text = _nas_files_patch_st_mobile_upload(text)
    text = _nas_files_patch_st_mobile_edit(text)
    return text


def _nas_files_patch_st_mobile_edit(text: str) -> str:
    """Fix Sencha Touch mobile Edit (selection mode) on phones."""
    if "Ext.app.Base.DataViewPanel" in text:
        old_handler = (
            "\t\tthis.editBtn.handler = function()\r\n"
            "\t\t{\r\n"
            "\t\t\tExt.app.Stage.getDockedComponent('maintool').tapFileAction()\r\n"
            "\t\t}"
        )
        new_handler = (
            "\t\tthis.editBtn.handler = function()\r\n"
            "\t\t{\r\n"
            "\t\t\tif(Ext.app.Util && Ext.app.Util._smToggleEditMode){\r\n"
            "\t\t\t\tExt.app.Util._smToggleEditMode();\r\n"
            "\t\t\t}else{\r\n"
            "\t\t\t\ttry{\r\n"
            "\t\t\t\t\tvar mt=Ext.app.Stage&&Ext.app.Stage.getDockedComponent('maintool');\r\n"
            "\t\t\t\t\tif(mt&&mt.tapFileAction)mt.tapFileAction.call(mt);\r\n"
            "\t\t\t\t}catch(e){}\r\n"
            "\t\t\t}\r\n"
            "\t\t}"
        )
        if old_handler in text:
            text = text.replace(old_handler, new_handler)
    toggle_block = (
        "\t_smToggleEditMode: function()\r\n"
        "\t{\r\n"
        "\t\tvar panel = Ext.app.isPanel;\r\n"
        "\t\tif(!panel && Ext.app.Stage){panel = Ext.app.isPanel = Ext.app.Stage.getActiveItem();}\r\n"
        "\t\tif(!panel || !panel.editBtn){return;}\r\n"
        "\t\tvar dv = (panel.getComponent && (panel.getComponent('data_view') || panel.getComponent(0))) || null;\r\n"
        "\t\tvar dom = dv && dv.el && dv.el.dom;\r\n"
        "\t\tvar mt = Ext.app.Stage && Ext.app.Stage.getDockedComponent && Ext.app.Stage.getDockedComponent('maintool');\r\n"
        "\t\tif(typeof isAction !== 'undefined' && isAction === 'edit'){\r\n"
        "\t\t\tpanel.editBtn.setText(Ext.app.makeTxt('edit btn'));\r\n"
        "\t\t\tpanel.editBtn.removeCls('x-button-confirm');\r\n"
        "\t\t\tif(typeof isDir !== 'undefined' && isDir != '/' && panel.backBtn){panel.backBtn.show();}\r\n"
        "\t\t\tisAction = 'select';\r\n"
        "\t\t\tif(panel.edittool && panel.edittool.hide){panel.edittool.hide();}\r\n"
        "\t\t\tif(mt && mt.show){mt.show();}\r\n"
        "\t\t\tif(dom){\r\n"
        "\t\t\t\tExt.select('.main-wrap', dom).removeCls(['selected-wrap','selected-wrap-icon']);\r\n"
        "\t\t\t\tif(typeof isViewMode !== 'undefined' && isViewMode == 'list'){Ext.select('.arrowimg', dom).show();}\r\n"
        "\t\t\t}\r\n"
        "\t\t\tpanel.selectedItem = [];\r\n"
        "\t\t\ttry{panel.doComponentLayout();if(Ext.app.Stage&&Ext.app.Stage.doComponentLayout)Ext.app.Stage.doComponentLayout();}catch(e){}\r\n"
        "\t\t\treturn;\r\n"
        "\t\t}\r\n"
        "\t\tisAction = 'edit';\r\n"
        "\t\tif(dom && typeof isViewMode !== 'undefined' && isViewMode == 'list'){Ext.select('.arrowimg', dom).hide();}\r\n"
        "\t\tpanel.editBtn.addCls('x-button-confirm');\r\n"
        "\t\tpanel.editBtn.setText(Ext.app.makeTxt('fin btn'));\r\n"
        "\t\tif(panel.backBtn){panel.backBtn.hide();}\r\n"
        "\t\tif(mt && mt.hide){mt.hide();}\r\n"
        "\t\tif(panel.edittool){\r\n"
        "\t\t\tpanel.edittool.noselect(true);\r\n"
        "\t\t\tpanel.edittool.show();\r\n"
        "\t\t}else{\r\n"
        "\t\t\tvar edit = new Ext.app.editMenu();\r\n"
        "\t\t\tpanel.addDocked(edit);\r\n"
        "\t\t\tpanel.edittool = edit;\r\n"
        "\t\t}\r\n"
        "\t\ttry{panel.doComponentLayout();if(Ext.app.Stage&&Ext.app.Stage.doComponentLayout)Ext.app.Stage.doComponentLayout();}catch(e){}\r\n"
        "\t},\r\n\r\n"
    )
    if "_smToggleEditMode" not in text and (
        "_smUploadFinish: function" in text or "deleteFile: function" in text
    ):
        if "_smUploadFinish: function" in text and "\tupload: function(el)" in text:
            text = text.replace(
                "\t},\r\n\r\n\tupload: function(el)",
                "\t},\r\n\r\n" + toggle_block + "\tupload: function(el)",
                1,
            )
        elif "deleteFile: function" in text:
            text = text.replace(
                "\t},\r\n\t\r\n\tdeleteFile: function(datas, el)",
                "\t},\r\n\r\n" + toggle_block + "\r\n\tdeleteFile: function(datas, el)",
                1,
            )
    # Clean delete success: exit edit mode, hide mask, no raw JSON leak / stuck OK bar.
    if "deleteFile: function" in text and "Ext.app.alert(Ext.app.makeTxt('remove result'),r.responseText);" in text:
        text = text.replace(
            "if(count == datalength){\r\n"
            "                            Ext.app.alert(Ext.app.makeTxt('remove result'),r.responseText);\r\n"
            "                            Ext.app.isPanel.getComponent('data_view').setData();\r\n"
            "                            return;\r\n"
            "                        }",
            "if(count == datalength){\r\n"
            "                            try{Ext.app.Util.hideMask();}catch(e){}\r\n"
            "                            try{if(typeof isAction!=='undefined'&&isAction==='edit'&&Ext.app.Util._smToggleEditMode){Ext.app.Util._smToggleEditMode();}}catch(e){}\r\n"
            "                            try{if(Ext.app.isPanel&&Ext.app.isPanel.getComponent('data_view'))Ext.app.isPanel.getComponent('data_view').setData();}catch(e){}\r\n"
            "                            try{if(window.smHideOrphanDialogs)smHideOrphanDialogs();if(window.Ext&&Ext.Msg&&Ext.Msg.hide)Ext.Msg.hide();}catch(e){}\r\n"
            "                            Ext.app.alert(Ext.app.makeTxt('remove result'),'Deleted');\r\n"
            "                            return;\r\n"
            "                        }",
        )
    # Ensure rename/mkdir prompts can show after prior dialog hides (clear sticky styles).
    prompt_prefix = "try{if(window.smRestoreDialogs)smRestoreDialogs();}catch(_smE){}\r\n\t\tExt.Msg.prompt("
    if "Ext.Msg.prompt(" in text and prompt_prefix not in text:
        text = text.replace("Ext.Msg.prompt(", prompt_prefix)
    if "renameFile: function" in text and "dst:(isDir+v)" in text:
        text = text.replace(
            "success: function(r){\r\n"
            "\t\t\t\t\tExt.app.isPanel.getComponent('data_view').setData();\r\n"
            "\t\t\t\t},\r\n"
            "\t\t\t\tfailure: function(r)\r\n"
            "\t\t\t\t{\r\n"
            "\t\t\t\t\tif (r.responseText != ''){\r\n"
            "\t\t\t\t\t\tExt.app.alert(Ext.app.makeTxt('error'),Ext.app.makeTxt(r.responseText));\r\n"
            "\t\t\t\t\t}else{\r\n"
            "\t\t\t\t\t\tExt.app.alert(Ext.app.makeTxt('error'),Ext.app.makeTxt('terminate a network connection'));\r\n"
            "\t\t\t\t\t}\r\n"
            "                    if(Ext.app.isPanel){\r\n"
            "                        Ext.app.isPanel.fireEvent('reselect')\r\n"
            "                    }\r\n"
            "\t\t\t\t},\r\n"
            "\t\t\t\tscope: this\r\n"
            "\t\t\t});\r\n"
            "\t\t},el,false,d.name,{",
            "success: function(r){\r\n"
            "\t\t\t\t\ttry{if(typeof isAction!=='undefined'&&isAction==='edit'&&Ext.app.Util._smToggleEditMode){Ext.app.Util._smToggleEditMode();}}catch(e){}\r\n"
            "\t\t\t\t\ttry{if(Ext.app.isPanel&&Ext.app.isPanel.getComponent('data_view'))Ext.app.isPanel.getComponent('data_view').setData();}catch(e){}\r\n"
            "\t\t\t\t},\r\n"
            "\t\t\t\tfailure: function(r)\r\n"
            "\t\t\t\t{\r\n"
            "\t\t\t\t\tif (r.responseText != ''){\r\n"
            "\t\t\t\t\t\tExt.app.alert(Ext.app.makeTxt('error'),Ext.app.makeTxt(r.responseText));\r\n"
            "\t\t\t\t\t}else{\r\n"
            "\t\t\t\t\t\tExt.app.alert(Ext.app.makeTxt('error'),Ext.app.makeTxt('terminate a network connection'));\r\n"
            "\t\t\t\t\t}\r\n"
            "                    if(Ext.app.isPanel){\r\n"
            "                        Ext.app.isPanel.fireEvent('reselect')\r\n"
            "                    }\r\n"
            "\t\t\t\t},\r\n"
            "\t\t\t\tscope: this\r\n"
            "\t\t\t});\r\n"
            "\t\t},el,false,d.name,{",
        )
    return text


def _nas_files_patch_st_mobile_upload(text: str) -> str:
    """Add Upload to the Sencha Touch (/st/) mobile action sheet."""
    if (
        "Ext.app.Base.Toolbar" not in text
        and "deleteFile: function" not in text
        and '"makedir"' not in text
    ):
        return text
    if "id: 'uploadbtn'" not in text and "id: 'mkdirbtn'" in text:
        text = text.replace(
            "\t\t\t\t\t\ttext: Ext.app.makeTxt('makedir'),\r\n"
            "\t\t\t\t\t\tid: 'mkdirbtn',\r\n"
            "\t\t\t\t\t},{\r\n"
            "\t\t\t\t\t\ttext: Ext.app.makeTxt('slideshow'),",
            "\t\t\t\t\t\ttext: Ext.app.makeTxt('makedir'),\r\n"
            "\t\t\t\t\t\tid: 'mkdirbtn',\r\n"
            "\t\t\t\t\t},{\r\n"
            "\t\t\t\t\t\ttext: Ext.app.makeTxt('menu_file_upload'),\r\n"
            "\t\t\t\t\t\tid: 'uploadbtn',\r\n"
            "\t\t\t\t\t\thandler: function()\r\n"
            "\t\t\t\t\t\t{\r\n"
            "\t\t\t\t\t\t\tExt.app.Util.upload(this);\r\n"
            "\t\t\t\t\t\t},\r\n"
            "\t\t\t\t\t},{\r\n"
            "\t\t\t\t\t\ttext: Ext.app.makeTxt('slideshow'),",
        )
    # Wire a native file input over the Upload button (iOS-safe; no programmatic click).
    old_beforeshow = (
        "\t\t\t\t\t\tbeforeshow:function(cmp)\r\n"
        "\t\t\t\t\t\t{\r\n"
        "\t\t\t\t\t\t\tvar mkdirBtn = cmp.getComponent('mkdirbtn');\r\n"
        "\t\t\t\t\t\t\tvar uploadBtn = cmp.getComponent('uploadbtn');\r\n"
        "\t\t\t\t\t\t\tif(isLogin){\r\n"
        "\t\t\t\t\t\t\t\tif(mkdirBtn) mkdirBtn.show();\r\n"
        "\t\t\t\t\t\t\t\tif(uploadBtn) uploadBtn.show();\r\n"
        "\t\t\t\t\t\t\t}else{\r\n"
        "\t\t\t\t\t\t\t\tif(mkdirBtn) mkdirBtn.hide();\r\n"
        "\t\t\t\t\t\t\t\tif(uploadBtn) uploadBtn.hide();\r\n"
        "\t\t\t\t\t\t\t}\r\n"
        "\t\t\t\t\t\t}"
    )
    new_beforeshow = (
        "\t\t\t\t\t\tbeforeshow:function(cmp)\r\n"
        "\t\t\t\t\t\t{\r\n"
        "\t\t\t\t\t\t\tvar mkdirBtn = cmp.getComponent('mkdirbtn');\r\n"
        "\t\t\t\t\t\t\tvar uploadBtn = cmp.getComponent('uploadbtn');\r\n"
        "\t\t\t\t\t\t\tif(isLogin){\r\n"
        "\t\t\t\t\t\t\t\tif(mkdirBtn) mkdirBtn.show();\r\n"
        "\t\t\t\t\t\t\t\tif(uploadBtn) uploadBtn.show();\r\n"
        "\t\t\t\t\t\t\t}else{\r\n"
        "\t\t\t\t\t\t\t\tif(mkdirBtn) mkdirBtn.hide();\r\n"
        "\t\t\t\t\t\t\t\tif(uploadBtn) uploadBtn.hide();\r\n"
        "\t\t\t\t\t\t\t}\r\n"
        "\t\t\t\t\t\t\ttry{if(uploadBtn&&Ext.app.Util&&Ext.app.Util._smWireUploadButton){Ext.defer(function(){try{Ext.app.Util._smWireUploadButton(uploadBtn,this);}catch(e){}},30,this);}}catch(e){}\r\n"
        "\t\t\t\t\t\t}"
    )
    if old_beforeshow in text:
        text = text.replace(old_beforeshow, new_beforeshow)
    elif (
        "id: 'uploadbtn'" in text
        and "beforeshow:function(cmp)" in text
        and "_smWireUploadButton" not in text
    ):
        text = text.replace(
            "\t\t\t\t\t\tbeforeshow:function(cmp)\r\n"
            "\t\t\t\t\t\t{\r\n"
            "\t\t\t\t\t\t\tif(isLogin){\r\n"
            "\t\t\t\t\t\t\t\tcmp.getComponent(0).show();\r\n"
            "\t\t\t\t\t\t\t}else{\r\n"
            "\t\t\t\t\t\t\t\tcmp.getComponent(0).hide();\r\n"
            "\t\t\t\t\t\t\t}\r\n"
            "\t\t\t\t\t\t}",
            new_beforeshow,
        )
    upload_block = (
        "\t_smParseRpc: function(text)\r\n"
        "\t{\r\n"
        "\t\tvar raw = String(text || '').trim();\r\n"
        "\t\tif(!raw){return null;}\r\n"
        "\t\ttry{if(typeof JSON !== 'undefined' && JSON.parse){return JSON.parse(raw);}}catch(e){}\r\n"
        "\t\ttry{return Ext.decode(raw);}catch(e){}\r\n"
        "\t\treturn null;\r\n"
        "\t},\r\n\r\n\t_smUploadFinish: function(response, raw, forceOk)\r\n"
        "\t{\r\n"
        "\t\tif(!response && raw){response = Ext.app.Util._smParseRpc(raw);}\r\n"
        "\t\tvar ok = forceOk || (response && (response.success === true || response.success === 'true' || response.success === 1));\r\n"
        "\t\tif(ok){\r\n"
        "\t\t\ttry{if(Ext.app.isPanel && Ext.app.isPanel.getComponent('data_view')){Ext.app.isPanel.getComponent('data_view').setData();}}catch(e){}\r\n"
        "\t\t\tvar names = '';\r\n"
        "\t\t\tif(response && response.result){for(var k in response.result){if(response.result.hasOwnProperty(k)){names += k + '<br/>';}}}\r\n"
        "\t\t\tvar body = names ? ('Uploaded:<br/>' + names) : 'Upload complete';\r\n"
        "\t\t\ttry{Ext.app.alert(Ext.app.makeTxt('confirm'), body);}catch(e){Ext.app.alert('Done', body);}\r\n"
        "\t\t}else{\r\n"
        "\t\t\tvar err = (response && response.msg) ? String(response.msg) : (raw || 'upload failed');\r\n"
        "\t\t\ttry{Ext.app.alert(Ext.app.makeTxt('error'), err);}catch(e){Ext.app.alert('Error', err);}\r\n"
        "\t\t}\r\n"
        "\t},\r\n\r\n\t_smWireUploadButton: function(btn, toolbar)\r\n"
        "\t{\r\n"
        "\t\tif(!btn){return;}\r\n"
        "\t\tvar el = (btn.el && btn.el.dom) || (btn.getEl && btn.getEl() && btn.getEl().dom) || document.getElementById('uploadbtn');\r\n"
        "\t\tif(!el){return;}\r\n"
        "\t\ttry{el.style.position = 'relative';}catch(e){}\r\n"
        "\t\tvar input = el.querySelector('#sm-st-upload-input-btn');\r\n"
        "\t\tif(!input){\r\n"
        "\t\t\tinput = document.createElement('input');\r\n"
        "\t\t\tinput.type = 'file';\r\n"
        "\t\t\tinput.id = 'sm-st-upload-input-btn';\r\n"
        "\t\t\tinput.multiple = true;\r\n"
        "\t\t\tinput.setAttribute('accept', '*/*');\r\n"
        "\t\t\tinput.style.cssText = 'position:absolute;left:0;top:0;width:100%;height:100%;opacity:0.01;z-index:20;border:0;margin:0;padding:0;';\r\n"
        "\t\t\tel.appendChild(input);\r\n"
        "\t\t\tinput.addEventListener('click', function(ev){try{ev.stopPropagation();}catch(e){}});\r\n"
        "\t\t\tinput.addEventListener('change', function(){\r\n"
        "\t\t\t\ttry{if(toolbar && toolbar.actions){toolbar.actions.hide();}}catch(e){}\r\n"
        "\t\t\t\tExt.app.Util._smDoUpload(input);\r\n"
        "\t\t\t});\r\n"
        "\t\t}\r\n"
        "\t\tinput._smActionsEl = toolbar;\r\n"
        "\t\ttry{input.value = '';}catch(e){}\r\n"
        "\t},\r\n\r\n\t_smDoUpload: function(input)\r\n"
        "\t{\r\n"
        "\t\tvar files = input && input.files;\r\n"
        "\t\tif(!files || !files.length){return;}\r\n"
        "\t\ttry{if(input._smActionsEl && input._smActionsEl.actions){input._smActionsEl.actions.hide();}}catch(e){}\r\n"
        "\t\ttry{if(window.Ext && Ext.Msg && Ext.Msg.hide){Ext.Msg.hide();}}catch(e){}\r\n"
        "\t\tExt.app.Util.setMask();\r\n"
        "\t\tvar dir = isDir || '/';\r\n"
        f"\t\tvar url = ('{NAS_FILES_PREFIX}/rpc/upload' + dir).split('/').map(encodeURIComponent).join('/');\r\n"
        "\t\tvar fd = new FormData();\r\n"
        "\t\tfor(var i = 0; i < files.length; i++){fd.append('filename[]', files[i]);}\r\n"
        "\t\tvar xhr = new XMLHttpRequest();\r\n"
        "\t\txhr.open('POST', url, true);\r\n"
        "\t\txhr.onload = function(){\r\n"
        "\t\t\tExt.app.Util.hideMask();\r\n"
        "\t\t\ttry{input.value = '';}catch(e){}\r\n"
        "\t\t\tExt.app.Util._smUploadFinish(Ext.app.Util._smParseRpc(xhr.responseText), xhr.responseText);\r\n"
        "\t\t};\r\n"
        "\t\txhr.onerror = function(){\r\n"
        "\t\t\tExt.app.Util.hideMask();\r\n"
        "\t\t\tExt.app.alert(Ext.app.makeTxt('error'), Ext.app.makeTxt('terminate a network connection'));\r\n"
        "\t\t};\r\n"
        "\t\txhr.send(fd);\r\n"
        "\t},\r\n\r\n\tupload: function(el)\r\n"
        "\t{\r\n"
        "\t\tif(!isLogin){\r\n"
        "\t\t\tExt.app.alert(Ext.app.makeTxt('error'), Ext.app.makeTxt('select tree to upload'));\r\n"
        "\t\t\treturn;\r\n"
        "\t\t}\r\n"
        "\t\ttry{\r\n"
        "\t\t\tvar btn = (el && el.actions && el.actions.getComponent) ? el.actions.getComponent('uploadbtn') : null;\r\n"
        "\t\t\tif(btn && Ext.app.Util._smWireUploadButton){Ext.app.Util._smWireUploadButton(btn, el);}\r\n"
        "\t\t\tvar input = document.getElementById('sm-st-upload-input-btn');\r\n"
        "\t\t\tif(input){try{input.value='';}catch(e){} try{input.click();return;}catch(e){}}\r\n"
        "\t\t}catch(e){}\r\n"
        "\t\ttry{\r\n"
        "\t\t\tvar topWin = window.top || window.parent;\r\n"
        "\t\t\tif(topWin && topWin !== window && typeof topWin.smNasUploadPick === 'function'){\r\n"
        "\t\t\t\twindow.__smUploadActionsEl = el;\r\n"
        "\t\t\t\ttopWin.smNasUploadPick(isDir || '/', window);\r\n"
        "\t\t\t\treturn;\r\n"
        "\t\t\t}\r\n"
        "\t\t}catch(e){}\r\n"
        "\t\tvar wrap = document.getElementById('sm-st-upload-wrap');\r\n"
        "\t\tvar input = document.getElementById('sm-st-upload-input');\r\n"
        "\t\tif(!wrap || !input){\r\n"
        "\t\t\twrap = document.createElement('label');\r\n"
        "\t\t\twrap.id = 'sm-st-upload-wrap';\r\n"
        "\t\t\twrap.setAttribute('for', 'sm-st-upload-input');\r\n"
        "\t\t\twrap.style.cssText = 'position:fixed;left:0;top:0;width:1px;height:1px;overflow:hidden;opacity:0.01;z-index:2147483647;';\r\n"
        "\t\t\tinput = document.createElement('input');\r\n"
        "\t\t\tinput.type = 'file';\r\n"
        "\t\t\tinput.id = 'sm-st-upload-input';\r\n"
        "\t\t\tinput.multiple = true;\r\n"
        "\t\t\tinput.setAttribute('accept', '*/*');\r\n"
        "\t\t\twrap.appendChild(input);\r\n"
        "\t\t\tdocument.body.appendChild(wrap);\r\n"
        "\t\t\tinput.onchange = function(){Ext.app.Util._smDoUpload(input);};\r\n"
        "\t\t}\r\n"
        "\t\tinput._smActionsEl = el;\r\n"
        "\t\ttry{input.value = '';}catch(e){}\r\n"
        "\t\ttry{wrap.click();}catch(e){try{input.click();}catch(e2){Ext.app.alert(Ext.app.makeTxt('error'), 'Upload is not supported in this browser.');}}\r\n"
        "\t},\r\n\r\n\tdeleteFile: function(datas, el)"
    )
    if "upload: function" not in text and "deleteFile: function" in text:
        text = text.replace("\t},\r\n\t\r\n\tdeleteFile: function(datas, el)", "\t},\r\n\r\n" + upload_block)
    elif (
        "setTimeout(function(){try{input.click()" in text
        or "sm-st-upload-input" in text
        or "smNasUploadPick" in text
        or "_smUploadFinish" in text
        or "_smWireUploadButton" in text
    ):
        text = re.sub(
            r"\t(?:_smParseRpc: function\(text\)\r\n[\s\S]*?)?(?:_smUploadFinish: function\(response, raw, forceOk\)\r\n[\s\S]*?)?(?:_smWireUploadButton: function\(btn, toolbar\)\r\n[\s\S]*?)?(?:_smDoUpload: function\(input\)\r\n[\s\S]*?)?upload: function\(el\)\r\n[\s\S]*?\t\},\r\n\r\n\tdeleteFile: function",
            upload_block,
            text,
            count=1,
        )
    if "this.actions.hide();\r\n\t\t\t\t\t\t\tExt.app.Util.upload(this);" in text:
        text = text.replace(
            "this.actions.hide();\r\n\t\t\t\t\t\t\tExt.app.Util.upload(this);",
            "Ext.app.Util.upload(this);",
        )
    if "Ext.app.Util.upload(this);\r\n\t\t\t\t\t\t\tthis.actions.hide();" in text:
        text = text.replace(
            "Ext.app.Util.upload(this);\r\n\t\t\t\t\t\t\tthis.actions.hide();",
            "Ext.app.Util.upload(this);",
        )
    if '"menu_file_upload"' not in text and '"makedir"' in text:
        text = text.replace(
            '\t\t\t"makedir" : "Create a new folder",',
            '\t\t\t"makedir" : "Create a new folder",\n\t\t\t"menu_file_upload" : "Upload",',
        )
    return text


def _nas_files_patch_removed_toolbar_buttons(text: str) -> str:
    """Guard Ext.getCmp().enable/disable calls for UI parts removed from the chrome."""
    text = re.sub(
        r"Ext\.getCmp\((['\"])([^'\"]+)\1\)\.(enable|disable|show|hide)\(\)",
        r"(function(_smB){if(_smB&&_smB.\3)_smB.\3();})(Ext.getCmp(\1\2\1))",
        text,
    )
    text = re.sub(
        r"iconPanel\.items\.each\(function\s*\(\s*item\s*\)\s*\{[\s\S]*?\}\s*\)\s*;",
        "try{if(window.iconPanel&&iconPanel.items&&iconPanel.items.each){iconPanel.items.each(function(item){if(item&&item.enable)try{item.enable();}catch(e){}});}}catch(e){}",
        text,
        count=1,
    )
    return text


def _nas_files_rewrite_json_paths(text: str) -> str:
    """Rewrite absolute icon/rpc paths in base_config.json and RPC JSON."""

    def repl(match: re.Match[str]) -> str:
        quote, path = match.group(1), match.group(2)
        if path.startswith(NAS_FILES_PREFIX + "/") or path == NAS_FILES_PREFIX:
            return match.group(0)
        return f"{quote}{NAS_FILES_PREFIX}{path}{quote}"

    return re.sub(
        r"""(['"])(/(?:rpc|ui|st|webaxs)(?:/[^'"]*)?)\1""",
        repl,
        text,
    )


def _nas_files_inject(body: bytes, content_type: str) -> bytes:
    ctype = (content_type or "").lower()
    is_js = (
        "javascript" in ctype
        or "ecmascript" in ctype
        or ctype in {"application/x-javascript", "text/js"}
    )
    is_html = "text/html" in ctype
    is_json = "application/json" in ctype or "text/json" in ctype or ctype.endswith("+json")
    is_css = "text/css" in ctype
    if not is_js and not is_html and not is_json and not is_css:
        return body
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = body.decode("latin-1")
        except Exception:
            return body

    try:
        if is_json:
            return _nas_files_rewrite_json_paths(text).encode("utf-8")

        if is_css:
            return _nas_files_patch_css(text).encode("utf-8")

        if is_js:
            return _nas_files_rewrite_js_paths(text).encode("utf-8")

        if "sm-nas-files-js" in text:
            return body
        text = _nas_files_rewrite_html_paths(text)
        snippet = NAS_FILES_SNIPPET
        lower = text.lower()
        head_idx = lower.find("<head>")
        if head_idx != -1:
            insert_at = head_idx + len("<head>")
            text = text[:insert_at] + snippet + text[insert_at:]
        else:
            idx = lower.find("</head>")
            if idx != -1:
                text = text[:idx] + snippet + text[idx:]
            else:
                text = snippet + text
        return text.encode("utf-8")
    except Exception:
        # Never drop NAS static assets if a rewrite/hook regresses.
        return body


# Cache rewritten static NAS UI assets on the VPS so phones don't re-pull
# Sencha/Ext over the ~40ms WireGuard hop on every Files open.
_NAS_FILES_CACHE_LOCK = threading.Lock()
_NAS_FILES_CACHE: dict[str, tuple[float, int, str, bytes]] = {}
_NAS_FILES_CACHE_BYTES = 0
_NAS_FILES_CACHE_MAX_BYTES = int(
    os.environ.get("NAS_FILES_CACHE_MAX_BYTES", str(48 * 1024 * 1024))
)
_NAS_FILES_CACHE_TTL = float(os.environ.get("NAS_FILES_CACHE_TTL", str(6 * 3600)))
_NAS_STATIC_EXTS = (
    ".js",
    ".css",
    ".png",
    ".gif",
    ".jpg",
    ".jpeg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".svg",
    ".map",
)
_nas_http_tls = threading.local()


def _nas_files_cacheable(method: str, rel: str) -> bool:
    if method != "GET":
        return False
    rel_l = (rel or "/").lower().split("?", 1)[0]
    if rel_l.startswith("/rpc/"):
        return False
    return any(rel_l.endswith(ext) for ext in _NAS_STATIC_EXTS)


def _nas_files_browser_cache_control(rel: str) -> str:
    rel_l = (rel or "/").lower().split("?", 1)[0]
    if rel_l.startswith("/rpc/"):
        return "no-store"
    if any(rel_l.endswith(ext) for ext in _NAS_STATIC_EXTS):
        # Buffalo ships versioned paths under /st/js/sencha-touch-1.1.0/ etc.
        return "private, max-age=86400"
    return "private, max-age=0, must-revalidate"


def _nas_files_cache_get(key: str) -> tuple[int, str, bytes] | None:
    now = time.time()
    with _NAS_FILES_CACHE_LOCK:
        hit = _NAS_FILES_CACHE.get(key)
        if not hit:
            return None
        expires, status, ctype, body = hit
        if expires < now:
            _NAS_FILES_CACHE.pop(key, None)
            global _NAS_FILES_CACHE_BYTES
            _NAS_FILES_CACHE_BYTES = max(0, _NAS_FILES_CACHE_BYTES - len(body))
            return None
        return status, ctype, body


def _nas_files_cache_put(key: str, status: int, ctype: str, body: bytes) -> None:
    if status != 200 or not body:
        return
    global _NAS_FILES_CACHE_BYTES
    with _NAS_FILES_CACHE_LOCK:
        old = _NAS_FILES_CACHE.pop(key, None)
        if old:
            _NAS_FILES_CACHE_BYTES = max(0, _NAS_FILES_CACHE_BYTES - len(old[3]))
        while (
            _NAS_FILES_CACHE
            and _NAS_FILES_CACHE_BYTES + len(body) > _NAS_FILES_CACHE_MAX_BYTES
        ):
            # Drop oldest insert order (dict preserves order).
            _k, _v = next(iter(_NAS_FILES_CACHE.items()))
            _NAS_FILES_CACHE.pop(_k, None)
            _NAS_FILES_CACHE_BYTES = max(0, _NAS_FILES_CACHE_BYTES - len(_v[3]))
        _NAS_FILES_CACHE[key] = (
            time.time() + _NAS_FILES_CACHE_TTL,
            status,
            ctype,
            body,
        )
        _NAS_FILES_CACHE_BYTES += len(body)


def _nas_files_reset_conn() -> None:
    conn = getattr(_nas_http_tls, "conn", None)
    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass
    _nas_http_tls.conn = None


def _nas_files_http_exchange(
    method: str,
    path_q: str,
    headers: dict[str, str],
    payload: bytes | None,
    timeout: float,
) -> tuple[int, dict[str, str], list[str], bytes, http.client.HTTPResponse | None]:
    """Keep-alive HTTP to the NAS (one connection per worker thread)."""
    parsed = urlparse(NAS_FILES_UPSTREAM)
    host = parsed.hostname or "192.168.8.159"
    port = int(parsed.port or 80)
    if not path_q.startswith("/"):
        path_q = "/" + path_q

    def _once() -> tuple[int, dict[str, str], list[str], bytes, http.client.HTTPResponse | None]:
        conn = getattr(_nas_http_tls, "conn", None)
        if conn is None:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
            _nas_http_tls.conn = conn
        else:
            conn.timeout = timeout
        conn.request(method, path_q, body=payload, headers=headers)
        resp = conn.getresponse()
        status = int(resp.status)
        upstream_headers = {k: v for k, v in resp.getheaders()}
        set_cookies = [v for k, v in resp.getheaders() if k.lower() == "set-cookie"]
        # Caller streams large bodies; otherwise read fully so conn can be reused.
        return status, upstream_headers, set_cookies, b"", resp

    try:
        return _once()
    except (http.client.HTTPException, OSError, TimeoutError):
        _nas_files_reset_conn()
        try:
            return _once()
        except (http.client.HTTPException, OSError, TimeoutError) as exc:
            _nas_files_reset_conn()
            raise URLError(str(exc)) from exc


def _nas_files_maybe_gzip(handler: "Handler", body: bytes, content_type: str) -> tuple[bytes, str | None]:
    ctype = (content_type or "").lower()
    if not body or len(body) < 512:
        return body, None
    if not any(
        x in ctype
        for x in (
            "javascript",
            "ecmascript",
            "text/css",
            "text/html",
            "text/plain",
            "application/json",
            "image/svg",
        )
    ):
        return body, None
    ae = (handler.headers.get("Accept-Encoding") or "").lower()
    if "gzip" not in ae:
        return body, None
    compressed = gzip.compress(body, compresslevel=5)
    if len(compressed) >= len(body) * 0.95:
        return body, None
    return compressed, "gzip"


def proxy_nas_files_request(handler: "Handler", method: str) -> None:
    """Same-origin reverse proxy to Buffalo WebAccess (file manager on :9000).

    Streams binary file open/download/thumbnail responses (multi‑GB movies) and
    forwards Range/HEAD so browsers can play video and icons can load.
    Caches rewritten static JS/CSS/images on the VPS and allows browser caching.
    """
    import shutil

    parsed = urlparse(handler.path)
    rel = parsed.path[len(NAS_FILES_PREFIX) :] or "/"
    if not rel.startswith("/"):
        rel = "/" + rel
    path_q = rel
    if parsed.query:
        path_q = rel + "?" + parsed.query
    upstream = urljoin(NAS_FILES_UPSTREAM + "/", rel.lstrip("/"))
    if parsed.query:
        upstream = upstream + "?" + parsed.query

    length = int(handler.headers.get("Content-Length", "0") or "0")
    payload = handler.rfile.read(length) if length > 0 and method != "HEAD" else None

    headers = {}
    for key in (
        "Accept",
        "Accept-Language",
        "Content-Type",
        "X-Requested-With",
        "Referer",
        "Range",
        "If-Range",
        "If-None-Match",
        "If-Modified-Since",
    ):
        val = handler.headers.get(key)
        if val:
            headers[key] = val
    cookie = handler.headers.get("Cookie")
    if cookie:
        # Prefer the last webaxs_session if the browser still has Path=/ and
        # Path=/nas-files/ duplicates from older builds.
        kept: list[str] = []
        webaxs_val: str | None = None
        for part in cookie.split(";"):
            piece = part.strip()
            if not piece or "=" not in piece:
                continue
            name, val = piece.split("=", 1)
            name = name.strip()
            val = val.strip()
            if not name or name == COOKIE_NAME:
                continue
            if name == "webaxs_session":
                webaxs_val = val
                continue
            kept.append(f"{name}={val}")
        if webaxs_val:
            kept.append(f"webaxs_session={webaxs_val}")
        if kept:
            headers["Cookie"] = "; ".join(kept)
    headers["Host"] = urlparse(NAS_FILES_UPSTREAM).netloc or "192.168.8.159:9000"
    headers["User-Agent"] = handler.headers.get("User-Agent") or "ServerManager-NasFilesProxy/1.0"
    headers["Accept-Encoding"] = "identity"
    headers["Connection"] = "keep-alive"

    try:
        _prepare_nas_files_proxy(force=False)
    except Exception:
        pass

    rel_l = rel.lower()
    stream_body = method == "HEAD" or any(
        rel_l.startswith(p)
        for p in ("/rpc/cat", "/rpc/download", "/rpc/thumbnail")
    )
    cache_key = f"{method}:{path_q}"
    use_cache = _nas_files_cacheable(method, rel) and not stream_body

    # Serve rewritten static assets from VPS memory when possible.
    if use_cache:
        cached = _nas_files_cache_get(cache_key)
        if cached is not None:
            status, content_type, body = cached
            etag = '"' + hashlib.md5(body).hexdigest() + '"'
            inm = (handler.headers.get("If-None-Match") or "").strip()
            if inm and inm == etag:
                handler.send_response(304)
                handler.send_header("ETag", etag)
                handler.send_header("Cache-Control", _nas_files_browser_cache_control(rel))
                handler.end_headers()
                return
            out_body, enc = _nas_files_maybe_gzip(handler, body, content_type)
            handler.send_response(status)
            handler.send_header("Content-Type", content_type)
            handler.send_header("Content-Length", str(len(out_body)))
            handler.send_header("Cache-Control", _nas_files_browser_cache_control(rel))
            handler.send_header("ETag", etag)
            handler.send_header("X-Nas-Cache", "HIT")
            if enc:
                handler.send_header("Content-Encoding", enc)
                handler.send_header("Vary", "Accept-Encoding")
            handler.end_headers()
            if method != "HEAD":
                handler.wfile.write(out_body)
            return

    resp = None
    body = b""
    status = 502
    upstream_headers: dict[str, str] = {}
    set_cookies: list[str] = []
    try:
        timeout = 600.0 if stream_body else 60.0
        status, upstream_headers, set_cookies, _, resp = _nas_files_http_exchange(
            method, path_q, headers, payload, timeout
        )
        if stream_body:
            body = b""
        else:
            assert resp is not None
            body = resp.read()
            # Do not resp.close() — that closes the keep-alive socket.
            resp = None
    except (URLError, TimeoutError, OSError) as exc:
        # Fallback to urllib once if keep-alive path fails hard.
        try:
            _prepare_nas_files_proxy(force=True)
        except Exception:
            pass
        _nas_files_reset_conn()
        try:
            req = Request(upstream, data=payload, headers=headers, method=method)
            resp = urlopen(req, timeout=600)
            status = int(getattr(resp, "status", 200) or 200)
            upstream_headers = {k: v for k, v in resp.headers.items()}
            set_cookies = []
            if hasattr(resp.headers, "get_all"):
                set_cookies = resp.headers.get_all("Set-Cookie") or []
            elif resp.headers.get("Set-Cookie"):
                set_cookies = [resp.headers.get("Set-Cookie")]
            body = b"" if stream_body else resp.read()
            if not stream_body and resp is not None:
                try:
                    resp.close()
                except Exception:
                    pass
                resp = None
        except HTTPError as http_exc:
            status = int(getattr(http_exc, "code", 502) or 502)
            upstream_headers = {
                k: v for k, v in (http_exc.headers.items() if http_exc.headers else [])
            }
            set_cookies = []
            if http_exc.headers and hasattr(http_exc.headers, "get_all"):
                set_cookies = http_exc.headers.get_all("Set-Cookie") or []
            elif http_exc.headers and http_exc.headers.get("Set-Cookie"):
                set_cookies = [http_exc.headers.get("Set-Cookie")]
            if stream_body:
                resp = http_exc
                body = b""
            else:
                body = http_exc.read() if hasattr(http_exc, "read") else b""
                resp = None
        except (URLError, TimeoutError, OSError) as exc:
            handler._json(502, _nas_files_error_detail(exc))
            return

    content_type = (
        upstream_headers.get("Content-Type")
        or upstream_headers.get("content-type")
        or "application/octet-stream"
    )
    if (not stream_body) and rel.lower().endswith(".js") and "javascript" not in content_type.lower():
        content_type = "application/javascript; charset=utf-8"
    if (not stream_body) and rel.lower().endswith(".json") and "json" not in content_type.lower():
        content_type = "application/json; charset=utf-8"
    if not stream_body:
        body = _nas_files_inject(body, content_type)
        if use_cache and status == 200:
            _nas_files_cache_put(cache_key, status, content_type, body)

    if stream_body:
        handler.send_response(status)
        skip = {
            "transfer-encoding",
            "content-length",
            "connection",
            "content-encoding",
            "x-frame-options",
            "content-security-policy",
            "set-cookie",
        }
        for key, value in upstream_headers.items():
            low = key.lower()
            if low in skip:
                continue
            if low == "location":
                handler.send_header(key, _nas_files_rewrite_location(value))
            else:
                handler.send_header(key, value)
        for cookie_hdr in set_cookies:
            if cookie_hdr:
                handler.send_header("Set-Cookie", _nas_files_rewrite_set_cookie(cookie_hdr))
        # Preserve upstream Content-Length / Accept-Ranges for video seeking.
        cl = upstream_headers.get("Content-Length") or upstream_headers.get("content-length")
        if cl and method != "HEAD":
            handler.send_header("Content-Length", cl)
        elif method == "HEAD" and cl:
            handler.send_header("Content-Length", cl)
        if not (upstream_headers.get("Accept-Ranges") or upstream_headers.get("accept-ranges")):
            handler.send_header("Accept-Ranges", "bytes")
        # Prefer inline playback for /rpc/cat (movies) over forced download.
        cd = upstream_headers.get("Content-Disposition") or upstream_headers.get("content-disposition")
        if not cd and rel_l.startswith("/rpc/cat"):
            handler.send_header("Content-Disposition", "inline")
        handler.send_header("Cache-Control", "private, max-age=0")
        handler.end_headers()
        if method != "HEAD" and resp is not None:
            try:
                shutil.copyfileobj(resp, handler.wfile, length=1024 * 256)
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                try:
                    resp.close()
                except Exception:
                    pass
                # Body consumed; keep-alive socket may still be reusable.
        elif resp is not None:
            try:
                resp.close()
            except Exception:
                pass
        return

    if resp is not None:
        try:
            resp.close()
        except Exception:
            pass

    etag = '"' + hashlib.md5(body).hexdigest() + '"' if body else None
    inm = (handler.headers.get("If-None-Match") or "").strip()
    if etag and inm == etag and status == 200:
        handler.send_response(304)
        handler.send_header("ETag", etag)
        handler.send_header("Cache-Control", _nas_files_browser_cache_control(rel))
        handler.end_headers()
        return

    out_body, enc = _nas_files_maybe_gzip(handler, body, content_type)
    handler.send_response(status)
    skip = {
        "transfer-encoding",
        "content-length",
        "connection",
        "content-encoding",
        "x-frame-options",
        "content-security-policy",
        "set-cookie",
        "cache-control",
        "etag",
    }
    for key, value in upstream_headers.items():
        low = key.lower()
        if low in skip:
            continue
        if low == "location":
            handler.send_header(key, _nas_files_rewrite_location(value))
        else:
            handler.send_header(key, value)
    for cookie_hdr in set_cookies:
        if cookie_hdr:
            handler.send_header("Set-Cookie", _nas_files_rewrite_set_cookie(cookie_hdr))
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(out_body)))
    handler.send_header("Cache-Control", _nas_files_browser_cache_control(rel))
    if etag:
        handler.send_header("ETag", etag)
    if use_cache:
        handler.send_header("X-Nas-Cache", "MISS")
    if enc:
        handler.send_header("Content-Encoding", enc)
        handler.send_header("Vary", "Accept-Encoding")
    handler.end_headers()
    if method != "HEAD":
        handler.wfile.write(out_body)


def _buffalo_rewrite_location(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return raw
    if raw.startswith(BUFFALO_PREFIX + "/") or raw == BUFFALO_PREFIX:
        return raw
    lower = raw.lower()
    for prefix in (
        BUFFALO_UPSTREAM,
        "http://192.168.8.159",
        "https://buffalo.vpstruelord.com",
        "http://buffalo.vpstruelord.com",
    ):
        if lower.startswith(prefix.lower()):
            rest = raw[len(prefix) :]
            if not rest.startswith("/"):
                rest = "/" + rest
            return BUFFALO_PREFIX + rest
    if raw.startswith("/"):
        return BUFFALO_PREFIX + raw
    return raw


def _buffalo_rewrite_set_cookie(value: str) -> str:
    parts = [p.strip() for p in value.split(";") if p.strip()]
    if not parts:
        return value
    out = [parts[0]]
    saw_path = False
    for part in parts[1:]:
        low = part.lower()
        if low.startswith("path="):
            out.append(f"Path={BUFFALO_PREFIX}/")
            saw_path = True
        elif low.startswith("domain="):
            continue
        else:
            out.append(part)
    if not saw_path:
        out.append(f"Path={BUFFALO_PREFIX}/")
    return "; ".join(out)


def _buffalo_rewrite_html_paths(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        attr, quote, path = match.group(1), match.group(2), match.group(3)
        if path.startswith(BUFFALO_PREFIX + "/") or path == BUFFALO_PREFIX:
            return match.group(0)
        return f"{attr}={quote}{BUFFALO_PREFIX}{path}{quote}"

    return re.sub(
        r"\b(href|src|action)=(['\"])(/(?!/|buffalo-frame/)[^'\"]*)\2",
        repl,
        text,
        flags=re.I,
    )


def _buffalo_inject_fit_css(body: bytes, content_type: str) -> bytes:
    ctype = (content_type or "").lower()
    if "text/html" not in ctype:
        return body
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = body.decode("latin-1")
        except Exception:
            return body
    if "sm-buffalo-fit" in text:
        return body
    text = _buffalo_rewrite_html_paths(text)
    snippet = BUFFALO_FIT_SNIPPET
    lower = text.lower()
    # Inject BEFORE other scripts so XHR/fetch patch is active for ExtJS.
    head_idx = lower.find("<head>")
    if head_idx != -1:
        insert_at = head_idx + len("<head>")
        text = text[:insert_at] + snippet + text[insert_at:]
    else:
        idx = lower.find("</head>")
        if idx != -1:
            text = text[:idx] + snippet + text[idx:]
        else:
            text = snippet + text
    return text.encode("utf-8")


def proxy_buffalo_request(handler: "Handler", method: str) -> None:
    """Same-origin reverse proxy to the LinkStation, with CSS fit injection."""
    parsed = urlparse(handler.path)
    rel = parsed.path[len(BUFFALO_PREFIX) :] or "/"
    if not rel.startswith("/"):
        rel = "/" + rel
    upstream = urljoin(BUFFALO_UPSTREAM + "/", rel.lstrip("/"))
    if parsed.query:
        upstream = upstream + "?" + parsed.query

    length = int(handler.headers.get("Content-Length", "0") or "0")
    payload = handler.rfile.read(length) if length > 0 else None

    headers = {}
    for key in ("Accept", "Accept-Language", "Content-Type", "X-Requested-With", "Referer"):
        val = handler.headers.get(key)
        if val:
            headers[key] = val
    cookie = handler.headers.get("Cookie")
    if cookie:
        # Drop portal session cookie; NAS only needs its own cookies.
        kept = []
        for part in cookie.split(";"):
            name = part.strip().split("=", 1)[0].strip()
            if name and name != COOKIE_NAME:
                kept.append(part.strip())
        if kept:
            headers["Cookie"] = "; ".join(kept)
    headers["Host"] = urlparse(BUFFALO_UPSTREAM).netloc
    headers["User-Agent"] = handler.headers.get("User-Agent") or "ServerManager-BuffaloProxy/1.0"
    headers["Accept-Encoding"] = "identity"

    req = Request(upstream, data=payload, headers=headers, method=method)
    try:
        with urlopen(req, timeout=60) as resp:
            body = resp.read()
            status = getattr(resp, "status", 200) or 200
            upstream_headers = {k: v for k, v in resp.headers.items()}
            set_cookies = []
            if hasattr(resp.headers, "get_all"):
                set_cookies = resp.headers.get_all("Set-Cookie") or []
            elif resp.headers.get("Set-Cookie"):
                set_cookies = [resp.headers.get("Set-Cookie")]
    except HTTPError as exc:
        body = exc.read() if hasattr(exc, "read") else b""
        status = int(getattr(exc, "code", 502) or 502)
        upstream_headers = {k: v for k, v in (exc.headers.items() if exc.headers else [])}
        set_cookies = []
        if exc.headers and hasattr(exc.headers, "get_all"):
            set_cookies = exc.headers.get_all("Set-Cookie") or []
        elif exc.headers and exc.headers.get("Set-Cookie"):
            set_cookies = [exc.headers.get("Set-Cookie")]
    except (URLError, TimeoutError, OSError) as exc:
        try:
            threading.Thread(
                target=lambda: ensure_flint_ovpn_lan_access(force=True),
                name="flint-ovpn-lan-buffalo",
                daemon=True,
            ).start()
        except Exception:
            pass
        handler._json(502, {"error": f"buffalo proxy failed: {exc}"})
        return

    content_type = upstream_headers.get("Content-Type") or upstream_headers.get("content-type") or "application/octet-stream"
    body = _buffalo_inject_fit_css(body, content_type)

    handler.send_response(status)
    skip = {
        "transfer-encoding",
        "content-length",
        "connection",
        "content-encoding",
        "x-frame-options",
        "content-security-policy",
        "set-cookie",
    }
    for key, value in upstream_headers.items():
        low = key.lower()
        if low in skip:
            continue
        if low == "location":
            handler.send_header(key, _buffalo_rewrite_location(value))
        else:
            handler.send_header(key, value)
    for cookie in set_cookies:
        if cookie:
            handler.send_header("Set-Cookie", _buffalo_rewrite_set_cookie(cookie))
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


def _wg_ui_rewrite_location(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return raw
    lower = raw.lower()
    for host in WG_UI_PUBLIC_HOSTS:
        host_l = host.lower()
        if host_l.startswith("http://") or host_l.startswith("https://"):
            prefix = host_l
        else:
            # bare host — try both schemes against the Location value
            for scheme in ("https://", "http://"):
                p = scheme + host_l
                if lower.startswith(p):
                    rest = raw[len(p) :]
                    if not rest.startswith("/"):
                        rest = "/" + rest
                    return WG_UI_PREFIX + rest
            continue
        if lower.startswith(prefix):
            rest = raw[len(prefix) :]
            if not rest.startswith("/"):
                rest = "/" + rest
            return WG_UI_PREFIX + rest
    if raw.startswith("/") and not raw.startswith("//"):
        if raw == WG_UI_PREFIX or raw.startswith(WG_UI_PREFIX + "/"):
            return raw
        return WG_UI_PREFIX + raw
    return raw


def _wg_ui_rewrite_set_cookie(cookie: str) -> str:
    parts = [p.strip() for p in (cookie or "").split(";") if p.strip()]
    if not parts:
        return cookie
    out = [parts[0]]
    saw_path = False
    for part in parts[1:]:
        low = part.lower()
        if low.startswith("path="):
            out.append(f"Path={WG_UI_PREFIX}/")
            saw_path = True
        elif low.startswith("domain="):
            continue
        elif low.startswith("samesite="):
            out.append("SameSite=Lax")
        else:
            out.append(part)
    if not saw_path:
        out.append(f"Path={WG_UI_PREFIX}/")
    # Force dark theme preference for nuxt-color-mode (cookie name: theme).
    return "; ".join(out)


def _wg_ui_rewrite_html(text: str) -> str:
    def repl_attr(match: re.Match[str]) -> str:
        attr, quote, path = match.group(1), match.group(2), match.group(3)
        if path.startswith(WG_UI_PREFIX + "/") or path == WG_UI_PREFIX:
            return match.group(0)
        return f"{attr}={quote}{WG_UI_PREFIX}{path}{quote}"

    text = re.sub(
        r"\b(href|src|action)=(['\"])(/(?!/|"
        + re.escape(WG_UI_PREFIX.lstrip("/"))
        + r"/)[^'\"]*)\2",
        repl_attr,
        text,
        flags=re.I,
    )

    def repl_abs(match: re.Match[str]) -> str:
        quote, path = match.group(1), match.group(2)
        if path.startswith(WG_UI_PREFIX + "/") or path == WG_UI_PREFIX:
            return match.group(0)
        return f"{quote}{WG_UI_PREFIX}{path}{quote}"

    # importmap / JSON absolute paths: "/_nuxt/...", "/manifest.json", etc.
    text = re.sub(
        r"(['\"])(/(?:_nuxt|api|login|logout|clients|admin|manifest\.json|favicon\.png|apple-touch-icon\.png)[^'\"]*)\1",
        repl_abs,
        text,
        flags=re.I,
    )
    # Force dark on <html>
    def force_dark_html(match: re.Match[str]) -> str:
        attrs = match.group(1) or ""
        if "data-color-mode-forced" not in attrs.lower():
            attrs = ' data-color-mode-forced="dark"' + attrs
        if re.search(r"\bclass\s*=", attrs, flags=re.I):
            attrs = re.sub(
                r'class=(["\'])(.*?)\1',
                lambda c: (
                    f'class={c.group(1)}{c.group(2)}{c.group(1)}'
                    if re.search(r"(^|\s)dark(\s|$)", c.group(2))
                    else f'class={c.group(1)}{(c.group(2) + " dark").strip()}{c.group(1)}'
                ),
                attrs,
                count=1,
                flags=re.I,
            )
        else:
            attrs = ' class="dark"' + attrs
        return f"<html{attrs}>"

    text = re.sub(r"<html\b([^>]*)>", force_dark_html, text, count=1, flags=re.I)
    return text


def _wg_ui_inject_theme(body: bytes, content_type: str) -> bytes:
    ctype = (content_type or "").lower()
    if "text/html" not in ctype:
        return body
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = body.decode("latin-1")
        except Exception:
            return body
    if "sm-wg-theme" in text:
        return body
    text = _wg_ui_rewrite_html(text)
    # Help Nuxt router resolve under the portal prefix.
    text = text.replace('baseURL:"/"', f'baseURL:"{WG_UI_PREFIX}/"')
    text = text.replace("baseURL:'/'", f"baseURL:'{WG_UI_PREFIX}/'")
    snippet = WG_UI_THEME_SNIPPET
    lower = text.lower()
    head_idx = lower.find("<head>")
    if head_idx != -1:
        insert_at = head_idx + len("<head>")
        text = text[:insert_at] + snippet + text[insert_at:]
    else:
        idx = lower.find("</head>")
        if idx != -1:
            text = text[:idx] + snippet + text[idx:]
        else:
            text = snippet + text
    return text.encode("utf-8")


def proxy_wg_ui_request(handler: "Handler", method: str) -> None:
    """Same-origin reverse proxy to wg-easy with ServerManager theme injection."""
    parsed = urlparse(handler.path)
    rel = parsed.path[len(WG_UI_PREFIX) :] or "/"
    if not rel.startswith("/"):
        rel = "/" + rel
    upstream = urljoin(WG_UI_UPSTREAM + "/", rel.lstrip("/"))
    if parsed.query:
        upstream = upstream + "?" + parsed.query

    length = int(handler.headers.get("Content-Length", "0") or "0")
    payload = handler.rfile.read(length) if length > 0 else None

    headers = {}
    for key in (
        "Accept",
        "Accept-Language",
        "Content-Type",
        "X-Requested-With",
        "Referer",
        "Origin",
    ):
        val = handler.headers.get(key)
        if val:
            headers[key] = val
    cookie = handler.headers.get("Cookie")
    if cookie:
        kept = []
        for part in cookie.split(";"):
            name = part.strip().split("=", 1)[0].strip()
            if name and name != COOKIE_NAME:
                kept.append(part.strip())
        # Ensure dark theme preference reaches nuxt-color-mode.
        if not any(p.lower().startswith("theme=") for p in kept):
            kept.append("theme=dark")
        if kept:
            headers["Cookie"] = "; ".join(kept)
    else:
        headers["Cookie"] = "theme=dark"
    headers["Host"] = urlparse(WG_UI_UPSTREAM).netloc
    headers["User-Agent"] = handler.headers.get("User-Agent") or "ServerManager-WgUiProxy/1.0"
    headers["Accept-Encoding"] = "identity"
    headers["X-Forwarded-Proto"] = "https"
    headers["X-Forwarded-Host"] = handler.headers.get("Host") or PORTAL_HOST

    req = Request(upstream, data=payload, headers=headers, method=method)
    try:
        with urlopen(req, timeout=60) as resp:
            body = resp.read()
            status = getattr(resp, "status", 200) or 200
            upstream_headers = {k: v for k, v in resp.headers.items()}
            set_cookies = []
            if hasattr(resp.headers, "get_all"):
                set_cookies = resp.headers.get_all("Set-Cookie") or []
            elif resp.headers.get("Set-Cookie"):
                set_cookies = [resp.headers.get("Set-Cookie")]
    except HTTPError as exc:
        body = exc.read() if hasattr(exc, "read") else b""
        status = int(getattr(exc, "code", 502) or 502)
        upstream_headers = {k: v for k, v in (exc.headers.items() if exc.headers else [])}
        set_cookies = []
        if exc.headers and hasattr(exc.headers, "get_all"):
            set_cookies = exc.headers.get_all("Set-Cookie") or []
        elif exc.headers and exc.headers.get("Set-Cookie"):
            set_cookies = [exc.headers.get("Set-Cookie")]
    except (URLError, TimeoutError, OSError) as exc:
        handler._json(502, {"error": f"wg-ui proxy failed: {exc}"})
        return

    content_type = (
        upstream_headers.get("Content-Type")
        or upstream_headers.get("content-type")
        or "application/octet-stream"
    )
    body = _wg_ui_inject_theme(body, content_type)

    # Always advertise dark theme cookie for this prefix.
    set_cookies = list(set_cookies or [])
    set_cookies.append(f"theme=dark; Path={WG_UI_PREFIX}/; Max-Age=31536000; SameSite=Lax")

    handler.send_response(status)
    skip = {
        "transfer-encoding",
        "content-length",
        "connection",
        "content-encoding",
        "x-frame-options",
        "content-security-policy",
        "set-cookie",
    }
    for key, value in upstream_headers.items():
        low = key.lower()
        if low in skip:
            continue
        if low == "location":
            handler.send_header(key, _wg_ui_rewrite_location(value))
        else:
            handler.send_header(key, value)
    for cookie in set_cookies:
        if cookie:
            handler.send_header("Set-Cookie", _wg_ui_rewrite_set_cookie(cookie))
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Content-Security-Policy", "frame-ancestors 'self'")
    handler.end_headers()
    if method.upper() != "HEAD":
        handler.wfile.write(body)


class Handler(BaseHTTPRequestHandler):
    server_version = "ServerManager/1.2"

    def log_message(self, fmt: str, *args) -> None:
        print(f"[{self.log_date_time_string()}] {self.address_string()} {fmt % args}")

    def _unauthorized(self, *, api: bool = True, reason: str = "no session") -> None:
        if reason != "no session":
            log_failed_login(self.client_address[0], AUTH_USER, reason)
        if api:
            self._json(401, {"error": "unauthorized"})
            return
        self.send_response(302)
        self.send_header("Location", "/login.html")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def _json(self, code: int, payload: dict, *, set_cookie: str | None = None, clear_cookie: bool = False, extra_cookies: list[str] | None = None) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if set_cookie:
            self.send_header("Set-Cookie", _cookie_set_header(set_cookie))
        if clear_cookie:
            self.send_header("Set-Cookie", _cookie_clear_header())
        for cookie in extra_cookies or []:
            if cookie:
                self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def _is_authed(self) -> bool:
        if check_basic_auth(self.headers.get("Authorization")):
            return True
        return session_valid(parse_session_cookie(self.headers.get("Cookie")))

    def _nas_download_allowed(self, query: str) -> bool:
        if self._is_authed():
            return True
        from urllib.parse import parse_qs

        token = (parse_qs(query or "").get("t") or [""])[0]
        return nas_download_token_valid(token)

    def _require_auth(self, *, api: bool = True) -> bool:
        if self._is_authed():
            return True
        self._unauthorized(api=api)
        return False

    def _require_ssh_panel_unlock(self) -> bool:
        """Portal session must have recently re-entered the portal password."""
        tok = parse_session_cookie(self.headers.get("Cookie"))
        st = ssh_panel_unlock_status(tok)
        if st.get("unlocked"):
            return True
        self._json(
            403,
            {
                "ok": False,
                "error": "VPS login panel is locked. Re-enter the password to unlock.",
                "panel_lock": st,
            },
        )
        return False

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw.decode("utf-8") or "{}")

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/logout":
            destroy_session(parse_session_cookie(self.headers.get("Cookie")))
            body = (
                b"<!DOCTYPE html><html><head>"
                b'<meta charset="utf-8" />'
                b'<meta http-equiv="refresh" content="0;url=/login.html" />'
                b"<title>Signing out</title>"
                b"<script>location.replace('/login.html');</script>"
                b"</head><body>Signed out. <a href='/login.html'>Continue</a></body></html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", _cookie_clear_header())
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        if path in (
            "/login.html",
            "/email-code-test.html",
            "/auth-app.html",
            "/auth-app-iphone.html",
            "/api/branding",
            "/api/health",
            "/api/auth-app/vpn-allowlist",
            "/api/auth-app/enroll-status",
            "/api/auth-app/register-device",
        ) or path.startswith("/static/"):
            pass  # public (auth-app is the phone authenticator PWA)
        elif path in (
            "/api/openvpn/windows",
            "/download/windows.ovpn",
        ):
            pass  # public Windows OpenVPN download (token checked below)
        elif path in ("/claim", "/claim/", "/claim/api", "/api/plex/claim"):
            pass  # public plex claim helper (proxied from plex.vpstruelord.com)
        elif path in ("/api/email-code/send", "/api/email-code/verify"):
            pass  # public email-code test form APIs (rate-limited)
        elif not self._is_authed():
            if path.startswith("/api/") or path.startswith("/claim"):
                self._unauthorized(api=True)
            else:
                self._unauthorized(api=False)
            return

        if path in ("/claim", "/claim/"):
            html = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Claim Plex Media Server</title>
<style>body{font-family:system-ui,sans-serif;background:#111;color:#eee;max-width:36rem;margin:3rem auto;padding:0 1rem;line-height:1.45}
input,button{font:inherit;padding:.65rem .8rem;border-radius:8px;border:1px solid #444;background:#222;color:#eee;width:100%;box-sizing:border-box;margin:.4rem 0}
button{background:#e5a00d;color:#111;border:0;font-weight:700;cursor:pointer}
a{color:#e5a00d}pre{white-space:pre-wrap;background:#1a1a1a;padding:.75rem;border-radius:8px}</style></head><body>
<h1>Claim Plex Media Server</h1>
<p>Your Proxmox container already runs Plex Media Server. The web setup page shows <b>Not authorized</b> over the public URL until the server is claimed to your plex.tv account.</p>
<p><b>Codes expire in about 4 minutes</b> — copy a fresh one and paste it here immediately.</p>
<ol>
<li>Open <a href="https://www.plex.tv/claim/" target="_blank" rel="noopener">https://www.plex.tv/claim/</a> while signed in</li>
<li>Copy the claim code (starts with <code>claim-</code>)</li>
<li>Paste it below within one minute and click <b>Claim server</b></li>
</ol>
<form id="f"><input id="t" name="token" placeholder="claim-xxxxxxxx" autocomplete="off" required>
<button type="submit">Claim server</button></form>
<pre id="o"></pre>
<script>
document.getElementById('f').onsubmit = async (e) => {
  e.preventDefault();
  const o = document.getElementById('o');
  o.textContent = 'Claiming…';
  try {
    const r = await fetch('/claim/api', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({token: document.getElementById('t').value})
    });
    const j = await r.json();
    o.textContent = JSON.stringify(j, null, 2);
    if (j.ok) location.href = 'https://plex.vpstruelord.com/web/index.html';
  } catch (err) {
    o.textContent = String(err);
  }
};
</script></body></html>"""
            body = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/api/branding":
            self._json(
                200,
                {
                    "title": PANEL_TITLE,
                    "tagline": PANEL_TAGLINE,
                },
            )
            return
        if path == "/api/me":
            self._json(200, {"ok": True, "user": AUTH_USER, "title": PANEL_TITLE})
            return
        if path == "/api/settings":
            if not self._require_auth(api=True):
                return
            try:
                self._json(200, build_portal_settings())
            except Exception as exc:
                self._json(500, {"error": str(exc)})
            return
        if path == "/api/leds":
            if not self._require_auth(api=True):
                return
            try:
                self._json(200, leds_status())
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc), "state": "unknown"})
            return
        if path == "/api/bluetooth":
            if not self._require_auth(api=True):
                return
            try:
                self._json(200, bluetooth_status())
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc), "owner": "unknown"})
            return
        if path == "/api/xbox":
            if not self._require_auth(api=True):
                return
            try:
                self._json(200, xbox_status())
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc), "owner": "unknown"})
            return
        if path == "/api/elements":
            if not self._require_auth(api=True):
                return
            try:
                self._json(200, elements_status())
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc), "state": "unknown"})
            return
        if path == "/api/elements/pipeline":
            if not self._require_auth(api=True):
                return
            try:
                self._json(200, elements_pipeline_status())
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path == "/api/forwards":
            try:
                self._json(200, read_state())
            except Exception as exc:
                self._json(500, {"error": str(exc)})
            return
        if path == "/api/lan-devices":
            try:
                self._json(200, read_lan_devices())
            except Exception as exc:
                self._json(500, {"error": str(exc), "devices": []})
            return
        if path == "/api/bond":
            try:
                self._json(200, read_bond_state())
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc), "installed": False})
            return
        if path == "/api/health":
            self._json(200, {"ok": True})
            return
        if path in ("/", "/index.html"):
            return self._serve_file(STATIC_DIR / "index.html", "text/html; charset=utf-8")
        if path == "/openvpn.html":
            return self._serve_file(STATIC_DIR / "openvpn.html", "text/html; charset=utf-8")
        if path in ("/windows-vpn.html", "/ikev2.html"):
            return self._serve_file(STATIC_DIR / "windows-vpn.html", "text/html; charset=utf-8")
        if path in ("/nas-windows.html", "/nas-setup.html"):
            return self._serve_file(STATIC_DIR / "nas-windows.html", "text/html; charset=utf-8")
        if path == "/login.html":
            # Always clear any stale session display path; if still authed, go home
            if self._is_authed():
                self.send_response(302)
                self.send_header("Location", "/")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                return
            return self._serve_file(STATIC_DIR / "login.html", "text/html; charset=utf-8")
        if path == "/email-code-test.html":
            return self._serve_file(
                STATIC_DIR / "email-code-test.html", "text/html; charset=utf-8"
            )
        if path == "/auth-app.html":
            return self._serve_file(
                STATIC_DIR / "auth-app.html", "text/html; charset=utf-8"
            )
        if path == "/auth-app-iphone.html":
            return self._serve_file(
                STATIC_DIR / "auth-app-iphone.html", "text/html; charset=utf-8"
            )
        if path.startswith("/static/"):
            rel = path[len("/static/") :]
            target = (STATIC_DIR / rel).resolve()
            if not str(target).startswith(str(STATIC_DIR.resolve())):
                self._json(404, {"error": "not found"})
                return
            ctype = "application/octet-stream"
            if target.suffix == ".css":
                ctype = "text/css; charset=utf-8"
            elif target.suffix == ".js":
                ctype = "application/javascript; charset=utf-8"
            elif target.suffix == ".html":
                ctype = "text/html; charset=utf-8"
            elif target.suffix == ".webmanifest" or target.name.endswith(".webmanifest"):
                ctype = "application/manifest+json; charset=utf-8"
            elif target.suffix == ".png":
                ctype = "image/png"
            elif target.suffix == ".svg":
                ctype = "image/svg+xml"
            return self._serve_file(target, ctype)
        if path == "/api/vps-status":
            if not self._require_auth(api=True):
                return
            try:
                self._json(200, build_vps_status())
            except Exception as exc:
                self._json(500, {"error": str(exc)})
            return
        if path == "/api/dns-map":
            if not self._require_auth(api=True):
                return
            try:
                self._json(200, build_dns_map())
            except Exception as exc:
                self._json(500, {"error": str(exc)})
            return
        if path == "/api/pihole-sso":
            if not self._require_auth(api=True):
                return
            try:
                self._json(200, pihole_sso_url())
            except Exception as exc:
                self._json(500, {"error": str(exc)})
            return
        if path == "/api/ftp/status":
            if not self._require_auth(api=True):
                return
            self._json(200, ftp_status())
            return
        if path == "/api/ftp/warm":
            if not self._require_auth(api=True):
                return
            try:
                self._json(200, ftp_warm())
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path == "/api/ftp/list":
            if not self._require_auth(api=True):
                return
            try:
                qs = parse_qs(urlparse(self.path).query)
                path_q = (qs.get("path") or ["/"])[0]
                self._json(200, ftp_list(path_q))
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path == "/api/ftp/download":
            if not self._require_auth(api=True):
                return
            try:
                from urllib.parse import quote
                qs = parse_qs(urlparse(self.path).query)
                path_q = (qs.get("path") or [""])[0]
                inline = (qs.get("inline") or ["0"])[0] in ("1", "true", "yes")
                target = ftp_norm_path(path_q)
                if target == "/":
                    raise ValueError("not a file")
                name = target.rsplit("/", 1)[-1] or "download"
                ctype = ftp_guess_mime(name)
                if inline and ctype.startswith("text/") and "charset=" not in ctype:
                    ctype = ctype + "; charset=utf-8"
                # Dedicated FTP session so long media streams do not block list pool.
                ftp = ftp_connect()
                try:
                    size = None
                    try:
                        size = ftp.size(target)
                    except Exception:
                        size = None
                    self.send_response(200)
                    self.send_header("Content-Type", ctype)
                    disp = "inline" if inline else "attachment"
                    self.send_header(
                        "Content-Disposition",
                        f"{disp}; filename*=UTF-8''{quote(name)}",
                    )
                    if size is not None:
                        self.send_header("Content-Length", str(size))
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("X-Content-Type-Options", "nosniff")
                    self.end_headers()
                    ftp.retrbinary(f"RETR {target}", self.wfile.write)
                finally:
                    try:
                        ftp.quit()
                    except Exception:
                        try:
                            ftp.close()
                        except Exception:
                            pass
            except Exception as exc:
                try:
                    self._json(500, {"ok": False, "error": str(exc)})
                except Exception:
                    pass
            return
        if path in (
            "/api/wireguard/config",
            "/download/GL-MT6000-school.conf",
            "/download/wireguard.conf",
        ):
            if not self._require_auth(api=True):
                return
            try:
                from urllib.parse import quote

                body = load_flint_wireguard_conf()
                name = WG_CLIENT_DOWNLOAD_NAME
                self.send_response(200)
                self.send_header("Content-Type", "application/x-wireguard-profile")
                self.send_header(
                    "Content-Disposition",
                    f"attachment; filename=\"{name}\"; filename*=UTF-8''{quote(name)}",
                )
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(body)
            except Exception as exc:
                self._json(404, {"ok": False, "error": str(exc)})
            return
        if path == "/api/openvpn/status":
            if not self._require_auth(api=True):
                return
            try:
                self._json(200, build_openvpn_status())
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path == "/api/ikev2/status":
            if not self._require_auth(api=True):
                return
            try:
                self._json(200, build_ikev2_status())
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path in ("/api/ikev2/windows-ps1", "/download/Setup-ServerManagerVpn.ps1"):
            if not self._require_auth(api=True):
                return
            try:
                from urllib.parse import quote

                body = load_ikev2_windows_ps1()
                name = "Setup-ServerManagerVpn.ps1"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header(
                    "Content-Disposition",
                    f"attachment; filename=\"{name}\"; filename*=UTF-8''{quote(name)}",
                )
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
            except Exception as exc:
                self._json(404, {"ok": False, "error": str(exc)})
            return
        if path in ("/api/ikev2/windows-cmd", "/download/Setup-ServerManagerVpn.cmd"):
            if not self._require_auth(api=True):
                return
            try:
                from urllib.parse import quote

                body = load_ikev2_windows_cmd()
                name = "Setup-ServerManagerVpn.cmd"
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header(
                    "Content-Disposition",
                    f"attachment; filename=\"{name}\"; filename*=UTF-8''{quote(name)}",
                )
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
            except Exception as exc:
                self._json(404, {"ok": False, "error": str(exc)})
            return
        if path in ("/api/ikev2/ca.crt", "/download/ServerManager-IKEv2-CA.crt"):
            if not self._require_auth(api=True):
                return
            try:
                from urllib.parse import quote

                pem = load_ikev2_ca_pem().encode("utf-8")
                if not pem:
                    self._json(404, {"ok": False, "error": "IKEv2 CA not found — run setup-ikev2.sh"})
                    return
                name = "ServerManager-IKEv2-CA.crt"
                self.send_response(200)
                self.send_header("Content-Type", "application/x-x509-ca-cert")
                self.send_header(
                    "Content-Disposition",
                    f"attachment; filename=\"{name}\"; filename*=UTF-8''{quote(name)}",
                )
                self.send_header("Content-Length", str(len(pem)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(pem)
            except Exception as exc:
                self._json(404, {"ok": False, "error": str(exc)})
            return
        if path == "/api/nas/status":
            if not self._require_auth(api=True):
                return
            try:
                self._json(200, build_nas_windows_status())
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path == "/api/nas/download-token":
            if not self._require_auth(api=True):
                return
            try:
                token = issue_nas_download_token()
                urls = build_nas_download_urls(token)
                self._json(
                    200,
                    {
                        "ok": True,
                        "token": token,
                        "expires_in": int(NAS_DL_TOKEN_TTL),
                        **urls,
                    },
                )
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path in ("/api/nas/windows-ps1", "/download/Setup-ServerManagerNas.ps1"):
            query = urlparse(self.path).query
            if not self._nas_download_allowed(query):
                self._unauthorized(api=True)
                return
            try:
                from urllib.parse import quote

                body = load_nas_windows_ps1()
                name = "Setup-ServerManagerNas.ps1"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header(
                    "Content-Disposition",
                    f"attachment; filename=\"{name}\"; filename*=UTF-8''{quote(name)}",
                )
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
            except Exception as exc:
                self._json(404, {"ok": False, "error": str(exc)})
            return
        if path in (
            "/api/nas/windows-setup",
            "/api/nas/windows-cmd",
            "/download/Setup-ServerManagerNas.cmd",
            "/download/Setup-ServerManagerNas-setup.cmd",
        ):
            query = urlparse(self.path).query
            if not self._nas_download_allowed(query):
                self._unauthorized(api=True)
                return
            try:
                from urllib.parse import quote

                body = load_nas_windows_bundle_cmd()
                name = "Setup-ServerManagerNas.cmd"
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header(
                    "Content-Disposition",
                    f"attachment; filename=\"{name}\"; filename*=UTF-8''{quote(name)}",
                )
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
            except Exception as exc:
                self._json(404, {"ok": False, "error": str(exc)})
            return
        if path == "/api/openvpn/clients":
            if not self._require_auth(api=True):
                return
            try:
                self._json(200, {"ok": True, "clients": list_openvpn_clients()})
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc), "clients": []})
            return
        if path.startswith("/api/openvpn/clients/"):
            if not self._require_auth(api=True):
                return
            name = path[len("/api/openvpn/clients/") :].strip("/")
            try:
                from urllib.parse import quote

                filename, body = load_openvpn_client_by_name(name)
                self.send_response(200)
                self.send_header("Content-Type", "application/x-openvpn-profile")
                self.send_header(
                    "Content-Disposition",
                    f"attachment; filename=\"{filename}\"; filename*=UTF-8''{quote(filename)}",
                )
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(body)
            except Exception as exc:
                self._json(404, {"ok": False, "error": str(exc)})
            return
        if path in (
            "/api/openvpn/config",
            "/api/openvpn/flint",
            "/download/flint.ovpn",
            "/download/GL-MT6000.ovpn",
        ):
            if not self._require_auth(api=True):
                return
            try:
                from urllib.parse import quote

                body = load_openvpn_client_conf(OVPN_FLINT_NAME)
                name = "GL-MT6000.ovpn"
                self.send_response(200)
                self.send_header("Content-Type", "application/x-openvpn-profile")
                self.send_header(
                    "Content-Disposition",
                    f"attachment; filename=\"{name}\"; filename*=UTF-8''{quote(name)}",
                )
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(body)
            except Exception as exc:
                self._json(404, {"ok": False, "error": str(exc)})
            return
        if path in (
            "/api/openvpn/phone",
            "/download/james-iphone.ovpn",
        ):
            if not self._require_auth(api=True):
                return
            try:
                from urllib.parse import quote

                body = load_openvpn_client_conf(OVPN_PHONE_NAME)
                name = "james-iphone.ovpn"
                self.send_response(200)
                self.send_header("Content-Type", "application/x-openvpn-profile")
                self.send_header(
                    "Content-Disposition",
                    f"attachment; filename=\"{name}\"; filename*=UTF-8''{quote(name)}",
                )
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(body)
            except Exception as exc:
                self._json(404, {"ok": False, "error": str(exc)})
            return
        if path in (
            "/api/openvpn/windows",
            "/download/windows.ovpn",
        ):
            # Allow either portal login OR shared download token (public Caddy path).
            import hmac

            qs = parse_qs(urlparse(self.path).query)
            token = (qs.get("t") or qs.get("token") or [""])[0].strip()
            token_ok = bool(
                OVPN_WINDOWS_DL_TOKEN
                and token
                and hmac.compare_digest(token, OVPN_WINDOWS_DL_TOKEN)
            )
            if not token_ok and not self._require_auth(api=True):
                return
            try:
                from urllib.parse import quote

                body = load_openvpn_client_conf(OVPN_WINDOWS_NAME)
                name = "windows.ovpn"
                self.send_response(200)
                self.send_header("Content-Type", "application/x-openvpn-profile")
                self.send_header(
                    "Content-Disposition",
                    f"attachment; filename=\"{name}\"; filename*=UTF-8''{quote(name)}",
                )
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(body)
            except Exception as exc:
                self._json(404, {"ok": False, "error": str(exc)})
            return
        if path in (
            "/api/openvpn/allow-ssh",
            "/download/flint-allow-vpn-ssh.sh",
        ):
            if not self._require_auth(api=True):
                return
            try:
                from urllib.parse import quote

                body = load_openvpn_script(OVPN_ALLOW_SSH_SCRIPT)
                name = "flint-allow-vpn-ssh.sh"
                self.send_response(200)
                self.send_header("Content-Type", "text/x-shellscript; charset=utf-8")
                self.send_header(
                    "Content-Disposition",
                    f"attachment; filename=\"{name}\"; filename*=UTF-8''{quote(name)}",
                )
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(body)
            except Exception as exc:
                self._json(404, {"ok": False, "error": str(exc)})
            return
        if path == "/api/buffalo-sso":
            if not self._require_auth(api=True):
                return
            try:
                scope = (parse_qs(urlparse(self.path).query).get("scope") or ["all"])[0]
                data = buffalo_sso_login(scope=scope)
                # Don't echo session secrets back to the browser JSON body.
                safe: dict = {"ok": True, "user": data.get("user")}
                admin = data.get("admin") or {}
                files = data.get("files") or {}
                if admin:
                    safe["admin"] = {"url": admin.get("url")}
                if files:
                    safe["files"] = {"url": files.get("url")}
                self._json(200, safe, extra_cookies=_buffalo_sso_cookie_headers(data))
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path == "/api/router-sso":
            if not self._require_auth(api=True):
                return
            try:
                data = router_sso_login()
                safe = {
                    "ok": True,
                    "user": data.get("user"),
                    "url": data.get("url") or f"https://{ROUTER_PUBLIC_HOST}/",
                }
                self._json(200, safe, extra_cookies=_router_sso_cookie_headers(data))
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path == "/api/wireguard-sso":
            if not self._require_auth(api=True):
                return
            try:
                data = wg_easy_sso_login()
                safe = {
                    "ok": True,
                    "user": data.get("user"),
                    "url": data.get("url") or f"{WG_UI_PREFIX}/",
                }
                self._json(200, safe, extra_cookies=_wg_easy_sso_cookie_headers(data))
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path == "/api/grafana-sso":
            if not self._require_auth(api=True):
                return
            try:
                data = grafana_sso_login()
                safe = {
                    "ok": True,
                    "user": data.get("user"),
                    "url": data.get("url") or f"https://{GRAFANA_PUBLIC_HOST}/",
                }
                self._json(200, safe, extra_cookies=_grafana_sso_cookie_headers(data))
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path == "/api/tailscale":
            if not self._require_auth(api=True):
                return
            try:
                self._json(200, tailscale_status())
            except Exception as exc:
                self._json(500, {"error": str(exc)})
            return
        if path == "/api/surfshark":
            if not self._require_auth(api=True):
                return
            try:
                self._json(200, surfshark_status())
            except Exception as exc:
                self._json(500, {"error": str(exc)})
            return
        if path == "/api/security":
            if not self._require_auth(api=True):
                return
            try:
                status = build_security_status()
                tok = parse_session_cookie(self.headers.get("Cookie"))
                lock = ssh_panel_unlock_status(tok)
                if isinstance(status.get("ssh"), dict):
                    if lock.get("unlocked"):
                        status["ssh"]["panel_lock"] = lock
                    else:
                        # Hide SSH status details until the panel is unlocked.
                        status["ssh"] = {"panel_lock": lock, "ok": True}
                self._json(200, status)
            except Exception as exc:
                self._json(500, {"error": str(exc)})
            return
        if path == "/api/security/ssh-unlock":
            if not self._require_auth(api=True):
                return
            try:
                tok = parse_session_cookie(self.headers.get("Cookie"))
                self._json(200, {"ok": True, **ssh_panel_unlock_status(tok)})
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path == "/api/security/vpn-allowlist":
            if not self._require_auth(api=True):
                return
            try:
                self._json(200, {"ok": True, **build_vpn_allowlist_status()})
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path == "/api/auth-app/enroll-status":
            try:
                self._json(200, {"ok": True, **auth_app_enroll_status()})
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path == "/api/auth-app/vpn-allowlist":
            try:
                qs = parse_qs(urlparse(self.path).query)
                code = (
                    self.headers.get("X-SM-Totp")
                    or (qs.get("code") or [""])[0]
                    or ""
                )
                require_auth_app_totp(str(code))
                # Refresh enrolled-device LAN sticky when Circle is opened.
                lan_hint = _normalize_vpn_ip(
                    self.headers.get("X-SM-Lan-Ip")
                    or (qs.get("lan_ip") or [""])[0]
                    or ""
                )
                if lan_hint and _is_home_lan_ipv4(lan_hint):
                    try:
                        touch_auth_app_device(lan_ip=lan_hint, note="Authenticator Circle")
                    except Exception:
                        pass
                self._json(200, {"ok": True, **build_vpn_allowlist_status(for_auth_app=True)})
            except ValueError as exc:
                self._json(403, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path == "/api/auth-app/register-device":
            try:
                qs = parse_qs(urlparse(self.path).query)
                code = (
                    self.headers.get("X-SM-Totp")
                    or (qs.get("code") or [""])[0]
                    or ""
                )
                require_auth_app_totp(str(code))
                lan_ip = _normalize_vpn_ip(
                    self.headers.get("X-SM-Lan-Ip")
                    or (qs.get("lan_ip") or [""])[0]
                    or ""
                )
                platform = str(
                    self.headers.get("X-SM-Platform")
                    or (qs.get("platform") or [""])[0]
                    or ""
                )
                result = touch_auth_app_device(
                    lan_ip=lan_ip,
                    note="Authenticator app",
                    platform=platform,
                )
                self._json(200, result)
            except ValueError as exc:
                self._json(403, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path in (
            "/api/security/ssh-login",
            "/api/security/ssh-keys",
            "/api/security/ssh-users",
        ):
            if not self._require_auth(api=True):
                return
            try:
                ssh = _security_sshd_config()
                tok = parse_session_cookie(self.headers.get("Cookie"))
                ssh["panel_lock"] = ssh_panel_unlock_status(tok)
                self._json(200, {"ok": True, "ssh": ssh})
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path == "/api/backup":
            if not self._require_auth(api=True):
                return
            try:
                self._json(200, build_backup_status())
            except Exception as exc:
                self._json(500, {"error": str(exc)})
            return
        if path == BUFFALO_PREFIX or path.startswith(BUFFALO_PREFIX + "/"):
            return proxy_buffalo_request(self, "GET")
        if path == NAS_FILES_PREFIX or path.startswith(NAS_FILES_PREFIX + "/"):
            return proxy_nas_files_request(self, "GET")
        if path == WG_UI_PREFIX or path.startswith(WG_UI_PREFIX + "/"):
            return proxy_wg_ui_request(self, "GET")
        self._json(404, {"error": "not found"})

    def do_HEAD(self) -> None:  # noqa: N802
        # WebAccess thumbnails probe with HEAD /rpc/thumbnail/...
        path = urlparse(self.path).path
        if path in (
            "/login.html",
            "/auth-app.html",
            "/auth-app-iphone.html",
            "/api/branding",
            "/api/health",
        ) or path.startswith("/static/"):
            return self.do_GET()
        if path in ("/claim", "/claim/", "/claim/api", "/api/plex/claim"):
            return self.do_GET()
        if not self._is_authed():
            if path.startswith("/api/") or path.startswith("/claim"):
                self._unauthorized(api=True)
            else:
                self._unauthorized(api=False)
            return
        if path == NAS_FILES_PREFIX or path.startswith(NAS_FILES_PREFIX + "/"):
            return proxy_nas_files_request(self, "HEAD")
        if path == BUFFALO_PREFIX or path.startswith(BUFFALO_PREFIX + "/"):
            return proxy_buffalo_request(self, "HEAD")
        if path == WG_UI_PREFIX or path.startswith(WG_UI_PREFIX + "/"):
            return proxy_wg_ui_request(self, "HEAD")
        self.send_response(404)
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path in ("/claim/api", "/api/plex/claim"):
            # Unauthenticated on purpose: used from plex.vpstruelord.com/claim while PMS is unclaimed.
            try:
                payload = self._read_json()
                token = str((payload or {}).get("token") or "").strip()
                result = _plex_claim_via_token(token)
                # Refresh identity
                try:
                    import urllib.request

                    with urllib.request.urlopen(
                        f"http://{PLEX_HOST}:{PLEX_PORT}/identity", timeout=5
                    ) as resp:
                        ident = resp.read().decode("utf-8", errors="replace")
                    result["identity"] = ident[:500]
                    result["claimed"] = 'claimed="1"' in ident or "claimed=\"1\"" in ident
                except Exception:
                    pass
                self._json(200 if result.get("ok") else 400, result)
            except ValueError as exc:
                self._json(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path == "/api/login":
            try:
                payload = self._read_json()
                if not isinstance(payload, dict):
                    payload = {}
                user = str(payload.get("username", "")).strip()
                password = str(payload.get("password", ""))
                code = str(
                    payload.get("code")
                    or payload.get("email_code")
                    or payload.get("app_code")
                    or ""
                ).strip()
                login_token = str(
                    payload.get("login_token") or payload.get("pending_token") or ""
                ).strip()
            except Exception:
                self._json(400, {"error": "invalid json"})
                return
            try:
                if login_token and code:
                    result = complete_portal_login(
                        login_token=login_token,
                        code=code,
                        client_ip=self.client_address[0],
                    )
                    self._json(
                        200,
                        {
                            "ok": True,
                            "user": result.get("user") or AUTH_USER,
                            "message": result.get("message") or "Signed in.",
                        },
                        set_cookie=str(result.get("session") or ""),
                    )
                    return
                if not user or not password:
                    self._json(400, {"error": "Username and password required"})
                    return
                result = begin_portal_login(
                    username=user,
                    password=password,
                    client_ip=self.client_address[0],
                )
                # Never create a session until 2FA succeeds.
                self._json(200, result)
            except PermissionError as exc:
                log_failed_login(self.client_address[0], user or "?")
                time.sleep(0.35)
                self._json(401, {"error": str(exc) or "Invalid username or password"})
            except ValueError as exc:
                time.sleep(0.25)
                self._json(403, {"error": str(exc)})
            except Exception as exc:
                self._json(500, {"error": str(exc)})
            return
        if path == "/api/email-code/send":
            try:
                result = send_email_test_code(self.client_address[0])
                self._json(200, result)
            except ValueError as exc:
                self._json(429, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path == "/api/email-code/verify":
            try:
                payload = self._read_json()
                code = str((payload or {}).get("code") or "")
                result = verify_email_test_code(self.client_address[0], code)
                self._json(200, result)
            except ValueError as exc:
                time.sleep(0.25)
                self._json(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path == "/api/auth-app/vpn-allowlist":
            try:
                payload = self._read_json()
                if not isinstance(payload, dict):
                    payload = {}
                require_auth_app_totp(str(payload.get("code") or ""))
                lan_hint = _normalize_vpn_ip(
                    self.headers.get("X-SM-Lan-Ip") or payload.get("lan_ip") or ""
                )
                if lan_hint and _is_home_lan_ipv4(lan_hint):
                    try:
                        touch_auth_app_device(
                            lan_ip=lan_hint,
                            note="Authenticator Circle",
                            platform=str(payload.get("platform") or ""),
                        )
                    except Exception:
                        pass
                result = mutate_vpn_allowlist(
                    action=str(payload.get("action") or ""),
                    ip=str(payload.get("ip") or ""),
                    note=str(payload.get("note") or "from authenticator app"),
                    source="auth-app",
                )
                self._json(200, result)
            except ValueError as exc:
                time.sleep(0.2)
                self._json(403, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path == "/api/auth-app/register-device":
            try:
                payload = self._read_json()
                if not isinstance(payload, dict):
                    payload = {}
                require_auth_app_totp(str(payload.get("code") or ""))
                lan_ip = _normalize_vpn_ip(
                    self.headers.get("X-SM-Lan-Ip") or payload.get("lan_ip") or ""
                )
                result = touch_auth_app_device(
                    lan_ip=lan_ip,
                    note=str(payload.get("note") or "Authenticator app"),
                    platform=str(payload.get("platform") or ""),
                )
                self._json(200, result)
            except ValueError as exc:
                time.sleep(0.2)
                self._json(403, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path == "/api/logout":
            destroy_session(parse_session_cookie(self.headers.get("Cookie")))
            self._json(200, {"ok": True}, clear_cookie=True)
            return
        if not self._require_auth(api=True):
            return
        if path == "/api/openvpn/clients":
            try:
                payload = self._read_json()
                name = str((payload or {}).get("name") or "").strip()
                redirect = bool((payload or {}).get("redirect_gateway", True))
                result = create_openvpn_client(name, redirect_gateway=redirect)
                self._json(200, result)
            except ValueError as exc:
                self._json(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path == "/api/leds":
            if not self._require_auth(api=True):
                return
            try:
                payload = self._read_json()
                action = ""
                if isinstance(payload, dict):
                    action = str(payload.get("action") or payload.get("state") or "").strip()
                result = leds_set(action)
                self._json(200, result)
            except ValueError as exc:
                self._json(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path == "/api/bluetooth":
            if not self._require_auth(api=True):
                return
            try:
                payload = self._read_json()
                action = ""
                if isinstance(payload, dict):
                    action = str(payload.get("action") or payload.get("owner") or "").strip()
                result = bluetooth_set(action)
                self._json(200, result)
            except ValueError as exc:
                self._json(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path == "/api/xbox":
            if not self._require_auth(api=True):
                return
            try:
                payload = self._read_json()
                action = ""
                if isinstance(payload, dict):
                    action = str(payload.get("action") or payload.get("owner") or "").strip()
                result = xbox_set(action)
                self._json(200, result)
            except ValueError as exc:
                self._json(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path == "/api/elements":
            if not self._require_auth(api=True):
                return
            try:
                payload = self._read_json()
                action = ""
                if isinstance(payload, dict):
                    action = str(
                        payload.get("action") or payload.get("state") or ""
                    ).strip()
                result = elements_set(action)
                self._json(200, result)
            except ValueError as exc:
                self._json(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path == "/api/elements/upload":
            if not self._require_auth(api=True):
                return
            try:
                qs = parse_qs(urlparse(self.path).query)
                library = (qs.get("library") or qs.get("kind") or ["movies"])[0]
                filename = (qs.get("filename") or qs.get("name") or [""])[0]
                process = (qs.get("process") or ["0"])[0] in (
                    "1",
                    "true",
                    "yes",
                    "on",
                )
                length = int(self.headers.get("Content-Length", "0") or 0)
                if length <= 0:
                    raise ValueError("empty upload")
                if length > ELEMENTS_UPLOAD_MAX_BYTES:
                    raise ValueError(
                        f"file too large ({length} bytes; max {ELEMENTS_UPLOAD_MAX_BYTES})"
                    )
                if not filename:
                    filename = self.headers.get("X-Filename") or "upload.bin"
                data = self.rfile.read(length)
                self._json(
                    200,
                    elements_upload_media(
                        library, filename, data, process=process
                    ),
                )
            except ValueError as exc:
                self._json(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path == "/api/settings":
            try:
                payload = self._read_json()
                result = apply_portal_settings(payload if isinstance(payload, dict) else {})
                # Password / logout-all clears sessions — drop this browser cookie too.
                clear = "password" in (result.get("changed") or []) or "sessions" in (
                    result.get("changed") or []
                )
                self._json(
                    200 if result.get("ok") else 400,
                    result,
                    clear_cookie=clear,
                )
            except ValueError as exc:
                self._json(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path == "/api/tailscale":
            try:
                payload = self._read_json()
                result = apply_tailscale(payload if isinstance(payload, dict) else {})
                self._json(200 if result.get("ok") else 400, result)
            except Exception as exc:
                self._json(500, {"error": str(exc)})
            return
        if path == "/api/tailscale/login":
            try:
                self._json(200, tailscale_start_login())
            except Exception as exc:
                self._json(500, {"error": str(exc)})
            return
        if path == "/api/surfshark":
            try:
                payload = self._read_json()
                result = apply_surfshark(payload if isinstance(payload, dict) else {})
                self._json(200 if result.get("ok") else 400, result)
            except Exception as exc:
                self._json(500, {"error": str(exc)})
            return
        if path == "/api/ftp/mkdir":
            try:
                payload = self._read_json()
                self._json(200, ftp_mkdir(str(payload.get("path") or "")))
            except ValueError as exc:
                self._json(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path == "/api/ftp/delete":
            try:
                payload = self._read_json()
                self._json(200, ftp_delete(str(payload.get("path") or "")))
            except ValueError as exc:
                self._json(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path == "/api/ftp/rename":
            try:
                payload = self._read_json()
                self._json(
                    200,
                    ftp_rename(str(payload.get("src") or ""), str(payload.get("dst") or "")),
                )
            except ValueError as exc:
                self._json(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path == "/api/ftp/upload":
            try:
                qs = parse_qs(urlparse(self.path).query)
                path_q = (qs.get("path") or [""])[0]
                length = int(self.headers.get("Content-Length", "0") or 0)
                if length <= 0:
                    raise ValueError("empty upload")
                if length > 512 * 1024 * 1024:
                    raise ValueError("file too large (512MB max)")
                data = self.rfile.read(length)
                self._json(200, ftp_upload_bytes(path_q, data))
            except ValueError as exc:
                self._json(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path == "/api/security/ssh-unlock":
            try:
                payload = self._read_json()
                if not isinstance(payload, dict):
                    payload = {}
                tok = parse_session_cookie(self.headers.get("Cookie"))
                action = str(payload.get("action") or "unlock").strip().lower()
                if action in ("lock", "relock"):
                    result = lock_ssh_panel(tok)
                elif action in ("2fa", "two_factor", "set_2fa"):
                    if not self._require_ssh_panel_unlock():
                        return
                    enabled_raw = payload.get("enabled", payload.get("two_factor_enabled"))
                    if isinstance(enabled_raw, str):
                        enabled = enabled_raw.strip().lower() in ("1", "true", "yes", "on")
                    else:
                        enabled = bool(enabled_raw)
                    result = set_ssh_panel_2fa(
                        tok,
                        enabled=enabled,
                        password=str(
                            payload.get("password") or payload.get("portal_password") or ""
                        ),
                        code=str(
                            payload.get("code")
                            or payload.get("email_code")
                            or payload.get("app_code")
                            or ""
                        ),
                        client_ip=self.client_address[0],
                        method=str(
                            payload.get("method")
                            or payload.get("two_factor_method")
                            or ""
                        ),
                        enroll_secret=str(
                            payload.get("enroll_secret")
                            or payload.get("totp_secret")
                            or ""
                        ),
                    )
                elif action in (
                    "device_enroll",
                    "auth_enroll",
                    "enroll_devices",
                    "new_devices",
                ):
                    if not self._require_ssh_panel_unlock():
                        return
                    unlocked_raw = payload.get(
                        "unlocked",
                        payload.get(
                            "device_enroll_unlocked",
                            payload.get("enroll_unlocked", payload.get("enabled")),
                        ),
                    )
                    if isinstance(unlocked_raw, str):
                        unlocked = unlocked_raw.strip().lower() in (
                            "1",
                            "true",
                            "yes",
                            "on",
                            "unlock",
                        )
                    else:
                        unlocked = bool(unlocked_raw)
                    result = set_auth_app_device_enroll(tok, unlocked=unlocked)
                else:
                    result = unlock_ssh_panel(
                        tok,
                        str(payload.get("password") or payload.get("portal_password") or ""),
                        code=str(
                            payload.get("code")
                            or payload.get("email_code")
                            or payload.get("app_code")
                            or ""
                        ),
                        client_ip=self.client_address[0],
                    )
                # Attach fresh ssh snapshot for UI refresh (read-only).
                ssh = _security_sshd_config()
                lock = ssh_panel_unlock_status(tok)
                if result.get("unlocked") or lock.get("unlocked"):
                    ssh["panel_lock"] = lock
                    result["ssh"] = ssh
                else:
                    # Keep details hidden while locked; still surface 2FA flags.
                    result["ssh"] = {"panel_lock": {**lock, **{
                        k: result[k]
                        for k in (
                            "need_code",
                            "two_factor_enabled",
                            "two_factor_method",
                            "auth_app_path",
                            "email_to",
                        )
                        if k in result
                    }}, "ok": True}
                self._json(200, result)
            except ValueError as exc:
                self._json(403, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path == "/api/security/vpn-allowlist":
            if not self._require_auth(api=True):
                return
            if not self._require_ssh_panel_unlock():
                return
            try:
                payload = self._read_json()
                if not isinstance(payload, dict):
                    payload = {}
                result = mutate_vpn_allowlist(
                    action=str(payload.get("action") or ""),
                    ip=str(payload.get("ip") or ""),
                    note=str(payload.get("note") or ""),
                )
                self._json(200, result)
            except ValueError as exc:
                self._json(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path == "/api/security/ssh-login":
            if not self._require_ssh_panel_unlock():
                return
            try:
                payload = self._read_json()
                if not isinstance(payload, dict):
                    payload = {}
                method = str(
                    payload.get("method")
                    or payload.get("login_method")
                    or payload.get("mode")
                    or ""
                ).strip()
                root = payload.get("permit_root_login")
                if root is None:
                    root = payload.get("root_login")
                if method:
                    result = apply_ssh_login_method(
                        method,
                        permit_root_login=str(root) if root is not None else None,
                    )
                elif root is not None:
                    result = apply_ssh_root_login(str(root))
                else:
                    raise ValueError(
                        "Provide method (password_and_keys|keys_only) "
                        "and/or permit_root_login (yes|prohibit-password|no)"
                    )
                tok = parse_session_cookie(self.headers.get("Cookie"))
                if isinstance(result.get("ssh"), dict):
                    result["ssh"]["panel_lock"] = ssh_panel_unlock_status(tok)
                self._json(200, result)
            except ValueError as exc:
                self._json(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path == "/api/security/ssh-keys":
            if not self._require_ssh_panel_unlock():
                return
            try:
                payload = self._read_json()
                if not isinstance(payload, dict):
                    payload = {}
                action = str(
                    payload.get("action") or payload.get("op") or "add"
                ).strip().lower()
                if action in ("add", "create", "append"):
                    result = add_ssh_authorized_key(
                        str(payload.get("public_key") or payload.get("key") or "")
                    )
                elif action in ("generate", "auto", "auto_create", "autocreate"):
                    result = generate_ssh_authorized_key(
                        comment=str(payload.get("comment") or ""),
                        username=str(payload.get("username") or "root"),
                        also_root=bool(payload.get("also_root")),
                    )
                elif action in ("remove", "delete", "del"):
                    idx = payload.get("index")
                    result = remove_ssh_authorized_key(
                        index=int(idx) if idx is not None and str(idx) != "" else None,
                        fingerprint=(
                            str(payload.get("fingerprint") or "").strip() or None
                        ),
                    )
                else:
                    raise ValueError("action must be add, generate, or remove")
                tok = parse_session_cookie(self.headers.get("Cookie"))
                if isinstance(result.get("ssh"), dict):
                    result["ssh"]["panel_lock"] = ssh_panel_unlock_status(tok)
                self._json(200, result)
            except ValueError as exc:
                self._json(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path == "/api/security/ssh-users":
            if not self._require_ssh_panel_unlock():
                return
            try:
                payload = self._read_json()
                if not isinstance(payload, dict):
                    payload = {}
                result = create_ssh_login_user(
                    str(payload.get("username") or payload.get("user") or ""),
                    sudo=bool(
                        payload.get("sudo", True)
                        if "sudo" in payload
                        else True
                    ),
                    generate_key=bool(
                        payload.get("generate_key", True)
                        if "generate_key" in payload
                        else True
                    ),
                    public_key=str(
                        payload.get("public_key") or payload.get("key") or ""
                    ),
                    comment=str(payload.get("comment") or ""),
                    also_root=bool(payload.get("also_root")),
                )
                tok = parse_session_cookie(self.headers.get("Cookie"))
                if isinstance(result.get("ssh"), dict):
                    result["ssh"]["panel_lock"] = ssh_panel_unlock_status(tok)
                self._json(200, result)
            except ValueError as exc:
                self._json(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path == "/api/backup":
            try:
                payload = self._read_json()
                result = apply_backup_settings(
                    payload if isinstance(payload, dict) else {}
                )
                # Always 200 so the UI can render status + token errors.
                self._json(200, result)
            except ValueError as exc:
                self._json(200, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path == "/api/backup/run":
            try:
                result = run_backup_now()
                # Always 200 so the UI can show stdout/stderr on failure.
                self._json(200, result)
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        if path == "/api/bond":
            try:
                payload = self._read_json()
                result = apply_bond_action(payload if isinstance(payload, dict) else {})
                self._json(200 if result.get("ok") else 400, result)
            except ValueError as exc:
                self._json(400, {"error": str(exc)})
            except Exception as exc:
                self._json(500, {"error": str(exc)})
            return
        if path == BUFFALO_PREFIX or path.startswith(BUFFALO_PREFIX + "/"):
            return proxy_buffalo_request(self, "POST")
        if path == NAS_FILES_PREFIX or path.startswith(NAS_FILES_PREFIX + "/"):
            return proxy_nas_files_request(self, "POST")
        if path == WG_UI_PREFIX or path.startswith(WG_UI_PREFIX + "/"):
            return proxy_wg_ui_request(self, "POST")
        self._json(404, {"error": "not found"})

    def do_PUT(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == WG_UI_PREFIX or path.startswith(WG_UI_PREFIX + "/"):
            if not self._require_auth(api=False):
                return
            return proxy_wg_ui_request(self, "PUT")
        if not self._require_auth(api=True):
            return
        if path == "/api/lan-aliases":
            try:
                payload = self._read_json()
                result = set_lan_alias(
                    ip=str(payload.get("ip") or ""),
                    mac=str(payload.get("mac") or ""),
                    name=str(payload.get("name") or ""),
                )
                self._json(200, result)
            except ValueError as exc:
                self._json(400, {"error": str(exc)})
            except Exception as exc:
                self._json(500, {"error": str(exc)})
            return
        if path != "/api/forwards":
            self._json(404, {"error": "not found"})
            return
        try:
            payload = self._read_json()
            # Backward compatible: flat {rules} => vps only payload shape
            if "vps" not in payload and "rules" in payload:
                payload = {
                    "vps": {"rules": payload.get("rules"), "comments": payload.get("comments")},
                    "router": payload.get("router") or {},
                }
            result = write_and_apply(payload)
            # Ensure JSON-serializable summary always includes a top-level error hint
            if not result.get("ok"):
                bits = []
                for key in ("vps", "router", "hookups", "firewall"):
                    part = result.get(key) or {}
                    if part.get("ok") is False:
                        bits.append(
                            f"{key}: {(part.get('stderr') or part.get('stdout') or 'failed')[-500:]}"
                        )
                if bits and not result.get("error"):
                    result["error"] = " | ".join(bits)
            self._json(200 if result["ok"] else 500, result)
        except ValueError as exc:
            self._json(400, {"error": str(exc)})
        except Exception as exc:
            self._json(500, {"error": str(exc)})

    def do_DELETE(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == WG_UI_PREFIX or path.startswith(WG_UI_PREFIX + "/"):
            if not self._require_auth(api=False):
                return
            return proxy_wg_ui_request(self, "DELETE")
        if not self._require_auth(api=True):
            return
        if path.startswith("/api/openvpn/clients/"):
            name = path[len("/api/openvpn/clients/") :].strip("/")
            try:
                self._json(200, revoke_openvpn_client(name))
            except ValueError as exc:
                self._json(400, {"ok": False, "error": str(exc)})
            except Exception as exc:
                self._json(500, {"ok": False, "error": str(exc)})
            return
        self._json(404, {"error": "not found"})

    def do_PATCH(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == WG_UI_PREFIX or path.startswith(WG_UI_PREFIX + "/"):
            if not self._require_auth(api=False):
                return
            return proxy_wg_ui_request(self, "PATCH")
        self._json(404, {"error": "not found"})

    def _serve_file(self, path: Path, content_type: str) -> None:
        if not path.is_file():
            self._json(404, {"error": "not found"})
            return
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)


def main() -> None:
    require_auth_configured()
    if not APPLY_SCRIPT.is_file():
        raise SystemExit(f"Apply script missing: {APPLY_SCRIPT}")
    # Ensure sshpass exists
    if subprocess.run(["bash", "-lc", "command -v sshpass"], capture_output=True).returncode != 0:
        raise SystemExit("sshpass is required on the VPS (apt install sshpass)")
    if TS_HOST_PROTECT_SCRIPT.is_file():
        try:
            stj = _tailscale_status_json()
            if str(stj.get("BackendState") or "") == "Running":
                set_ts_host_protect(True)
        except Exception:
            pass
    # School OpenVPN: prefer tun0 for home LAN + allow Flint OVPN→LAN (Buffalo).
    try:
        if _ovpn_flint_connected():
            ensure_ovpn_home_lan_routes()
            threading.Thread(
                target=lambda: ensure_flint_ovpn_lan_access(force=True),
                name="flint-ovpn-lan",
                daemon=True,
            ).start()
    except Exception:
        pass
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"ServerManager panel on http://{HOST}:{PORT}")
    print(f"  title:    {PANEL_TITLE}")
    print(f"  vps conf: {CONF_PATH}")
    print(f"  router:   {ROUTER_USER}@{ROUTER_HOST}:{ROUTER_CONF}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
