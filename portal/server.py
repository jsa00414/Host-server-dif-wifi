#!/usr/bin/env python3
"""ServerManager panel — VPS forwards, GL.iNet router, domains, firewall."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import shlex
import subprocess
import syslog
import tempfile
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

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


def log_failed_login(ip: str, user: str, reason: str = "bad password") -> None:
    try:
        syslog.openlog("port-forward-ui", syslog.LOG_PID, syslog.LOG_AUTH)
        syslog.syslog(syslog.LOG_WARNING, f"Failed login attempt from {ip} user={user} reason={reason}")
    except OSError:
        pass


ROUTER_HOST = os.environ.get("ROUTER_HOST", "192.168.8.1")
ROUTER_HOSTS = [
    h.strip()
    for h in os.environ.get("ROUTER_HOSTS", "10.8.0.3,192.168.8.1").split(",")
    if h.strip()
]
if ROUTER_HOST not in ROUTER_HOSTS:
    ROUTER_HOSTS.insert(0, ROUTER_HOST)
ROUTER_USER = os.environ.get("ROUTER_USER", "root")
ROUTER_CONF = os.environ.get("ROUTER_CONF", "/etc/config/port_forward")


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
    "10.8.0.0/24 10.42.42.0/24 192.168.8.0/24 10.9.0.0/24 100.64.0.0/10 172.18.0.1/32 127.0.0.1/32",
)
VPN_UFW_FROM = os.environ.get("VPN_UFW_FROM", "10.8.0.0/24")
PIHOLE_SSO_SECRET = os.environ.get("PIHOLE_SSO_SECRET", "").strip()
PIHOLE_SSO_URL = os.environ.get(
    "PIHOLE_SSO_URL", "https://pihole.vpstruelord.com/sm-autologin"
).strip()

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
    reserved = {22, 25, 80, 443, 465, 587, 993, 5000, 5001, 5002}
    protected_pubs = {8080, 8443}
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
        # Keep protected admin HTTP/HTTPS public ports immutable
        if pub in protected_pubs and not external:
            expected = {
                8080: ("tcp", "192.168.8.1", 80, "flint-http"),
                8443: ("tcp", "192.168.8.1", 443, "flint-https"),
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
    proc = subprocess.run(
        ["ufw", "status"],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
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
    per_host = max(3, min(6, timeout // max(1, len(ROUTER_HOSTS))))
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
        for host in ROUTER_HOSTS:
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
        by_ip[ip] = {"hostname": name, "mac": mac_s}
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
        if not cur:
            by_ip[ip] = {
                "ip": ip,
                "mac": mac,
                "hostname": name,
                "source": "gl",
                "named_by": "gl" if name else "",
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
    by_pub[8443] = {
        "pub": 8443,
        "proto": "tcp",
        "dest_ip": "192.168.8.1",
        "dest_port": 443,
        "name": "flint-https",
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


def default_hookups() -> list[dict]:
    return []


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
        cleaned.append(
            {
                "enabled": enabled,
                "domain": domain,
                "target_host": target_host,
                "target_port": target_port,
                "name": name,
                "external": external,
                "vpn_only": vpn_only,
            }
        )
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
        lines.append(f"{r['domain']} {{")
        lines.append("\tencode gzip")
        if r.get("vpn_only"):
            # VPN hairpin: wg clients reach VPS:443 with source 10.8.x (requires CF DNS-only).
            lines.append(f"\t@vpn_clients remote_ip {VPN_CLIENT_CIDRS}")
            lines.append("\thandle @vpn_clients {")
            lines.append(f"\t\treverse_proxy {r['target_host']}:{r['target_port']}")
            lines.append("\t}")
            lines.append("\thandle {")
            lines.append('\t\trespond "Forbidden" 403')
            lines.append("\t}")
        else:
            # Public: plain reverse_proxy only — no client_ip matcher residue.
            lines.append(f"\treverse_proxy {r['target_host']}:{r['target_port']}")
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
    # Reload first (picks up new site blocks), then restart if certs still missing.
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
    still = [d for d in need if not _caddy_domain_has_cert(d)]
    if still:
        logs.append(f"Restarting {CADDY_CONTAINER} to force ACME for: {', '.join(still)}")
        subprocess.run(
            ["docker", "restart", CADDY_CONTAINER],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        time.sleep(3)

    deadline = time.time() + 90
    pending = list(need)
    while pending and time.time() < deadline:
        pending = [d for d in pending if not _caddy_domain_has_cert(d)]
        if not pending:
            break
        time.sleep(3)

    ok = True
    for domain in need:
        if _caddy_domain_has_cert(domain):
            probe = "https ok" if _https_probe_ok(domain) else "cert present (https still warming)"
            logs.append(f"{domain}: {probe}")
        else:
            ok = False
            logs.append(f"{domain}: certificate not issued yet — check DNS and Caddy logs")

    if warnings:
        logs.extend(f"WARN: {w}" for w in warnings)
    return ok, "\n".join(logs), "\n".join(warnings)


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
    cleaned = validate_hookups(rules)
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
    # VPN on/off and enable toggles must not leave stale client_ip routes.
    # Restart whenever the managed block changed, or whenever reload failed.
    if block_changed or reload.returncode != 0:
        rst = subprocess.run(
            ["docker", "restart", CADDY_CONTAINER],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        restart_out = (rst.stdout or "") + (rst.stderr or "")
        time.sleep(3)
        # Confirm container is up; reload is optional after restart (config loaded at start)
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
                stdout=(reload.stdout or "") + "\nCaddy restarted to apply VPN/public mode\n",
                stderr=reload.stderr or "",
            )
        else:
            reload = subprocess.CompletedProcess(
                args=reload.args,
                returncode=1,
                stdout=reload.stdout or "",
                stderr=(reload.stderr or "") + "\nCaddy restart failed\n" + restart_out,
            )

    # Persist JSON only after Caddy accepted the new config (keeps UI in sync)
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
    ok = reload.returncode == 0 and cert_ok and dns_ok and coredns_ok
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


UFW_PROTECTED = {
    (22, "tcp"),  # SSH
    (5002, "tcp"),  # this admin UI
    (5000, "udp"),  # WireGuard tunnel
}

UFW_ROW_RE = re.compile(
    r"^\[\s*(?P<num>\d+)\]\s+(?P<to>.+?)\s{2,}(?P<action>ALLOW IN|DENY IN|REJECT IN)\s{2,}"
    r"(?P<frm>.+?)(?:\s+#\s*(?P<comment>.*))?$"
)


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


def _is_vpn_ufw_from(frm: str) -> bool:
    f = (frm or "").lower().replace(" ", "")
    if f.startswith("anywhere"):
        return False
    return VPN_UFW_FROM.replace(" ", "") in f or f.startswith("10.8.0.")


def read_firewall_state() -> dict:
    verbose = subprocess.run(
        ["ufw", "status", "verbose"],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    numbered = subprocess.run(
        ["ufw", "status", "numbered"],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
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
        if "ALLOW" not in m.group("action"):
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
        rules.append(
            {
                "id": int(m.group("num")),
                "port": port,
                "proto": proto,
                "action": "allow",
                "from": "Anywhere" if frm.lower().startswith("anywhere") else frm,
                "comment": comment,
                "to": to_disp,
                "locked": locked,
                "vpn_only": vpn_only,
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
        if action not in ("allow",):
            raise ValueError(f"Firewall rule {i + 1}: only allow rules are supported")
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
            vpn_only = False  # never VPN-restrict SSH / UI / WG listen
        cleaned.append(
            {
                "port": port,
                "proto": proto,
                "action": action,
                "comment": comment,
                "locked": locked,
                "vpn_only": vpn_only,
            }
        )
    # Ensure protected rules always remain (public)
    for port, proto in UFW_PROTECTED:
        if (port, proto) not in seen:
            labels = {
                (22, "tcp"): "SSH",
                (5002, "tcp"): "Port forward UI",
                (5000, "udp"): "WireGuard VPN tunnel",
            }
            cleaned.append(
                {
                    "port": port,
                    "proto": proto,
                    "action": "allow",
                    "comment": labels.get((port, proto), f"protected-{port}"),
                    "locked": True,
                    "vpn_only": False,
                }
            )
    return cleaned


def _ufw_allow_cmd(rule: dict) -> list[str]:
    port = rule["port"]
    proto = rule["proto"]
    comment = rule["comment"]
    if rule.get("vpn_only") and (port, proto) not in UFW_PROTECTED:
        return [
            "ufw",
            "allow",
            "from",
            VPN_UFW_FROM,
            "to",
            "any",
            "port",
            str(port),
            "proto",
            proto,
            "comment",
            comment,
        ]
    return ["ufw", "allow", f"{port}/{proto}", "comment", comment]


def write_firewall_state(rules: list[dict]) -> dict:
    desired = validate_firewall_rules(rules)
    desired_keys = {(r["port"], r["proto"]): r for r in desired}
    logs: list[str] = []

    # Delete current IPv4/v6 rules that are unwanted or need recreate (vpn_only change)
    numbered = subprocess.run(
        ["ufw", "status", "numbered"],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
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

    # Delete from highest number so indices stay stable
    for num, port, proto, _ipv6, cur_vpn in sorted(rows, key=lambda x: x[0], reverse=True):
        if (port, proto) in UFW_PROTECTED:
            continue
        want = desired_keys.get((port, proto))
        if want is None:
            pass  # delete
        elif bool(want.get("vpn_only")) == bool(cur_vpn):
            continue  # keep matching rule
        # else recreate (vpn_only flipped)
        proc = subprocess.run(
            ["ufw", "--force", "delete", str(num)],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        logs.append(
            f"delete {num} {port}/{proto}: rc={proc.returncode} {(proc.stdout or proc.stderr or '').strip()}"
        )

    # Refresh and add missing / recreated
    after = read_firewall_state()
    have = {
        (r["port"], r["proto"]): bool(r.get("vpn_only")) for r in after["rules"]
    }
    for key, rule in desired_keys.items():
        if key in have and have[key] == bool(rule.get("vpn_only")):
            continue
        proc = subprocess.run(
            _ufw_allow_cmd(rule),
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        scope = "vpn" if rule.get("vpn_only") else "public"
        logs.append(
            f"allow {rule['port']}/{rule['proto']} ({scope}): rc={proc.returncode} {(proc.stdout or proc.stderr or '').strip()}"
        )

    # Ensure ufw enabled with deny incoming
    subprocess.run(["ufw", "--force", "enable"], capture_output=True, text=True, timeout=20)
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
    """Route WireGuard via Tailscale exit; keep VPS public IP on main table."""
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
    exit_ip = str(vpn_exit.get("exit_ip") or prefs.get("ExitNodeIP") or "").strip()
    # Prefer our VPN-only state; fall back to live Tailscale prefs
    custom_exit = bool(vpn_exit.get("enabled")) or bool(exit_ip or prefs.get("ExitNodeID"))
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


def build_backup_status() -> dict:
    """GitHub backup agent status for the Backup portal tab (never returns the token)."""
    installed = BACKUP_SCRIPT.is_file()
    secrets_ok = BACKUP_SECRETS.is_file()
    env = _parse_env_file(BACKUP_SECRETS) if secrets_ok else {}
    owner = (env.get("GITHUB_OWNER") or "").strip()
    repo = (env.get("GITHUB_REPO") or "").strip()
    branch = (env.get("GITHUB_BRANCH") or "main").strip() or "main"
    backup_name = (env.get("BACKUP_NAME") or "vps").strip() or "vps"
    has_token = bool((env.get("GITHUB_TOKEN") or "").strip())
    configured = installed and secrets_ok and bool(owner and repo and has_token)

    log_text = _read_text(str(BACKUP_LOG))
    lines = [ln for ln in log_text.splitlines() if ln.strip()]
    log_tail = "\n".join(lines[-50:])
    last_ok = None
    last_message = ""
    last_at = ""
    for line in reversed(lines):
        if "Pushed backup" in line:
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

    return {
        "ok": configured and last_ok is not False,
        "installed": installed,
        "configured": configured,
        "has_token": has_token,
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


def run_backup_now() -> dict:
    """Run sm-backup.sh once; returns status + command output."""
    if not BACKUP_SCRIPT.is_file():
        return {"ok": False, "error": "Backup agent not installed on this VPS"}
    if not BACKUP_SECRETS.is_file():
        return {"ok": False, "error": "Missing /opt/servermanager-backup/secrets.env"}
    if _backup_running():
        return {"ok": False, "error": "A backup is already running", "status": build_backup_status()}

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
                "status": build_backup_status(),
            }
        stdout = (stdout or "").strip()
        stderr = (stderr or "").strip()
        env = _parse_env_file(BACKUP_SECRETS)
        tok = (env.get("GITHUB_TOKEN") or "").strip()
        if tok:
            stdout = stdout.replace(tok, "***")
            stderr = stderr.replace(tok, "***")
        ok = proc.returncode == 0
        return {
            "ok": ok,
            "exit_code": proc.returncode,
            "stdout": stdout[-8000:],
            "stderr": stderr[-4000:],
            "status": build_backup_status(),
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc), "status": build_backup_status()}
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
    public_ip = (os.environ.get("VPS_PUBLIC_IP") or "").strip() or "74.208.54.132"

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
    - Custom Exit Node routes *WireGuard VPN* (10.8.0.0/24) via the chosen
      Tailscale exit; it does not steal the VPS management path.
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

    def _json(self, code: int, payload: dict, *, set_cookie: str | None = None, clear_cookie: bool = False) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if set_cookie:
            self.send_header("Set-Cookie", _cookie_set_header(set_cookie))
        if clear_cookie:
            self.send_header("Set-Cookie", _cookie_clear_header())
        self.end_headers()
        self.wfile.write(body)

    def _is_authed(self) -> bool:
        if check_basic_auth(self.headers.get("Authorization")):
            return True
        return session_valid(parse_session_cookie(self.headers.get("Cookie")))

    def _require_auth(self, *, api: bool = True) -> bool:
        if self._is_authed():
            return True
        self._unauthorized(api=api)
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
        if path in ("/login.html", "/api/branding", "/api/health") or path.startswith("/static/"):
            pass  # public
        elif not self._is_authed():
            if path.startswith("/api/"):
                self._unauthorized(api=True)
            else:
                self._unauthorized(api=False)
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
        if path == "/login.html":
            # Always clear any stale session display path; if still authed, go home
            if self._is_authed():
                self.send_response(302)
                self.send_header("Location", "/")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                return
            return self._serve_file(STATIC_DIR / "login.html", "text/html; charset=utf-8")
        if path.startswith("/static/"):
            rel = path[len("/static/") :]
            target = (STATIC_DIR / rel).resolve()
            if not str(target).startswith(str(STATIC_DIR.resolve())):
                self._json(404, {"error": "not found"})
                return
            ctype = "text/css" if target.suffix == ".css" else "application/javascript"
            if target.suffix == ".html":
                ctype = "text/html; charset=utf-8"
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
        if path == "/api/backup":
            if not self._require_auth(api=True):
                return
            try:
                self._json(200, build_backup_status())
            except Exception as exc:
                self._json(500, {"error": str(exc)})
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/api/login":
            try:
                payload = self._read_json()
                user = str(payload.get("username", "")).strip()
                password = str(payload.get("password", ""))
            except Exception:
                self._json(400, {"error": "invalid json"})
                return
            if not check_credentials(user, password):
                log_failed_login(self.client_address[0], user or "?")
                time.sleep(0.35)
                self._json(401, {"error": "Invalid username or password"})
                return
            token = create_session()
            self._json(200, {"ok": True, "user": AUTH_USER}, set_cookie=token)
            return
        if path == "/api/logout":
            destroy_session(parse_session_cookie(self.headers.get("Cookie")))
            self._json(200, {"ok": True}, clear_cookie=True)
            return
        if not self._require_auth(api=True):
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
        if path == "/api/backup/run":
            try:
                result = run_backup_now()
                self._json(200 if result.get("ok") else 400, result)
            except Exception as exc:
                self._json(500, {"error": str(exc)})
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
        self._json(404, {"error": "not found"})

    def do_PUT(self) -> None:  # noqa: N802
        if not self._require_auth(api=True):
            return
        path = urlparse(self.path).path
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
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"ServerManager panel on http://{HOST}:{PORT}")
    print(f"  title:    {PANEL_TITLE}")
    print(f"  vps conf: {CONF_PATH}")
    print(f"  router:   {ROUTER_USER}@{ROUTER_HOST}:{ROUTER_CONF}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
