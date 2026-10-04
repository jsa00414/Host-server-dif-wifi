#!/usr/bin/env bash
# Sync Caddy @vpn_clients with the VPN trust circle (allowlisted sticky WAN IPs).
#
# Active IKEv2 peer WANs are NO LONGER auto-added. Unapproved peers still get
# internet (FORWARD/MASQ) but stay out of @vpn_clients until an operator
# approves them in Security → VPN trust circle (Authenticator unlock required).
# Guest DNS for unapproved VIPs is applied by ensure-vpn-client-gate.sh.
set -euo pipefail

CADDYFILE="${CADDYFILE:-/opt/truemail/Caddyfile}"
ENV_FILE="${PORTAL_ENV_FILE:-/opt/wireguard/port-forward-ui.env}"
STATE_DIR="${IKEV2_PEER_ACL_DIR:-/var/lib/servermanager}"
STATE_FILE="${STATE_DIR}/ikev2-peer-ips.txt"
STICKY_FILE="${STICKY_VPN_IPS_FILE:-/opt/servermanager/panel/caddy-sticky-vpn-ips.txt}"
ALLOWLIST_FILE="${VPN_ALLOWLIST_FILE:-/opt/servermanager/panel/vpn-allowlist.json}"
GATE_SCRIPT="${VPN_CLIENT_GATE_SCRIPT:-/opt/ikev2/ensure-vpn-client-gate.sh}"
LAN_GATE_SCRIPT="${LAN_CIRCLE_FLINT_GATE_SCRIPT:-/opt/ikev2/ensure-lan-circle-flint-gate.sh}"
# No blanket 192.168.8.0/24 — only approved LAN /32s enter @vpn_clients.
# Pending/denied LAN clients are blocked on Flint pre-NAT (see ensure-lan-circle-flint-gate.sh).
BASE_CIDRS_DEFAULT="10.8.0.0/24 10.42.42.0/24 10.9.0.0/24 10.10.0.0/24 100.64.0.0/10 127.0.0.1/32 74.208.76.213/32 10.11.0.1/32"

export CADDYFILE PORTAL_ENV_FILE="$ENV_FILE" STATE_FILE STICKY_FILE ALLOWLIST_FILE BASE_CIDRS_DEFAULT

mkdir -p "$STATE_DIR" "$(dirname "$STICKY_FILE")" "$(dirname "$ALLOWLIST_FILE")"

python3 - <<'PY'
import json
import os
import re
import subprocess
import time
from pathlib import Path

caddyfile = Path(os.environ.get("CADDYFILE", "/opt/truemail/Caddyfile"))
env_file = Path(os.environ.get("PORTAL_ENV_FILE", "/opt/wireguard/port-forward-ui.env"))
state_file = Path(os.environ.get("STATE_FILE", "/var/lib/servermanager/ikev2-peer-ips.txt"))
sticky_file = Path(
    os.environ.get("STICKY_FILE", "/opt/servermanager/panel/caddy-sticky-vpn-ips.txt")
)
allow_file = Path(
    os.environ.get("ALLOWLIST_FILE", "/opt/servermanager/panel/vpn-allowlist.json")
)
base_default = os.environ.get(
    "BASE_CIDRS_DEFAULT",
    "10.8.0.0/24 10.42.42.0/24 10.9.0.0/24 10.10.0.0/24 100.64.0.0/10 127.0.0.1/32 74.208.76.213/32 10.11.0.1/32",
)
now = int(time.time())

PRIVATE = [
    re.compile(r"^10\."),
    re.compile(r"^127\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[0-1])\."),
    re.compile(r"^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\."),
]


def is_public_ipv4(ip: str) -> bool:
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
        return False
    return not any(p.match(ip) for p in PRIVATE)


def is_home_lan_ipv4(ip: str) -> bool:
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip or ""):
        return False
    parts = [int(x) for x in ip.split(".")]
    if parts[0] != 192 or parts[1] != 168 or parts[2] != 8:
        return False
    return parts[3] not in (0, 1, 255)


def normalize_ip(raw: str) -> str:
    raw = (raw or "").strip()
    if "/" in raw:
        raw = raw.split("/", 1)[0]
    return raw


def denied_ips() -> set[str]:
    """Shared campus/ISP egress that must never enter @vpn_clients."""
    raw = os.environ.get("VPN_CIRCLE_DENIED_IPS", "192.81.235.246")
    out: set[str] = set()
    for part in re.split(r"[\s,;]+", raw):
        ip = normalize_ip(part)
        if ip and is_public_ipv4(ip) and ip != "74.208.76.213":
            out.add(ip)
    return out


DENIED_IPS = denied_ips()


def ensure_denied_wan_blocks(text: str) -> tuple[str, bool]:
    """Keep site-level @denied_wan handles on portal + router (incl. auth-app)."""
    if not DENIED_IPS:
        return text, False
    denied_s = " ".join(f"{ip}/32" for ip in sorted(DENIED_IPS))
    changed = False
    for site in ("portal.vpstruelord.com", "router.vpstruelord.com"):
        marker = f"{site} {{"
        start = text.find(marker)
        if start < 0:
            continue
        brace = text.find("{", start)
        # end of this site block (naive: next top-level site or EOF) — only need head
        window = text[brace + 1 : brace + 280]
        if f"@denied_wan client_ip {denied_s}" in window or (
            "@denied_wan client_ip" in window
            and all(f"{ip}/32" in window for ip in DENIED_IPS)
        ):
            continue
        insert = (
            f"\n\t# Hard-deny shared campus/ISP egress (never trust; includes auth-app).\n"
            f"\t@denied_wan client_ip {denied_s}\n"
            f"\thandle @denied_wan {{\n"
            f'\t\trespond "Forbidden" 403\n'
            f"\t}}\n"
        )
        text = text[: brace + 1] + insert + text[brace + 1 :]
        changed = True
    return text, changed


def peer_ips() -> list[str]:
    try:
        out = subprocess.check_output(
            ["ipsec", "statusall"], text=True, stderr=subprocess.STDOUT
        )
    except Exception:
        try:
            out = subprocess.check_output(
                ["ipsec", "status"], text=True, stderr=subprocess.STDOUT
            )
        except Exception:
            return []
    found = []
    for m in re.finditer(r"\.\.\.(\d{1,3}(?:\.\d{1,3}){3})\[", out):
        ip = m.group(1)
        if is_public_ipv4(ip) and ip not in found:
            found.append(ip)
    return found


def load_sticky_cidrs() -> list[str]:
    out: list[str] = []
    if not sticky_file.is_file():
        return out
    for line in sticky_file.read_text().splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        if "/" not in raw:
            raw = f"{raw}/32"
        if raw not in out:
            out.append(raw)
    return out


def row_is_sealed(row: dict) -> bool:
    if bool(row.get("sealed")):
        return True
    return str(row.get("source") or "") == "router" and "sealed" in str(
        row.get("note") or ""
    ).lower()


def row_has_key(row: dict) -> bool:
    return bool(str(row.get("pubkey") or "").strip())


def row_is_circle_trusted(row: dict) -> bool:
    """Circle membership is key-bound only (except sealed router WAN)."""
    return row_is_sealed(row) or row_has_key(row)


def load_allowlist_ips() -> set[str]:
    """Public sealed / key-bound WAN IPs that belong in @vpn_clients."""
    ips: set[str] = set()
    if not allow_file.is_file():
        return ips
    try:
        data = json.loads(allow_file.read_text(encoding="utf-8"))
    except Exception:
        return ips
    for row in data.get("allowed") or []:
        if not isinstance(row, dict):
            continue
        ip = normalize_ip(row.get("ip", ""))
        if ip and is_public_ipv4(ip) and row_is_circle_trusted(row):
            ips.add(ip)
    # Always keep sealed router WANs (env override) even if JSON was wiped.
    # Home Wi-Fi NATs here; per-device pending is enforced on Flint pre-NAT.
    sealed_raw = os.environ.get("VPN_CIRCLE_SEALED_IPS", "")
    for part in re.split(r"[\s,;]+", sealed_raw):
        ip = normalize_ip(part)
        if ip and is_public_ipv4(ip):
            ips.add(ip)
    return ips


def load_allowlist_lan_ips() -> set[str]:
    """Key-bound home-LAN client /32s (not the whole /24)."""
    ips: set[str] = set()
    if not allow_file.is_file():
        return ips
    try:
        data = json.loads(allow_file.read_text(encoding="utf-8"))
    except Exception:
        return ips
    for row in data.get("allowed") or []:
        if not isinstance(row, dict):
            continue
        ip = normalize_ip(row.get("ip", ""))
        if ip and is_home_lan_ipv4(ip) and row_has_key(row):
            ips.add(ip)
    return ips


def ensure_allowlist_seeded(sticky: list[str]) -> set[str]:
    """Ensure sealed WANs exist; scrub keyless; return trusted allowed IP set.

    Sticky file alone must NOT re-admit IPs without an Ed25519 pubkey.
    """
    allowed = load_allowlist_ips()
    data = {"allowed": [], "denied": [], "attempts": [], "pending": []}
    if allow_file.is_file():
        try:
            loaded = json.loads(allow_file.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                for key in data:
                    if isinstance(loaded.get(key), list):
                        data[key] = loaded[key]
        except Exception:
            pass
    changed = False
    sealed_raw = os.environ.get("VPN_CIRCLE_SEALED_IPS", "")
    sealed_ips = []
    for part in re.split(r"[\s,;]+", sealed_raw):
        ip = normalize_ip(part)
        if ip and is_public_ipv4(ip) and ip not in sealed_ips:
            sealed_ips.append(ip)

    by_ip = {
        normalize_ip(r.get("ip", "")): dict(r)
        for r in (data.get("allowed") or [])
        if isinstance(r, dict) and normalize_ip(r.get("ip", ""))
    }
    # Drop obsolete sealed rows when VPN_CIRCLE_SEALED_IPS no longer includes them.
    # Also drop permanently denied shared-egress IPs (campus NAT, etc.).
    for ip, row in list(by_ip.items()):
        if ip in DENIED_IPS:
            del by_ip[ip]
            changed = True
            continue
        if ip in sealed_ips:
            continue
        if row.get("sealed") or (
            str(row.get("source") or "") == "router"
            and "sealed" in str(row.get("note") or "").lower()
        ):
            del by_ip[ip]
            changed = True
    for ip in sealed_ips:
        if ip in DENIED_IPS:
            continue
        row = by_ip.get(ip) or {
            "ip": ip,
            "note": "Flint router WAN (sealed)",
            "approved_at": now,
            "source": "router",
            "sealed": True,
            "hidden": True,
        }
        before = dict(row)
        row.update(
            {
                "ip": ip,
                "sealed": True,
                "hidden": True,
                "source": "router",
                "note": row.get("note")
                if str(row.get("note") or "").strip()
                and "seeded from sticky" not in str(row.get("note") or "")
                else "Flint router WAN (sealed)",
            }
        )
        if not row.get("approved_at"):
            row["approved_at"] = now
        by_ip[ip] = row
        if before != row or ip not in allowed:
            changed = True
        allowed.add(ip)

    # Demote non-sealed keyless rows to pending (do not sticky-seed them back).
    pending = [r for r in (data.get("pending") or []) if isinstance(r, dict)]
    pending_ips = {normalize_ip(r.get("ip", "")) for r in pending}
    for ip, row in list(by_ip.items()):
        if ip in sealed_ips or row_is_circle_trusted(row):
            continue
        del by_ip[ip]
        changed = True
        allowed.discard(ip)
        if ip and ip not in pending_ips:
            pend = {
                "ip": ip,
                "status": "pending",
                "first_seen": int(row.get("approved_at") or now),
                "last_seen": now,
                "count": 1,
                "note": "needs key bind · removed from circle (key required)",
                "source": "key-required",
                "vip": "",
            }
            if is_home_lan_ipv4(ip):
                pend["kind"] = "lan"
            name = str(row.get("name") or row.get("hostname") or "").strip()
            if name:
                pend["name"] = name[:64]
                pend["hostname"] = name[:64]
            pending.append(pend)
            pending_ips.add(ip)
    data["pending"] = pending

    # sticky arg is ignored for seeding — kept for call-site compatibility.
    _ = sticky

    if changed or not allow_file.is_file():
        rebuilt = []
        seen = set()
        for ip in sealed_ips:
            if ip in by_ip:
                rebuilt.append(by_ip[ip])
                seen.add(ip)
        for ip, row in by_ip.items():
            if ip in seen:
                continue
            rebuilt.append(row)
            seen.add(ip)
        data["allowed"] = rebuilt
        allow_file.parent.mkdir(parents=True, exist_ok=True)
        allow_file.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
        try:
            os.chmod(allow_file, 0o600)
        except Exception:
            pass
        # Keep sticky file aligned: sealed + key-bound only.
        sticky_file.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            "# Managed by vpn allowlist — key-bound sticky WAN + LAN IPs",
            "# Key-bound only (except sealed router WAN).",
            "# one IPv4 /32 per line",
        ]
        for row in rebuilt:
            ip = normalize_ip(row.get("ip", ""))
            if not ip or not (is_public_ipv4(ip) or is_home_lan_ipv4(ip)):
                continue
            if row_is_circle_trusted(row):
                lines.append(f"{ip}/32")
        sticky_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {ip for ip in allowed if ip and is_public_ipv4(ip)}


def vpn_clients_cidrs_in_caddy(text: str) -> set[str]:
    """CIDRs currently present on live @vpn_clients matcher lines (ignore comments)."""
    found: set[str] = set()
    for m in re.finditer(
        r"^[ \t]*@vpn_clients (?:client_ip|remote_ip) (.+)$", text, re.M
    ):
        for tok in m.group(1).split():
            found.add(tok.strip())
    return found


def load_base_cidrs(allowed_ips: set[str], lan_ips: set[str]) -> list[str]:
    base = base_default.split()
    sticky = [
        c
        for c in load_sticky_cidrs()
        if normalize_ip(c) in allowed_ips or normalize_ip(c) in lan_ips
    ]
    if env_file.is_file():
        for line in env_file.read_text().splitlines():
            if line.startswith("VPN_CLIENT_CIDRS="):
                raw = line.split("=", 1)[1].strip().strip('"').strip("'")
                parts = raw.split()
                cleaned = []
                for p in parts:
                    # Never keep the blanket home LAN — approved LAN /32s only.
                    if p == "192.168.8.0/24":
                        continue
                    if p.endswith("/32"):
                        ip = p[:-3]
                        # Keep VPS public + allowlisted sticky only (drop transient peers)
                        if is_public_ipv4(ip) and ip != "74.208.76.213" and ip not in allowed_ips:
                            continue
                        if is_home_lan_ipv4(ip) and ip not in lan_ips:
                            continue
                    cleaned.append(p)
                if cleaned:
                    base = cleaned
                break
    # Drop blanket LAN if it leaked in via defaults/env.
    base = [c for c in base if c != "192.168.8.0/24"]
    # Never keep permanently denied shared egress.
    base = [
        c
        for c in base
        if normalize_ip(c) not in DENIED_IPS
    ]
    if "10.10.0.0/24" not in base:
        base.append("10.10.0.0/24")
    if "10.11.0.1/32" not in base:
        base.append("10.11.0.1/32")
    if "74.208.76.213/32" not in base:
        base.append("74.208.76.213/32")
    for s in sticky:
        if normalize_ip(s) in DENIED_IPS:
            continue
        if s not in base:
            base.append(s)
    for ip in sorted(allowed_ips):
        if ip in DENIED_IPS:
            continue
        cidr = f"{ip}/32"
        if cidr not in base:
            base.append(cidr)
    for ip in sorted(lan_ips):
        cidr = f"{ip}/32"
        if cidr not in base:
            base.append(cidr)
    return base


peers = peer_ips()
sticky_cidrs = load_sticky_cidrs()
allowed_ips = ensure_allowlist_seeded(sticky_cidrs) - DENIED_IPS
lan_ips = load_allowlist_lan_ips()
# Sticky file may include unapproved leftovers — only allowlisted count
sticky_trusted = [
    c
    for c in sticky_cidrs
    if normalize_ip(c) not in DENIED_IPS
    and (normalize_ip(c) in allowed_ips or normalize_ip(c) in lan_ips)
]
# Re-read sticky after possible reseal write.
sticky_cidrs = load_sticky_cidrs()
sticky_trusted = [
    c
    for c in sticky_cidrs
    if normalize_ip(c) not in DENIED_IPS
    and (normalize_ip(c) in allowed_ips or normalize_ip(c) in lan_ips)
]
base = load_base_cidrs(allowed_ips, lan_ips)

# IMPORTANT: do NOT auto-append live peer WANs. Only allowlisted sticky enter the circle.
combined = [c for c in base if normalize_ip(c) not in DENIED_IPS]
combined_s = " ".join(combined)

prev = state_file.read_text().strip() if state_file.is_file() else ""
cur = "\n".join(peers)
trusted_needed = sorted(
    {normalize_ip(c) for c in sticky_trusted} | set(allowed_ips) | set(lan_ips)
)
if prev == cur and caddyfile.is_file():
    text = caddyfile.read_text()
    live = vpn_clients_cidrs_in_caddy(text)
    # Require every trusted sticky/allowlisted /32 on the live matcher lines
    # (do NOT match comments — that previously skipped reseeding the router WAN).
    blanket_lan_gone = "192.168.8.0/24" not in live
    denied_gone = all(f"{ip}/32" not in live for ip in DENIED_IPS)
    text2, deny_changed = ensure_denied_wan_blocks(text)
    if deny_changed:
        caddyfile.write_text(text2)
        text = text2
    if (
        trusted_needed
        and all(f"{ip}/32" in live for ip in trusted_needed)
        and blanket_lan_gone
        and denied_gone
        and not deny_changed
    ):
        unapproved = [ip for ip in peers if ip not in allowed_ips]
        if not unapproved or all(f"{ip}/32" not in live for ip in unapproved):
            print(
                f"OK unchanged ({len(peers)} peers seen, {len(sticky_trusted)} trusted sticky, "
                f"{len(allowed_ips)} allowlisted, {len(lan_ips)} lan)"
            )
            raise SystemExit(0)

state_file.write_text(cur + ("\n" if cur else ""))

if env_file.is_file():
    lines = env_file.read_text().splitlines()
    out_lines = []
    found = False
    found_denied = False
    for line in lines:
        if line.startswith("VPN_CLIENT_CIDRS="):
            out_lines.append(f'VPN_CLIENT_CIDRS="{combined_s}"')
            found = True
        elif line.startswith("VPN_CIRCLE_DENIED_IPS="):
            out_lines.append(
                'VPN_CIRCLE_DENIED_IPS="' + " ".join(sorted(DENIED_IPS)) + '"'
            )
            found_denied = True
        else:
            out_lines.append(line)
    if not found:
        out_lines.append(f'VPN_CLIENT_CIDRS="{combined_s}"')
    if not found_denied and DENIED_IPS:
        out_lines.append(
            'VPN_CIRCLE_DENIED_IPS="' + " ".join(sorted(DENIED_IPS)) + '"'
        )
    env_file.write_text("\n".join(out_lines) + "\n")
    print(f"updated {env_file}")

if not caddyfile.is_file():
    print(f"missing {caddyfile}")
    raise SystemExit(1)

text = caddyfile.read_text()
text, _ = ensure_denied_wan_blocks(text)


def _repl(m):
    return f"{m.group(1)}@vpn_clients client_ip {combined_s}"


pat = re.compile(r"^([ \t]*)@vpn_clients (?:client_ip|remote_ip) (.+)$", re.M)
new_text, n = pat.subn(_repl, text)
if n == 0:
    print("WARN: no @vpn_clients client_ip/remote_ip lines found")
    caddyfile.write_text(text)
else:
    caddyfile.write_text(new_text)
    print(f"patched {n} Caddy @vpn_clients lines")

print("peers_seen:", ", ".join(peers) if peers else "(none)")
print("trusted_sticky:", ", ".join(sticky_trusted) if sticky_trusted else "(none)")
print("allowlisted:", ", ".join(sorted(allowed_ips)) if allowed_ips else "(none)")
print("lan_approved:", ", ".join(sorted(lan_ips)) if lan_ips else "(none)")
print("denied:", ", ".join(sorted(DENIED_IPS)) if DENIED_IPS else "(none)")
print("cidrs:", combined_s)

reload = subprocess.run(
    [
        "docker",
        "exec",
        "truemail-caddy-1",
        "caddy",
        "reload",
        "--config",
        "/etc/caddy/Caddyfile",
    ],
    capture_output=True,
    text=True,
)
if reload.returncode != 0:
    print("caddy reload failed:", (reload.stderr or reload.stdout)[:300])
    subprocess.check_call(["docker", "restart", "truemail-caddy-1"])
    print("restarted truemail-caddy-1")
else:
    print("caddy reloaded")
PY

# Apply guest DNS + UFW circle gating for live IKEv2 sessions
if [[ -x "$GATE_SCRIPT" ]]; then
  bash "$GATE_SCRIPT" || true
elif [[ -f "$GATE_SCRIPT" ]]; then
  chmod +x "$GATE_SCRIPT" 2>/dev/null || true
  bash "$GATE_SCRIPT" || true
fi

# Block pending/denied LAN clients on Flint (pre-NAT) so Wi-Fi pending works.
if [[ -x "$LAN_GATE_SCRIPT" ]]; then
  bash "$LAN_GATE_SCRIPT" || true
elif [[ -f "$LAN_GATE_SCRIPT" ]]; then
  chmod +x "$LAN_GATE_SCRIPT" 2>/dev/null || true
  bash "$LAN_GATE_SCRIPT" || true
fi
