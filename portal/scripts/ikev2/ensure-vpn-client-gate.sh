#!/usr/bin/env bash
# Gate IKEv2 clients into the "trust circle":
#   - Allowlisted WAN/VIP → AdGuard DNS + host INPUT (admin VIP path)
#   - Everyone else → internet OK, but DNS forced to guest resolver (no admin rewrites)
#
# Called from sm-ikev2-peer-acl.service after the Caddy sticky ACL sync.
set -euo pipefail

ALLOWLIST_FILE="${VPN_ALLOWLIST_FILE:-/opt/servermanager/panel/vpn-allowlist.json}"
STICKY_FILE="${STICKY_VPN_IPS_FILE:-/opt/servermanager/panel/caddy-sticky-vpn-ips.txt}"
GUEST_DNS="${VPN_GUEST_DNS:-1.1.1.1}"
IKEV2_POOL="${IKEV2_POOL:-10.10.0.0/24}"
ADGUARD_DNS="${ADGUARD_DNS:-10.42.42.44}"

export ALLOWLIST_FILE STICKY_FILE GUEST_DNS IKEV2_POOL ADGUARD_DNS

python3 - <<'PY'
import json
import os
import re
import subprocess
import time
from pathlib import Path

allow_path = Path(os.environ["ALLOWLIST_FILE"])
sticky_path = Path(os.environ["STICKY_FILE"])
guest_dns = os.environ.get("GUEST_DNS", "1.1.1.1").strip() or "1.1.1.1"
pool = os.environ.get("IKEV2_POOL", "10.10.0.0/24")
adguard = os.environ.get("ADGUARD_DNS", "10.42.42.44")
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
    if parts[3] in (0, 255, 1):
        return False
    return True


def normalize_ip(raw: str) -> str:
    raw = (raw or "").strip()
    if "/" in raw:
        raw = raw.split("/", 1)[0]
    return raw


def row_is_sealed(row: dict) -> bool:
    ip = normalize_ip(row.get("ip", ""))
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


def scrub_require_keys(data: dict) -> dict:
    """Demote non-sealed allowlisted IPs that lack an Ed25519 pubkey to pending."""
    kept = []
    pending = [r for r in (data.get("pending") or []) if isinstance(r, dict)]
    pending_ips = {normalize_ip(r.get("ip", "")) for r in pending}
    for row in list(data.get("allowed") or []):
        if not isinstance(row, dict):
            continue
        ip = normalize_ip(row.get("ip", ""))
        if not ip:
            continue
        if row_is_circle_trusted(row):
            kept.append(row)
            continue
        if ip not in pending_ips:
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
    data["allowed"] = kept
    data["pending"] = pending
    return data


def load_allowlist() -> dict:
    data = {
        "allowed": [],
        "denied": [],
        "attempts": [],
        "pending": [],
    }
    if allow_path.is_file():
        try:
            loaded = json.loads(allow_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                for key in data:
                    if isinstance(loaded.get(key), list):
                        data[key] = loaded[key]
        except Exception:
            pass
    # Do NOT seed sticky WAN into allowed without a circle key — membership is
    # key-bound only. Sealed router WANs are resealed below from env.
    allowed_set = {normalize_ip(x.get("ip", "")) for x in data["allowed"] if isinstance(x, dict)}
    # Always reseal configured WANs only (VPN_CIRCLE_SEALED_IPS; empty = none).
    sealed_raw = os.environ.get("VPN_CIRCLE_SEALED_IPS", "")
    sealed_set = set()
    for part in re.split(r"[\s,;]+", sealed_raw):
        ip = normalize_ip(part)
        if not ip or not is_public_ipv4(ip):
            continue
        sealed_set.add(ip)
        existing = next(
            (
                r
                for r in data["allowed"]
                if isinstance(r, dict) and normalize_ip(r.get("ip", "")) == ip
            ),
            None,
        )
        if existing:
            existing["sealed"] = True
            existing["hidden"] = True
            existing["source"] = "router"
            if not str(existing.get("note") or "").strip() or "seeded from sticky" in str(
                existing.get("note") or ""
            ):
                existing["note"] = "Flint router WAN (sealed)"
        else:
            data["allowed"].append(
                {
                    "ip": ip,
                    "note": "Flint router WAN (sealed)",
                    "approved_at": now,
                    "source": "router",
                    "sealed": True,
                    "hidden": True,
                }
            )
            allowed_set.add(ip)
    # Drop obsolete sealed campus/WAN rows when no longer configured.
    data["allowed"] = [
        r
        for r in data["allowed"]
        if not (
            isinstance(r, dict)
            and (
                r.get("sealed")
                or (
                    str(r.get("source") or "") == "router"
                    and "sealed" in str(r.get("note") or "").lower()
                )
            )
            and normalize_ip(r.get("ip", "")) not in sealed_set
        )
    ]
    data = scrub_require_keys(data)
    return data


def save_allowlist(data: dict) -> None:
    data = scrub_require_keys(data)
    allow_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = allow_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(allow_path)
    try:
        os.chmod(allow_path, 0o600)
    except Exception:
        pass


def sync_sticky(allowed: list[dict]) -> None:
    sticky_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Managed by vpn allowlist — key-bound sticky WAN + LAN IPs",
        "# Key-bound only (except sealed router WAN). No blanket 192.168.8.0/24.",
        "# one IPv4 /32 per line",
    ]
    for row in allowed:
        if not isinstance(row, dict):
            continue
        ip = normalize_ip(row.get("ip", ""))
        if not ip or not (is_public_ipv4(ip) or is_home_lan_ipv4(ip)):
            continue
        if row_is_circle_trusted(row):
            lines.append(f"{ip}/32")
    sticky_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def peer_sessions() -> list[dict]:
    """Return [{wan, vip, line}] for active IKEv2 SAs."""
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
    sessions = []
    # 74.x[...]...192.81.x[client]
    wan_re = re.compile(r"\.\.\.(\d{1,3}(?:\.\d{1,3}){3})\[")
    # child / VIP lines often include 10.10.0.N/32
    vip_re = re.compile(r"\b(10\.10\.\d{1,3}\.\d{1,3})(?:/32)?\b")
    current_wan = None
    for line in out.splitlines():
        m = wan_re.search(line)
        if m and is_public_ipv4(m.group(1)):
            current_wan = m.group(1)
        if "10.10." in line:
            vm = vip_re.search(line)
            if vm and current_wan:
                sessions.append({"wan": current_wan, "vip": vm.group(1), "line": line.strip()})
                current_wan = None
    # Deduplicate by wan
    seen = set()
    uniq = []
    for s in sessions:
        if s["wan"] in seen:
            continue
        seen.add(s["wan"])
        uniq.append(s)
    return uniq


def iptables_ok(cmd: list[str]) -> bool:
    return subprocess.run(cmd, capture_output=True).returncode == 0


def ensure_guest_dns(vip: str, enable: bool) -> None:
    """DNAT this IKEv2 VIP's DNS to guest resolver (bypass AdGuard admin rewrites)."""
    comment = f"SM-VPN-GUEST-DNS-{vip}"
    for proto in ("udp", "tcp"):
        check = [
            "iptables",
            "-t",
            "nat",
            "-C",
            "PREROUTING",
            "-s",
            f"{vip}/32",
            "-p",
            proto,
            "--dport",
            "53",
            "-m",
            "comment",
            "--comment",
            comment,
            "-j",
            "DNAT",
            "--to-destination",
            f"{guest_dns}:53",
        ]
        exists = iptables_ok(check)
        if enable and not exists:
            subprocess.run(
                [
                    "iptables",
                    "-t",
                    "nat",
                    "-I",
                    "PREROUTING",
                    "1",
                    "-s",
                    f"{vip}/32",
                    "-p",
                    proto,
                    "--dport",
                    "53",
                    "-m",
                    "comment",
                    "--comment",
                    comment,
                    "-j",
                    "DNAT",
                    "--to-destination",
                    f"{guest_dns}:53",
                ],
                check=False,
            )
        elif (not enable) and exists:
            subprocess.run(
                [
                    "iptables",
                    "-t",
                    "nat",
                    "-D",
                    "PREROUTING",
                    "-s",
                    f"{vip}/32",
                    "-p",
                    proto,
                    "--dport",
                    "53",
                    "-m",
                    "comment",
                    "--comment",
                    comment,
                    "-j",
                    "DNAT",
                    "--to-destination",
                    f"{guest_dns}:53",
                ],
                check=False,
            )


def list_guest_dns_vips() -> set[str]:
    proc = subprocess.run(
        ["iptables", "-t", "nat", "-S", "PREROUTING"],
        capture_output=True,
        text=True,
    )
    found = set()
    for line in (proc.stdout or "").splitlines():
        if "SM-VPN-GUEST-DNS-" not in line:
            continue
        m = re.search(r"SM-VPN-GUEST-DNS-(\d+\.\d+\.\d+\.\d+)", line)
        if m:
            found.add(m.group(1))
    return found


def ufw_replace_blanket() -> None:
    """Drop pool-wide host allow; keep narrow HTTPS so VIP/sslh still works for trusted path setup."""
    if not Path("/usr/sbin/ufw").is_file():
        return
    # Delete blanket if present
    subprocess.run(
        ["ufw", "delete", "allow", "from", pool],
        capture_output=True,
        text=True,
    )
    # Idempotent narrow allows for the pool (internet clients don't need host INPUT;
    # trusted circle uses per-VIP rules below). Keep 443 for sslh/VIP hairpin during enroll.
    for port in ("443", "80"):
        status = subprocess.run(["ufw", "status"], capture_output=True, text=True)
        needle = f"{port}/tcp"
        blob = status.stdout or ""
        if pool in blob and needle in blob and "IKEv2" in blob:
            continue
        subprocess.run(
            [
                "ufw",
                "allow",
                "from",
                pool,
                "to",
                "any",
                "port",
                port,
                "proto",
                "tcp",
                "comment",
                "IKEv2 base HTTPS",
            ],
            capture_output=True,
            text=True,
        )


def ufw_set_trusted(vip: str, enable: bool) -> None:
    if not Path("/usr/sbin/ufw").is_file():
        return
    comment = f"IKEv2 trusted {vip}"
    status = subprocess.run(["ufw", "status"], capture_output=True, text=True)
    blob = status.stdout or ""
    present = vip in blob and "IKEv2 trusted" in blob
    if enable and not present:
        subprocess.run(
            ["ufw", "allow", "from", f"{vip}/32", "comment", comment],
            capture_output=True,
            text=True,
        )
    elif (not enable) and present:
        # Best-effort delete by matching rule text
        numbered = subprocess.run(
            ["ufw", "status", "numbered"], capture_output=True, text=True
        )
        for line in (numbered.stdout or "").splitlines():
            if vip in line and "IKEv2 trusted" in line:
                m = re.search(r"\[\s*(\d+)\]", line)
                if m:
                    subprocess.run(
                        ["ufw", "--force", "delete", m.group(1)],
                        capture_output=True,
                        text=True,
                    )
                    break


data = load_allowlist()
# Trust circle: sealed router WAN or Ed25519 key-bound only.
allowed_ips = {
    normalize_ip(x.get("ip", ""))
    for x in data["allowed"]
    if isinstance(x, dict)
    and normalize_ip(x.get("ip", ""))
    and row_is_circle_trusted(x)
}
denied_ips = {
    normalize_ip(x.get("ip", ""))
    for x in data["denied"]
    if isinstance(x, dict) and normalize_ip(x.get("ip", ""))
}

sync_sticky(data["allowed"])
ufw_replace_blanket()

sessions = peer_sessions()
active_guest = set()
pending_map = {normalize_ip(x.get("ip", "")): x for x in data["pending"] if isinstance(x, dict)}
attempts = [x for x in data["attempts"] if isinstance(x, dict)]

for s in sessions:
    wan = s["wan"]
    vip = s["vip"]
    trusted = wan in allowed_ips
    ensure_guest_dns(vip, enable=not trusted)
    ufw_set_trusted(vip, enable=trusted)
    if not trusted:
        active_guest.add(vip)
        # Track attempt / pending
        row = pending_map.get(wan) or {
            "ip": wan,
            "vip": vip,
            "first_seen": now,
            "last_seen": now,
            "count": 0,
            "status": "denied" if wan in denied_ips else "pending",
        }
        row["vip"] = vip
        row["last_seen"] = now
        row["count"] = int(row.get("count") or 0) + 1
        if wan in denied_ips:
            row["status"] = "denied"
        elif row.get("status") != "denied":
            row["status"] = "pending"
        pending_map[wan] = row
        # Append compact attempt log
        attempts.append(
            {
                "ip": wan,
                "vip": vip,
                "ts": now,
                "trusted": False,
            }
        )

# Drop guest DNAT for VIPs no longer connected
for vip in list_guest_dns_vips():
    if vip not in active_guest and vip not in {s["vip"] for s in sessions if s["wan"] in allowed_ips}:
        # still connected trusted → already disabled above; leftover orphans:
        if vip not in {s["vip"] for s in sessions}:
            ensure_guest_dns(vip, enable=False)

# Keep pending for currently interesting IPs (active or recent 7d),
# and preserve LAN-offline pending rows seeded by the portal.
cutoff = now - 7 * 86400
preserved_lan = []
for row in data.get("pending") or []:
    if not isinstance(row, dict):
        continue
    if str(row.get("source") or "") == "lan-offline" or str(row.get("kind") or "") == "lan":
        ip = normalize_ip(row.get("ip", ""))
        if ip and ip not in allowed_ips and ip not in denied_ips:
            preserved_lan.append(row)

merged = {normalize_ip(x.get("ip", "")): x for x in pending_map.values() if isinstance(x, dict)}
for row in preserved_lan:
    ip = normalize_ip(row.get("ip", ""))
    if ip and ip not in merged:
        merged[ip] = row

data["pending"] = sorted(
    [
        v
        for v in merged.values()
        if int(v.get("last_seen") or 0) >= cutoff
        or str(v.get("source") or "") in ("lan-offline", "lan")
        or str(v.get("kind") or "") == "lan"
    ],
    key=lambda x: int(x.get("last_seen") or 0),
    reverse=True,
)[:80]
data["attempts"] = attempts[-200:]
save_allowlist(data)

print(
    f"gate: sessions={len(sessions)} trusted={sum(1 for s in sessions if s['wan'] in allowed_ips)} "
    f"guest_dns={len(active_guest)} allowed={len(allowed_ips)} pending={len(data['pending'])}"
)
PY
