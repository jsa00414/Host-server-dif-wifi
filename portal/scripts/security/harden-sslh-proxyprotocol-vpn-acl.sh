#!/usr/bin/env bash
# Fix 443 VPN-only ACLs that are currently bypassed:
#   sslh → 127.0.0.1:4443 makes Caddy see every client as 172.18.0.1, and that
#   address was allowlisted in @vpn_clients — so "VPN-only" sites were public.
#
# This script:
#   1) Installs sslh-fork v2.x + libproxyprotocol (keeps OpenVPN demux on :443)
#   2) Sends PROXY protocol v2 to Caddy so it learns the real client IP
#   3) Teaches Caddy to parse PROXY headers from the docker bridge
#   4) Removes 172.18.0.1 from VPN allowlists
#   5) VPN-gates router/proxmox and drops the cleartext http://VPS_IP portal site
#
# Keeps OpenVPN-on-443 via sslh (Flint / phone profiles unchanged).
# Safe to re-run. Requires: git, gcc, make, libconfig-dev, libpcre2-dev, libcap-dev, libbsd-dev.
set -euo pipefail

CADDYFILE="${CADDYFILE:-/opt/truemail/Caddyfile}"
CADDY_CONTAINER="${CADDY_CONTAINER:-truemail-caddy-1}"
ENV_FILE="${ENV_FILE:-/opt/wireguard/port-forward-ui.env}"
SSLH_UNIT="${SSLH_UNIT:-/etc/systemd/system/sslh-sm.service}"
SSLH_CFG="${SSLH_CFG:-/etc/sslh/sslh-sm.cfg}"
SSLH_BIN="${SSLH_BIN:-/usr/local/sbin/sslh-fork-pp}"
LIBPP_DIR="${LIBPP_DIR:-/usr/local/lib}"
BUILD_ROOT="${BUILD_ROOT:-/opt/servermanager/build}"
SSLH_TAG="${SSLH_TAG:-v2.2.4}"
VPN_CIDRS_DEFAULT="10.8.0.0/24 10.42.42.0/24 192.168.8.0/24 10.9.0.0/24 100.64.0.0/10 127.0.0.1/32"

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "missing $1" >&2; exit 1; }; }
need_cmd git
need_cmd gcc
need_cmd make
need_cmd python3
need_cmd docker

mkdir -p "$BUILD_ROOT" /etc/sslh /usr/local/sbin "$LIBPP_DIR"

echo "==> build libproxyprotocol + sslh-fork ${SSLH_TAG}"
apt-get install -y -qq libconfig-dev libpcre2-dev libcap-dev libbsd-dev >/dev/null

if [[ ! -d "$BUILD_ROOT/libproxyprotocol/.git" ]]; then
  git clone --depth 1 https://github.com/kosmas-valianos/libproxyprotocol.git \
    "$BUILD_ROOT/libproxyprotocol" >/dev/null
fi
make -C "$BUILD_ROOT/libproxyprotocol" >/dev/null
install -m 0755 "$BUILD_ROOT/libproxyprotocol/libs/libproxyprotocol.so" \
  "$LIBPP_DIR/libproxyprotocol.so"
echo "$LIBPP_DIR" >/etc/ld.so.conf.d/libproxyprotocol.conf
ldconfig

if [[ ! -d "$BUILD_ROOT/sslh/.git" ]]; then
  git clone --depth 1 --branch "$SSLH_TAG" https://github.com/yrutschle/sslh.git \
    "$BUILD_ROOT/sslh" >/dev/null
else
  git -C "$BUILD_ROOT/sslh" fetch --depth 1 origin "refs/tags/${SSLH_TAG}:refs/tags/${SSLH_TAG}" >/dev/null 2>&1 || true
  git -C "$BUILD_ROOT/sslh" checkout -q "$SSLH_TAG"
fi
(
  cd "$BUILD_ROOT/sslh"
  export C_INCLUDE_PATH="$BUILD_ROOT/libproxyprotocol/src"
  export LIBRARY_PATH="$LIBPP_DIR"
  export LD_LIBRARY_PATH="$LIBPP_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  ./configure >/dev/null
  make sslh-fork >/dev/null
  install -m 0755 sslh-fork "$SSLH_BIN"
)
"$SSLH_BIN" -V

echo "==> write sslh config (PROXY v2 → Caddy, OpenVPN → :8443)"
cat >"$SSLH_CFG" <<EOF
# Managed by harden-sslh-proxyprotocol-vpn-acl.sh — do not edit by hand
foreground: false;
inetd: false;
numeric: true;
transparent: false;
timeout: 2;
user: "sslh";
pidfile: "/run/sslh/sslh.pid";

listen:
(
    { host: "0.0.0.0"; port: "443"; }
);

protocols:
(
    { name: "tls"; host: "127.0.0.1"; port: "4443"; proxyprotocol: 2; },
    { name: "openvpn"; host: "127.0.0.1"; port: "8443"; },
    { name: "anyprot"; host: "127.0.0.1"; port: "4443"; proxyprotocol: 2; }
);
EOF
chmod 644 "$SSLH_CFG"

echo "==> point sslh-sm.service at new binary/config"
cp -a "$SSLH_UNIT" "${SSLH_UNIT}.bak-pp-$(date +%s)" 2>/dev/null || true
cat >"$SSLH_UNIT" <<EOF
[Unit]
Description=sslh multiplex HTTPS+OpenVPN on :443 (PROXY protocol to Caddy)
After=network-online.target docker.service openvpn-server-sm.service
Wants=network-online.target

[Service]
Type=forking
PIDFile=/run/sslh/sslh.pid
Environment=LD_LIBRARY_PATH=${LIBPP_DIR}
ExecStartPre=/bin/mkdir -p /run/sslh
ExecStartPre=/bin/chown sslh:sslh /run/sslh
ExecStart=${SSLH_BIN} -F${SSLH_CFG}
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload

echo "==> patch Caddyfile: PROXY wrapper + VPN CIDRs + admin gates"
cp -a "$CADDYFILE" "${CADDYFILE}.bak-pp-$(date +%s)"

# Desired VPN CIDR list (no docker gateway)
export VPN_CIDRS="${VPN_CLIENT_CIDRS:-$VPN_CIDRS_DEFAULT}"
VPN_CIDRS="$(
  python3 - <<'PY'
import os, re
raw = os.environ.get("VPN_CIDRS", "")
parts = [
    p
    for p in re.split(r"[\s,]+", raw.strip())
    if p and not p.startswith("172.18.") and p != "172.16.0.0/12"
]
if "127.0.0.1/32" not in parts:
    parts.append("127.0.0.1/32")
print(" ".join(parts))
PY
)"
export VPN_CIDRS
echo "vpn cidrs: $VPN_CIDRS"

python3 - "$CADDYFILE" <<'PY'
import re
import sys
from pathlib import Path
import os

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
vpn = os.environ["VPN_CIDRS"]

# 1) Ensure global servers block has proxy_protocol wrapper for docker→caddy.
#    Only connections from docker bridges are expected to send PROXY headers.
pp_block = """\tlistener_wrappers {
\t\tproxy_protocol {
\t\t\ttimeout 5s
\t\t\tallow 127.0.0.1/32 172.16.0.0/12
\t\t}
\t\ttls
\t}
"""

if "proxy_protocol" not in text:
    # Insert inside the first `{ servers { ... } }` global block if present,
    # otherwise create a global options block at the top.
    m = re.search(r"(?ms)^\{\s*\n\s*servers\s*\{", text)
    if m:
        insert_at = m.end()
        text = text[:insert_at] + "\n" + pp_block + text[insert_at:]
    else:
        text = (
            "{\n"
            "\tservers {\n"
            + pp_block
            + "\t}\n"
            "}\n\n"
            + text
        )
    print("caddy: added proxy_protocol listener_wrappers")
else:
    print("caddy: proxy_protocol already present")

# 2) Rewrite every @vpn_clients remote_ip line to the cleaned CIDR list.
text2, n = re.subn(
    r"(@vpn_clients\s+remote_ip\s+)[^\n]+",
    r"\g<1>" + vpn,
    text,
)
text = text2
print(f"caddy: rewrote {n} @vpn_clients remote_ip lines")

# 3) Remove cleartext http://PUBLIC_IP portal site (dual-run leftover).
text, n = re.subn(
    r"(?ms)^# Dual-run:.*?^http://\d+\.\d+\.\d+\.\d+ \{.*?\n\}\n*",
    "",
    text,
)
if n:
    print(f"caddy: removed {n} cleartext http://IP portal site(s)")
else:
    text, n = re.subn(
        r"(?ms)^http://\d+\.\d+\.\d+\.\d+ \{.*?\n\}\n*",
        "",
        text,
    )
    print(f"caddy: removed {n} http://IP site block(s) via fallback")

# 4) VPN-gate router.vpstruelord.com if it has no @vpn_clients yet.
router = re.search(r"(?ms)^router\.vpstruelord\.com \{.*?\n\}", text)
if router and "@vpn_clients" not in router.group(0):
    old = router.group(0)
    new = f"""router.vpstruelord.com {{
\tencode gzip
\t@vpn_clients remote_ip {vpn}
\thandle @vpn_clients {{
\t\treverse_proxy 192.168.8.1:80 {{
\t\t\theader_up Host 192.168.8.1
\t\t\theader_up X-Forwarded-Host {{host}}
\t\t\theader_up X-Forwarded-Proto https
\t\t\theader_down Location http://192.168.8.1 https://router.vpstruelord.com
\t\t\theader_down Location http://192.168.8.1/ https://router.vpstruelord.com/
\t\t\theader_down -X-Frame-Options
\t\t\theader_down -Content-Security-Policy
\t\t}}
\t}}
\thandle {{
\t\trespond "Forbidden" 403
\t}}
\theader {{
\t\tStrict-Transport-Security "max-age=31536000; includeSubDomains; preload"
\t\tX-Content-Type-Options nosniff
\t\tReferrer-Policy strict-origin-when-cross-origin
\t\tContent-Security-Policy "frame-ancestors *"
\t}}
}}"""
    text = text[: router.start()] + new + text[router.end() :]
    print("caddy: VPN-gated router.vpstruelord.com")
else:
    print("caddy: router block already gated or missing")

# 5) VPN-gate proxmox.vpstruelord.com if needed.
def replace_site_block(src: str, site: str, builder) -> tuple[str, bool]:
    """Replace a top-level `site { ... }` block using brace matching."""
    key = f"{site} {{"
    start = src.find(key)
    if start < 0:
        # also allow site at beginning of line with optional whitespace
        m = re.search(rf"(?m)^{re.escape(site)}\s*\{{", src)
        if not m:
            return src, False
        start = m.start()
        key = m.group(0)
    brace_open = src.find("{", start)
    depth = 0
    i = brace_open
    while i < len(src):
        ch = src[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                old = src[start:end]
                if "@vpn_clients" in old:
                    return src, False
                new = builder(old)
                return src[:start] + new + src[end:], True
        i += 1
    raise SystemExit(f"unbalanced braces in {site} block")


def proxmox_builder(old: str) -> str:
    # Extract reverse_proxy [...] and trailing header { } if present.
    rp = re.search(
        r"(?ms)reverse_proxy\s+https://[^\n]+\{.*?^\t\}|reverse_proxy\s+https://\S+",
        old,
    )
    hdr = re.search(r"(?ms)^\theader\s+\{.*?\n\t\}", old)
    rp_txt = rp.group(0) if rp else "reverse_proxy https://192.168.8.160:8006"
    hdr_txt = hdr.group(0) if hdr else ""
    # indent reverse_proxy one more level inside handle
    rp_indented = "\n".join(
        ("\t\t" + line[1:]) if line.startswith("\t") else ("\t\t" + line)
        for line in rp_txt.splitlines()
    )
    return (
        f"proxmox.vpstruelord.com {{\n"
        f"\t@vpn_clients remote_ip {vpn}\n"
        f"\thandle @vpn_clients {{\n"
        f"{rp_indented}\n"
        f"\t}}\n"
        f"\thandle {{\n"
        f"\t\trespond \"Forbidden\" 403\n"
        f"\t}}\n"
        f"{hdr_txt}\n"
        f"}}"
    )


text, ok = replace_site_block(text, "proxmox.vpstruelord.com", proxmox_builder)
print("caddy: VPN-gated proxmox.vpstruelord.com" if ok else "caddy: proxmox block already gated or missing")

# 6) Note about portal /dav sitting outside VPN handle.
if "portal.vpstruelord.com" in text and "@nasdav" in text:
    portal = re.search(r"(?ms)^portal\.vpstruelord\.com \{.*?\n\}", text)
    # best-effort note only
    print(
        "caddy: portal block present; /dav path matchers may still be public — "
        "real client IPs now enforce other VPN gates."
    )

path.write_text(text, encoding="utf-8")
print("caddy: wrote", path)
PY

# Persist cleaned VPN_CLIENT_CIDRS in portal env
if [[ -f "$ENV_FILE" ]]; then
  if grep -q '^VPN_CLIENT_CIDRS=' "$ENV_FILE"; then
    sed -i "s|^VPN_CLIENT_CIDRS=.*|VPN_CLIENT_CIDRS=\"${VPN_CIDRS}\"|" "$ENV_FILE"
  else
    printf '\nVPN_CLIENT_CIDRS="%s"\n' "$VPN_CIDRS" >>"$ENV_FILE"
  fi
  chmod 600 "$ENV_FILE"
  echo "env: VPN_CLIENT_CIDRS updated (docker gateway removed)"
fi

echo "==> validate caddy, restart sslh (PROXY on), then reload caddy"
if ! docker exec "$CADDY_CONTAINER" caddy validate --config /etc/caddy/Caddyfile; then
  echo "Caddyfile validation failed — fix before reload" >&2
  exit 1
fi
# sslh must speak PROXY before Caddy requires it from the docker bridge.
systemctl restart sslh-sm.service
sleep 1
systemctl --no-pager --full status sslh-sm.service | head -20
docker exec "$CADDY_CONTAINER" caddy reload --config /etc/caddy/Caddyfile
sleep 1

echo
echo "Done. From a non-VPN network, VPN-only hostnames should now return 403."
echo "OpenVPN on TCP/443 via sslh is unchanged. Test:"
echo "  curl -sI https://portal.vpstruelord.com/   # expect 403 off-VPN"
echo "  curl -sI https://router.vpstruelord.com/   # expect 403 off-VPN"
