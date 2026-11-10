#!/usr/bin/env python3
"""Discover Windows VM IP / RDP and inspect remote access options."""
from __future__ import annotations

import base64
import os
import sys

import paramiko

VPS = os.environ.get("VPS_HOST", "74.208.76.213")
PASSWORD = os.environ.get("VPS_SSH_PASSWORD", "").strip()


def main() -> int:
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(
        VPS,
        username="root",
        password=PASSWORD,
        timeout=45,
        allow_agent=False,
        look_for_keys=False,
    )

    def run(cmd: str, timeout: int = 120) -> str:
        _, stdout, stderr = c.exec_command(cmd, timeout=timeout)
        code = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        if err.strip():
            print(err[:1000], file=sys.stderr)
        if code != 0:
            print(f"[exit {code}]", file=sys.stderr)
        return out

    print(run("ip route replace 192.168.8.0/24 via 10.9.0.2 dev tun0 metric 5 2>/dev/null || true"))

    # Upload discovery script to VPS then to Proxmox
    discover = r'''
import base64, os, socket, paramiko
print("=== flint ===")
password = os.environ.get("ROUTER_PASS") or ""
b64 = os.environ.get("ROUTER_PASS_B64") or ""
if not password and b64:
    password = base64.b64decode(b64).decode()
hosts = []
for key in ("ROUTER_HOSTS", "ROUTER_HOST"):
    v = os.environ.get(key) or ""
    hosts += [h.strip() for h in v.replace(";", ",").split(",") if h.strip()]
user = os.environ.get("ROUTER_USER", "root")
print("hosts", hosts, "user", user, "passlen", len(password))
for host in (hosts or ["10.9.0.2", "192.168.8.1"]):
    cl = paramiko.SSHClient()
    cl.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        cl.connect(host, username=user, password=password, timeout=20, allow_agent=False, look_for_keys=False)
    except Exception as e:
        print("FAIL", host, e)
        continue
    print("OK", host)
    _, o, e = cl.exec_command(
        "echo LEASES; cat /tmp/dhcp.leases 2>/dev/null; echo ====; "
        "echo HOSTS; cat /tmp/hosts 2>/dev/null; echo ====; "
        "iptables-save 2>/dev/null | grep -E '3389|4000' | head -30"
    )
    print(o.read().decode()[:8000])
    cl.close()
    break

print("=== local RDP probe ===")
for ip in ["192.168.8.232", "192.168.8.243", "192.168.8.100", "192.168.8.110", "192.168.8.120"]:
    s = socket.socket(); s.settimeout(0.5)
    try:
        s.connect((ip, 3389)); print("OPEN", ip)
    except Exception as ex:
        print("closed", ip, type(ex).__name__)
    finally:
        s.close()
'''
    # write discover on VPS with env
    b64 = base64.b64encode(discover.encode()).decode()
    print(
        run(
            "set -a; . /opt/wireguard/port-forward-ui.env; set +a; "
            f"python3 -c \"import base64,pathlib; pathlib.Path('/tmp/disc.py').write_bytes(base64.b64decode('{b64}'))\"; "
            "python3 /tmp/disc.py"
        )
    )

    prox_scan = r'''#!/bin/bash
set -e
echo "=== neigh ==="
ip -4 neigh | head -80
echo "=== vm mac ==="
ip -4 neigh | grep -i bc:24:11:4a:ec:a6 || true
echo "=== scan rdp ==="
python3 - <<'P'
import socket
found=[]
for i in range(1,255):
    ip=f"192.168.8.{i}"
    s=socket.socket(); s.settimeout(0.07)
    try:
        s.connect((ip,3389)); found.append(ip); print("RDP", ip)
    except Exception:
        pass
    finally:
        s.close()
print("FOUND", found)
P
echo "=== qm status ==="
qm status 100
qm config 100 | grep -iE 'net0|agent|vga|hostpci'
'''
    b64 = base64.b64encode(prox_scan.encode()).decode()
    print(
        run(
            f"python3 -c \"import base64,pathlib; pathlib.Path('/tmp/prox-scan.sh').write_bytes(base64.b64decode('{b64}'))\"; "
            "scp -o StrictHostKeyChecking=no /tmp/prox-scan.sh root@192.168.8.160:/tmp/; "
            "ssh -o StrictHostKeyChecking=no root@192.168.8.160 bash /tmp/prox-scan.sh",
            timeout=180,
        )
    )

    # guacamole already?
    print(run("docker ps -a --format '{{.Names}}\t{{.Image}}\t{{.Status}}' | grep -iE 'guac|rdp|myrt' || true; ls /opt | head -40"))
    c.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
