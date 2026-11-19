#!/usr/bin/env python3
"""Upload and run create-rdp-target-vm.sh on Proxmox via the VPS OpenVPN path."""
from __future__ import annotations

import base64
import io
import os
import sys
import time
from pathlib import Path

import paramiko

SCRIPT = Path(__file__).resolve().parent / "create-rdp-target-vm.sh"
DEFAULT_HOST = "74.208.76.213"
PROXMOX = "192.168.8.160"
VMID = os.environ.get("RDP_VMID", "102").strip() or "102"


def _client() -> paramiko.SSHClient:
    host = os.environ.get("VPS_HOST", DEFAULT_HOST).strip()
    user = os.environ.get("VPS_USER", "root").strip() or "root"
    port = int(os.environ.get("VPS_PORT", "22"))
    key_text = os.environ.get("VPS_SSH_PRIVATE_KEY", "").strip()
    password = os.environ.get("VPS_SSH_PASSWORD", "").strip()
    if not key_text and not password:
        raise SystemExit("Set VPS_SSH_PRIVATE_KEY or VPS_SSH_PASSWORD")
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
    if key_text:
        kw["pkey"] = paramiko.RSAKey.from_private_key(io.StringIO(key_text))
    else:
        kw["password"] = password
    client.connect(**kw)
    return client


def _run(client: paramiko.SSHClient, cmd: str, timeout: int = 300) -> tuple[int, str, str]:
    _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    code = stdout.channel.recv_exit_status()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    return code, out, err


def main() -> int:
    if not SCRIPT.is_file():
        raise SystemExit(f"missing {SCRIPT}")

    script_b64 = base64.b64encode(SCRIPT.read_bytes()).decode("ascii")
    client = _client()
    try:
        code, out, err = _run(
            client,
            "ip route replace 192.168.8.0/24 via 10.9.0.2 dev tun0 metric 5 2>/dev/null || true; "
            f"ping -c1 -W3 {PROXMOX} >/dev/null && echo PING_OK || echo PING_FAIL",
            timeout=30,
        )
        print(out.strip() or err.strip())

        # Drop script on VPS then copy to Proxmox
        code, out, err = _run(
            client,
            "python3 -c \"import base64,pathlib; pathlib.Path('/tmp/create-rdp-target-vm.sh')"
            f".write_bytes(base64.b64decode('{script_b64}'))\"",
            timeout=60,
        )
        if code != 0:
            print(out, err, file=sys.stderr)
            return code

        print(f"=== uploading + creating VM {VMID} on Proxmox ===")
        code, out, err = _run(
            client,
            f"scp -o StrictHostKeyChecking=no /tmp/create-rdp-target-vm.sh "
            f"root@{PROXMOX}:/tmp/create-rdp-target-vm.sh && "
            f"ssh -o StrictHostKeyChecking=no root@{PROXMOX} "
            f"'chmod +x /tmp/create-rdp-target-vm.sh; "
            f"bash /tmp/create-rdp-target-vm.sh > /tmp/create-rdp-target.log 2>&1; "
            f"echo EXIT:$?; tail -80 /tmp/create-rdp-target.log'",
            timeout=600,
        )
        print(out)
        if err:
            print(err, file=sys.stderr)
        if code != 0:
            return code
        if f"STARTED_VM_{VMID}" not in out and "already exists" not in out:
            print("create script did not report success", file=sys.stderr)
            return 1

        print("=== waiting for guest agent / IP (Windows install) ===")
        ip = ""
        for i in range(120):  # up to ~40 min
            time.sleep(20)
            code, out, err = _run(
                client,
                f"ssh -o StrictHostKeyChecking=no root@{PROXMOX} "
                f"\"qm status {VMID}; "
                f"qm guest cmd {VMID} network-get-interfaces 2>/dev/null | head -80 || true; "
                f"echo '---ARP---'; "
                f"ip neigh show | grep -E '192\\.168\\.8\\.' || true; "
                f"echo '---LOG---'; tail -5 /tmp/create-rdp-target.log\"",
                timeout=60,
            )
            print(f"\n=== poll {i} ===")
            print(out[:2000])
            # Prefer guest-agent IPv4 that is not link-local
            for line in out.splitlines():
                if '"ip-address"' in line and "192.168.8." in line:
                    # "ip-address": "192.168.8.x"
                    part = line.split('"') 
                    for j, tok in enumerate(part):
                        if tok == "ip-address" and j + 2 < len(part):
                            cand = part[j + 2]
                            if cand.startswith("192.168.8.") and not cand.endswith(".255"):
                                ip = cand
                                break
                if ip:
                    break
            if ip:
                print(f"GUEST_IP={ip}")
                # Probe RDP from Proxmox
                code, out, err = _run(
                    client,
                    f"ssh -o StrictHostKeyChecking=no root@{PROXMOX} "
                    f"\"timeout 3 bash -c 'echo >/dev/tcp/{ip}/3389' && echo RDP_OPEN || echo RDP_CLOSED\"",
                    timeout=30,
                )
                print(out.strip())
                if "RDP_OPEN" in out:
                    print(f"READY: VM {VMID} RDP at {ip}:3389")
                    print(f"From VM 100 (192.168.8.163): mstsc /v:{ip}")
                    return 0
            if i > 0 and i % 6 == 0:
                # every ~2 min also try nmap-less sweep of common DHCP range for 3389
                code, out, err = _run(
                    client,
                    f"ssh -o StrictHostKeyChecking=no root@{PROXMOX} "
                    f"\"for h in $(seq 150 200); do "
                    f"timeout 0.3 bash -c 'echo >/dev/tcp/192.168.8.'$h'/3389' 2>/dev/null "
                    f"&& echo OPEN:192.168.8.$h; done\"",
                    timeout=90,
                )
                print("RDP sweep:", out.strip() or "(none)")
                for line in out.splitlines():
                    if line.startswith("OPEN:") and "192.168.8.163" not in line:
                        ip = line.split(":", 1)[1].strip()
                        print(f"READY: VM {VMID} RDP at {ip}:3389 (discovered)")
                        return 0

        print("timed out waiting for RDP", file=sys.stderr)
        return 1
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
