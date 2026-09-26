#!/usr/bin/env python3
"""Upload and run enable-windows-rdp-offline.sh on Proxmox via VPS."""
from __future__ import annotations

import base64
import os
import sys
import time
from pathlib import Path

import paramiko

SCRIPT = Path(__file__).resolve().parent / "enable-windows-rdp-offline.sh"


def main() -> int:
    pw = os.environ.get("VPS_SSH_PASSWORD", "").strip()
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(
        "74.208.76.213",
        username="root",
        password=pw,
        timeout=45,
        allow_agent=False,
        look_for_keys=False,
    )

    def run(cmd: str, timeout: int = 120) -> tuple[int, str, str]:
        _, stdout, stderr = c.exec_command(cmd, timeout=timeout)
        code = stdout.channel.recv_exit_status()
        return (
            code,
            stdout.read().decode("utf-8", errors="replace"),
            stderr.read().decode("utf-8", errors="replace"),
        )

    run("ip route replace 192.168.8.0/24 via 10.9.0.2 dev tun0 metric 5 2>/dev/null || true")
    # kill prior hung enables
    run(
        "ssh -o StrictHostKeyChecking=no root@192.168.8.160 "
        "\"pkill -9 -f enable-windows-rdp-offline || true; "
        "qemu-nbd -d /dev/nbd0 2>/dev/null || true; "
        "umount -l /mnt/win-rdp-edit 2>/dev/null || true\""
    )
    b64 = base64.b64encode(SCRIPT.read_bytes()).decode("ascii")
    code, out, err = run(
        "python3 -c \"import base64,pathlib; pathlib.Path('/tmp/enable-windows-rdp-offline.sh')"
        f".write_bytes(base64.b64decode('{b64}'))\""
    )
    if code != 0:
        print(out, err)
        return code

    code, out, err = run(
        "scp -o StrictHostKeyChecking=no /tmp/enable-windows-rdp-offline.sh "
        "root@192.168.8.160:/tmp/enable-windows-rdp-offline.sh && "
        "ssh -o StrictHostKeyChecking=no root@192.168.8.160 "
        "\": > /tmp/enable-rdp.log; nohup bash /tmp/enable-windows-rdp-offline.sh "
        ">> /tmp/enable-rdp.log 2>&1 & echo STARTED\""
    )
    print(out, err[:300] if err else "")

    for i in range(90):
        time.sleep(5)
        code, out, err = run(
            "ssh -o StrictHostKeyChecking=no root@192.168.8.160 "
            "\"echo '---LOG---'; tail -40 /tmp/enable-rdp.log; "
            "echo '---PROC---'; "
            "if pgrep -f '/tmp/enable-windows-rdp-offline.sh' >/dev/null; "
            "then echo RDP_ENABLE_RUNNING; else echo RDP_ENABLE_IDLE; fi; "
            "qm status 100; "
            "if grep -q '^DONE$' /tmp/enable-rdp.log; then echo RDP_ENABLE_FINISHED; fi\""
        )
        print(f"\n=== poll {i} ===")
        print(out)
        if "RDP_ENABLE_FINISHED" in out:
            break
        if "RDP_ENABLE_IDLE" in out and i > 2 and "Registry OK" in out:
            break
        if "missing hivexget" in out or "missing qemu-nbd" in out:
            print("missing tools", file=sys.stderr)
            break
    c.close()
    return 0 if "RDP_ENABLE_FINISHED" in out or "Registry OK" in out else 1


if __name__ == "__main__":
    raise SystemExit(main())
