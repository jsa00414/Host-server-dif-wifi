#!/bin/bash
# Allowlist Proxmox-related domains in sm-pihole + AdGuard on the VPS.
set -euo pipefail

DOMAINS=(
  proxmox.com
  download.proxmox.com
  enterprise.proxmox.com
  forum.proxmox.com
  bugzilla.proxmox.com
  pve.proxmox.com
  www.proxmox.com
  proxmox.vpstruelord.com
)

for d in "${DOMAINS[@]}"; do
  docker exec sm-pihole pihole allow "$d" >/dev/null || true
done
docker exec sm-pihole pihole --allow-wild proxmox.com >/dev/null || true
docker exec sm-pihole pihole --allow-wild vpstruelord.com >/dev/null || true

python3 - <<'PY'
import json
import subprocess

out = subprocess.check_output(
    ["docker", "exec", "sm-adguard", "wget", "-qO-", "http://127.0.0.1:3000/control/filtering/status"]
)
rules = list(json.loads(out).get("user_rules") or [])
for a in [
    "@@||proxmox.com^",
    "@@||proxmox.vpstruelord.com^",
    "@@||download.proxmox.com^",
    "@@||enterprise.proxmox.com^",
    "@@||forum.proxmox.com^",
]:
    if a not in rules:
        rules.append(a)
body = json.dumps({"rules": rules}).encode()
open("/tmp/adg-rules.json", "wb").write(body)
subprocess.check_call(["docker", "cp", "/tmp/adg-rules.json", "sm-adguard:/tmp/adg-rules.json"])
subprocess.check_call(
    [
        "docker",
        "exec",
        "sm-adguard",
        "wget",
        "-qO-",
        "--post-file=/tmp/adg-rules.json",
        "--header=Content-Type: application/json",
        "http://127.0.0.1:3000/control/filtering/set_rules",
    ]
)
print("OK pihole+adguard allowlist")
PY
