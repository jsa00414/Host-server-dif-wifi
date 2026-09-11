#!/usr/bin/env bash
# Harden Proxmox VM 100 (win11-pro-gpu) for Fortnite / Easy Anti-Cheat.
#
# Changes:
# - hv_vendor_id=AuthenticAMD (not "proxmox")
# - kvm=off, -hypervisor
# - realistic SMBIOS (Gigabyte B550)
# - ostype l26 so Proxmox does not inject hv_vendor_id=proxmox
# - keeps GPU hostpci0 x-vga
#
# Usage on Proxmox host:
#   ./fortnite-vm-harden.sh apply    # sets config + restarts VM 100
#   ./fortnite-vm-harden.sh status
set -euo pipefail
VMID="${VMID:-100}"
CONF="/etc/pve/qemu-server/${VMID}.conf"

need_root() { [[ $(id -u) -eq 0 ]] || { echo "run as root on Proxmox" >&2; exit 1; }; }

b64() { printf '%s' "$1" | base64 -w0; }

status() {
  echo "=== qm config ==="
  qm config "$VMID" | egrep '^(args|cpu|ostype|smbios|hostpci|vga):' || true
  PID=$(pgrep -f "/usr/bin/kvm.*-id ${VMID}" | head -1 || true)
  echo "pid=${PID:-none}"
  if [[ -n "${PID:-}" ]]; then
    python3 - <<P
import pathlib
parts=pathlib.Path('/proc/'+'''$PID'''+'/cmdline').read_bytes().split(b'\0')
cpus=[parts[i+1].decode() for i,x in enumerate(parts) if x==b'-cpu' and i+1<len(parts)]
print('cpu_count', len(cpus))
if cpus:
  print('LAST', cpus[-1])
  print('AuthenticAMD', 'AuthenticAMD' in cpus[-1])
  print('proxmox_anywhere', any('proxmox' in c for c in cpus))
P
  fi
}

apply() {
  need_root
  cp -a "$CONF" "/root/vm-${VMID}.conf.bak.fortnite.$(date +%Y%m%d%H%M%S)"
  UUID=$(qm config "$VMID" | sed -n 's/^smbios1:.*uuid=\([^,]*\).*/\1/p' | head -1)
  UUID=${UUID:-8f351dbb-6f26-4ee8-89a5-e3ee19e735af}
  SMBIOS1="uuid=${UUID},base64=1"
  SMBIOS1+=",manufacturer=$(b64 'Gigabyte Technology Co. Ltd.')"
  SMBIOS1+=",product=$(b64 'B550 AORUS PRO')"
  SMBIOS1+=",version=$(b64 'Default string')"
  SMBIOS1+=",serial=$(b64 'SNGB25091101')"
  SMBIOS1+=",sku=$(b64 'Default string')"
  SMBIOS1+=",family=$(b64 'B550 MB')"

  ARGS='-cpu host,-hypervisor,kvm=off,hv_vendor_id=AuthenticAMD,hv_time,hv_relaxed,hv_vapic,hv_spinlocks=0x1fff,hv_vpindex,hv_synic,hv_stimer,hv_reset,hv_runtime,hv_ipi'
  ARGS+=' -smbios type=0,vendor=AmericanMegatrends,version=F15h,date=05/16/2024'
  ARGS+=' -smbios type=2,manufacturer=Gigabyte,product=B550AORUSPRO,version=xx,serial=SNGB25091101'
  ARGS+=' -smbios type=3,manufacturer=Gigabyte,version=Default,serial=SNGB25091101,asset=Default,sku=Default'

  qm set "$VMID" --cpu host,flags=+pcid
  qm set "$VMID" --ostype l26
  qm set "$VMID" --smbios1 "$SMBIOS1"
  qm set "$VMID" --args "$ARGS"
  qm set "$VMID" --vga none
  qm set "$VMID" --hostpci0 0000:06:00,pcie=1,x-vga=1

  # Ensure single ostype line
  python3 - <<P
from pathlib import Path
p=Path('$CONF')
out=[]; seen=False
for line in p.read_text().splitlines():
    if line.startswith('ostype:'):
        if seen: continue
        out.append('ostype: l26'); seen=True
    else:
        out.append(line)
p.write_text('\\n'.join(out)+'\\n')
P

  qm stop "$VMID" --timeout 45 || true
  sleep 4
  qm start "$VMID"
  sleep 8
  status
  cat <<'MSG'

Applied. In Windows (admin PowerShell), also run once:
  bcdedit /set hypervisorlaunchtype off
  Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -NoRestart
Then reboot Windows, repair Easy Anti-Cheat / Fortnite, and retry.

MSG
}

case "${1:-status}" in
  status) status ;;
  apply) apply ;;
  *) echo "Usage: $0 status|apply" >&2; exit 2 ;;
esac
