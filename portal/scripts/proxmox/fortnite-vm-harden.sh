#!/usr/bin/env bash
# Harden Proxmox VM 100 for Fortnite / Easy Anti-Cheat.
#
# Installs a /usr/bin/kvm argv filter that:
#   - keeps argv0 as "kvm" (required for KVM accel)
#   - rewrites the first -cpu to: host,-hypervisor,kvm=off
#   - drops later -cpu / vmgenid / org.qemu.guest_agent devices
# Spoofs SMBIOS and disables QEMU guest agent.
#
# Usage on Proxmox:
#   ./fortnite-vm-harden.sh apply
#   ./fortnite-vm-harden.sh status
#   ./fortnite-vm-harden.sh undo     # restore /usr/bin/kvm -> qemu-system-x86_64
set -euo pipefail
VMID="${VMID:-100}"
CLEAN_CPU="${CLEAN_CPU:-host,-hypervisor,kvm=off}"
WRAP_DIR=/usr/local/lib/eac

need_root() { [[ $(id -u) -eq 0 ]] || { echo "run as root on Proxmox" >&2; exit 1; }; }

status() {
  echo "=== qm config ==="
  qm config "$VMID" | egrep '^(args|cpu|ostype|smbios|hostpci|vga|agent):' || true
  echo "=== /usr/bin/kvm ==="
  ls -l /usr/bin/kvm /usr/bin/qemu-system-x86_64 2>/dev/null || true
  file /usr/bin/kvm /usr/bin/qemu-system-x86_64 2>/dev/null || true
  python3 - <<P
import glob, os
for p in glob.glob('/proc/[0-9]*/cmdline'):
    try: raw=open(p,'rb').read()
    except Exception: continue
    parts=raw.split(b'\0')
    ok=False
    for i,x in enumerate(parts):
        if x==b'-id' and i+1<len(parts) and parts[i+1]==b'$VMID'.encode():
            ok=True
    if not ok: continue
    cpus=[parts[i+1].decode() for i,x in enumerate(parts) if x==b'-cpu' and i+1<len(parts)]
    print('cpus', cpus)
    print('kvm_pv', any('kvm_pv' in c for c in cpus))
    print('hv_', any('hv_' in c for c in cpus))
    print('hypervisor_hidden', any('-hypervisor' in c for c in cpus))
P
}

install_wrapper() {
  need_root
  mkdir -p "$WRAP_DIR"
  # Never write through a symlink — that overwrites qemu-system-x86_64.
  if [[ -L /usr/bin/qemu-system-x86_64 ]] || head -1 /usr/bin/qemu-system-x86_64 2>/dev/null | grep -q python; then
    echo "ERROR: /usr/bin/qemu-system-x86_64 is not a real ELF. Restore pve-qemu-kvm first:" >&2
    echo "  dpkg-deb -x /var/cache/apt/archives/pve-qemu-kvm_*.deb /tmp/pq && cp -a /tmp/pq/usr/bin/qemu-system-x86_64 /usr/bin/" >&2
    exit 1
  fi
  rm -f /usr/bin/kvm
  cat > /usr/bin/kvm <<WRAP
#!/usr/bin/env python3
import os, sys
REAL = "/usr/bin/qemu-system-x86_64"
CLEAN = "${CLEAN_CPU}"

def filter_argv(argv):
    is_target = any(argv[i] == "-id" and i + 1 < len(argv) and str(argv[i + 1]) == "${VMID}" for i in range(len(argv)))
    if not is_target:
        return argv
    out = []
    i = 0
    cpu_seen = 0
    while i < len(argv):
        a = argv[i]
        if a == "-device" and i + 1 < len(argv) and ("vmgenid" in argv[i + 1] or "org.qemu.guest_agent" in argv[i + 1]):
            i += 2
            continue
        if a == "-cpu" and i + 1 < len(argv):
            cpu_seen += 1
            if cpu_seen == 1:
                out += ["-cpu", CLEAN]
            i += 2
            continue
        out.append(a)
        i += 1
    return out

# argv0 must be "kvm" or QEMU falls back to TCG.
os.execv(REAL, ["kvm"] + filter_argv(sys.argv[1:]))
WRAP
  chmod 755 /usr/bin/kvm
  cp -a /usr/bin/kvm "$WRAP_DIR/kvm-wrap"
  echo "installed /usr/bin/kvm wrapper"
}

apply() {
  need_root
  install_wrapper
  cp -a "/etc/pve/qemu-server/${VMID}.conf" "/root/vm-${VMID}.conf.bak.fortnite.$(date +%Y%m%d%H%M%S)"

  UUID=$(qm config "$VMID" | sed -n 's/^smbios1:.*uuid=\([^,]*\).*/\1/p' | head -1)
  UUID=${UUID:-8f351dbb-6f26-4ee8-89a5-e3ee19e735af}
  b64() { printf '%s' "$1" | base64 -w0; }
  SMBIOS1="uuid=${UUID},base64=1"
  SMBIOS1+=",manufacturer=$(b64 'Gigabyte Technology Co. Ltd.')"
  SMBIOS1+=",product=$(b64 'B550 AORUS PRO')"
  SMBIOS1+=",version=$(b64 'Default string')"
  SMBIOS1+=",serial=$(b64 'SNGB25091101')"
  SMBIOS1+=",sku=$(b64 'Default string')"
  SMBIOS1+=",family=$(b64 'B550 MB')"

  # No second -cpu in args — wrapper rewrites Proxmox's.
  ARGS='-smbios type=0,vendor=AmericanMegatrends,version=F15h,date=05/16/2024'
  ARGS+=' -smbios type=2,manufacturer=Gigabyte,product=B550AORUSPRO,version=xx,serial=SNGB25091101'
  ARGS+=' -smbios type=3,manufacturer=Gigabyte,version=Default,serial=SNGB25091101,asset=Default,sku=Default'

  qm set "$VMID" --cpu host
  qm set "$VMID" --ostype l26
  qm set "$VMID" --smbios1 "$SMBIOS1"
  qm set "$VMID" --args "$ARGS"
  qm set "$VMID" --agent enabled=0
  qm set "$VMID" --delete serial0 2>/dev/null || true
  qm set "$VMID" --delete vmgenid 2>/dev/null || true
  qm set "$VMID" --vga none

  qm stop "$VMID" --timeout 60 || true
  sleep 3
  qm start "$VMID"
  sleep 8
  status
  cat <<'MSG'

Applied. Inside Windows (admin CMD), run once then reboot:
  bcdedit /set hypervisorlaunchtype off
Then repair Easy Anti-Cheat / Fortnite and try again.

MSG
}

undo() {
  need_root
  rm -f /usr/bin/kvm
  ln -sfn qemu-system-x86_64 /usr/bin/kvm
  echo "restored /usr/bin/kvm -> qemu-system-x86_64"
}

case "${1:-status}" in
  status) status ;;
  apply) apply ;;
  undo) undo ;;
  *) echo "Usage: $0 status|apply|undo" >&2; exit 2 ;;
esac
