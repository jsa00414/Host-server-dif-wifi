#!/usr/bin/env bash
# Carve 1TB from the Seagate 8TB (VG tu / /dev/sda) and attach to Windows VM 100.
#
# Drive: ST8000DM004-2U9188 (/dev/disk/by-id/ata-ST8000DM004-2U9188_ZR16L0CR)
# Storage: Proxmox LVM "tu-hdd" on VG "tu"
# Target: VM 100 win11-pro-gpu → sata2
#
# Usage (on Proxmox host):
#   ./attach-tu-1tb-to-vm.sh status
#   ./attach-tu-1tb-to-vm.sh attach   # create 1T LV if missing + attach as sata2
#   ./attach-tu-1tb-to-vm.sh detach   # hot-unplug sata2 (keeps LV)
set -euo pipefail

VMID="${VMID:-100}"
STORAGE="${STORAGE:-tu-hdd}"
VGNAME="${VGNAME:-tu}"
SIZE="${SIZE:-1024}"          # GiB
SLOT="${SLOT:-sata2}"
DISK_OPTS="${DISK_OPTS:-discard=on}"

need_root() {
  [[ "$(id -u)" -eq 0 ]] || { echo "run as root on the Proxmox host" >&2; exit 1; }
}

ensure_storage() {
  if ! pvesm status | awk 'NR>1{print $1}' | grep -qx "$STORAGE"; then
    echo "==> Adding LVM storage $STORAGE (vg=$VGNAME)"
    pvesm add lvm "$STORAGE" --vgname "$VGNAME" --content images,rootdir --shared 0
  fi
}

status() {
  echo "=== storage ==="
  pvesm status | grep -E "Name|$STORAGE|local-lvm" || true
  echo
  echo "=== VG $VGNAME ==="
  vgs "$VGNAME" 2>/dev/null || echo "(missing)"
  lvs "$VGNAME" 2>/dev/null || true
  echo
  echo "=== VM $VMID disks ==="
  qm config "$VMID" | grep -E "^(boot|$SLOT|sata|scsi|virtio)" || true
}

attach() {
  need_root
  ensure_storage
  if qm config "$VMID" | grep -qE "^${SLOT}:"; then
    echo "VM $VMID already has $SLOT:"
    qm config "$VMID" | grep -E "^${SLOT}:"
    status
    return 0
  fi
  echo "==> Creating ${SIZE}G disk on $STORAGE and attaching as $SLOT"
  # shellcheck disable=SC2086
  qm set "$VMID" --"$SLOT" "${STORAGE}:${SIZE},${DISK_OPTS}"
  status
  echo
  echo "OK — in Windows: Disk Management → Action → Rescan Disks,"
  echo "then Initialize / format the new ~1TB disk if it is Offline/Unknown."
}

detach() {
  need_root
  if ! qm config "$VMID" | grep -qE "^${SLOT}:"; then
    echo "VM $VMID has no $SLOT attached"
    return 0
  fi
  echo "==> Detaching $SLOT from VM $VMID (LV kept on $STORAGE)"
  qm set "$VMID" --delete "$SLOT"
  status
}

case "${1:-status}" in
  status) status ;;
  attach) attach ;;
  detach) detach ;;
  *)
    echo "Usage: $0 status|attach|detach" >&2
    exit 2
    ;;
esac
