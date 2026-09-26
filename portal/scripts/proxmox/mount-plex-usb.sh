#!/bin/bash
# Detach WD Elements USB from Windows VM, mount on Proxmox, bind into Plex CT.
set -euo pipefail

CTID="${CTID:-101}"
VMID="${VMID:-100}"
USB_HOST="${USB_HOST:-4-3.1.4}"
HOST_MNT="${HOST_MNT:-/mnt/plex-usb}"
CT_MNT="${CT_MNT:-/mnt/usb}"

echo "==> Detaching USB ${USB_HOST} from VM ${VMID} (if present)…"
# Find which usbN maps to this host path / vendor
mapfile -t usb_lines < <(qm config "$VMID" 2>/dev/null | grep -E '^usb[0-9]+:' || true)
for line in "${usb_lines[@]}"; do
  key="${line%%:*}"
  val="${line#*: }"
  if [[ "$val" == *"$USB_HOST"* ]] || [[ "$val" == *"1058:25a3"* ]] || [[ "$val" == *"host=4-3.1.4"* ]]; then
    echo "    removing $key ($val)"
    qm set "$VMID" -delete "$key" || true
  fi
done

echo "==> Waiting for block device…"
dev=""
for i in $(seq 1 30); do
  # Prefer WD Elements by-id (never guess /dev/sdX — that can be the system disk)
  for cand in /dev/disk/by-id/usb-WD_Elements*; do
    if [[ -e "$cand" && ! "$cand" =~ part ]]; then
      dev=$(readlink -f "$cand")
      break 2
    fi
  done
  # Fallback: partition/label Elements
  if [[ -e /dev/disk/by-label/Elements ]]; then
    part=$(readlink -f /dev/disk/by-label/Elements)
    # parent disk of the partition
    dev="/dev/$(lsblk -no PKNAME "$part" 2>/dev/null | head -1)"
    [[ -b "$dev" ]] && break
  fi
  sleep 1
done
if [[ -z "$dev" || ! -b "$dev" ]]; then
  echo "USB block device not found after detach. lsblk:" >&2
  lsblk -o NAME,SIZE,TYPE,FSTYPE,LABEL,TRAN,MODEL
  lsusb | grep -i western || true
  exit 1
fi
echo "    device=$dev"
lsblk -o NAME,SIZE,FSTYPE,LABEL,MOUNTPOINT "$dev"
part=""
if [[ -b "${dev}1" ]]; then
  part="${dev}1"
elif [[ -e /dev/disk/by-label/Elements ]]; then
  part=$(readlink -f /dev/disk/by-label/Elements)
elif lsblk -nr -o NAME,TYPE "$dev" | awk '$2=="part"{print; exit}' | grep -q .; then
  part="/dev/$(lsblk -nr -o NAME,TYPE "$dev" | awk '$2=="part"{print $1; exit}')"
else
  part="$dev"
fi
echo "    partition=$part"
fstype=$(lsblk -nr -o FSTYPE "$part" | head -1)
label=$(lsblk -nr -o LABEL "$part" | head -1)
echo "    fstype=${fstype:-unknown} label=${label:-none}"

mkdir -p "$HOST_MNT"
if mountpoint -q "$HOST_MNT"; then
  echo "==> Already mounted at $HOST_MNT"
else
  echo "==> Installing filesystem helpers if needed…"
  apt-get install -y -qq ntfs-3g exfatprogs 2>/dev/null || apt-get install -y -qq ntfs-3g || true
  opts="rw,nosuid,nodev,noatime,uid=0,gid=0,umask=0022"
  case "${fstype,,}" in
    ntfs|ntfs3) mount -t ntfs3 "$part" "$HOST_MNT" -o "$opts" 2>/dev/null || mount -t ntfs-3g "$part" "$HOST_MNT" -o "$opts" ;;
    exfat) mount -t exfat "$part" "$HOST_MNT" -o "$opts" ;;
    vfat|fat32) mount -t vfat "$part" "$HOST_MNT" -o "$opts" ;;
    ext4|xfs|btrfs) mount "$part" "$HOST_MNT" ;;
    *) mount "$part" "$HOST_MNT" -o "$opts" || mount "$part" "$HOST_MNT" ;;
  esac
fi
df -h "$HOST_MNT"
echo "==> Top-level contents:"
ls -la "$HOST_MNT" | head -40

# Persist fstab by UUID
uuid=$(blkid -s UUID -o value "$part" || true)
if [[ -n "$uuid" ]] && ! grep -q "$HOST_MNT" /etc/fstab 2>/dev/null; then
  fs=$(lsblk -nr -o FSTYPE "$part" | head -1)
  [[ -z "$fs" || "$fs" == "ntfs" ]] && fs=ntfs-3g
  echo "UUID=$uuid $HOST_MNT $fs defaults,nofail,x-systemd.automount,uid=0,gid=0,umask=0022 0 0" >> /etc/fstab
  echo "    added fstab entry for UUID=$uuid"
fi

echo "==> Binding into CT ${CTID} at ${CT_MNT}…"
# mp0 is NAS; use mp1 for USB
pct set "$CTID" -mp1 "${HOST_MNT},mp=${CT_MNT}" >/dev/null || true
if ! pct exec "$CTID" -- mountpoint -q "$CT_MNT" 2>/dev/null; then
  echo "    remounting CT to apply mp1…"
  pct stop "$CTID" || true
  pct start "$CTID"
  sleep 8
fi
pct exec "$CTID" -- bash -lc "mkdir -p '$CT_MNT'; df -h '$CT_MNT'; ls -la '$CT_MNT' | head -40"

echo
echo "USB ready for Plex:"
echo "  Host: $HOST_MNT"
echo "  CT:   $CT_MNT"
