#!/usr/bin/env bash
# Create a private LUKS virtual drive (file-backed) on a USB stick (Proxmox/Linux).
# Default target: Norelsys flash drive (not WD Elements / Plex).
set -euo pipefail

SIZE_MB="${SIZE_MB:-256}"
VAULT_FOLDER="${VAULT_FOLDER:-ServerManagerKeyVault}"
IMG_NAME="${IMG_NAME:-ServerManagerKeys.img}"
MAPPER_NAME="${MAPPER_NAME:-sm-key-vault}"
STICK_MNT="${STICK_MNT:-/mnt/sm-usb-stick}"
VAULT_MNT="${VAULT_MNT:-/mnt/sm-key-vault}"
# Prefer by-id; never guess system disks. Override with USB_BY_ID=/dev/disk/by-id/...
USB_BY_ID="${USB_BY_ID:-}"
PASSPHRASE="${PASSPHRASE:-}"  # if empty, generate and print once

die() { echo "ERROR: $*" >&2; exit 1; }

require_root() {
  [[ "$(id -u)" -eq 0 ]] || die "Run as root on the Proxmox host."
}

pick_usb_partition() {
  local cand part
  if [[ -n "$USB_BY_ID" ]]; then
    [[ -e "$USB_BY_ID" ]] || die "USB_BY_ID not found: $USB_BY_ID"
    cand=$(readlink -f "$USB_BY_ID")
    if [[ -b "${cand}1" ]]; then
      echo "${cand}1"
      return
    fi
    # If by-id already points at a partition:
    if lsblk -nr -o TYPE "$cand" | grep -qx part; then
      echo "$cand"
      return
    fi
    die "No partition on $cand"
  fi

  # Prefer Norelsys key stick (just plugged in); never WD Elements.
  for cand in /dev/disk/by-id/usb-NORELSYS_* /dev/disk/by-id/usb-Norelsys_*; do
    [[ -e "$cand" ]] || continue
    [[ "$cand" =~ part ]] && continue
    part=$(readlink -f "$cand")
    if [[ -b "${part}1" ]]; then
      echo "${part}1"
      return
    fi
  done

  # Fallback: single removable USB disk that is NOT WD Elements / plex-usb
  local disks=()
  while read -r name tran rm model; do
    [[ "$tran" == "usb" ]] || continue
    [[ "$rm" == "1" || "$rm" == "0" ]] || continue
    [[ "$model" == *Elements* || "$model" == *WDC* ]] && continue
    [[ -b "/dev/$name" ]] || continue
    # skip if mounted as plex-usb
    if findmnt -n -S "/dev/${name}1" 2>/dev/null | grep -q plex-usb; then
      continue
    fi
    disks+=("$name")
  done < <(lsblk -dn -o NAME,TRAN,RM,MODEL)

  if [[ ${#disks[@]} -eq 1 ]]; then
    local d="/dev/${disks[0]}"
    [[ -b "${d}1" ]] || die "USB /dev/${disks[0]} has no partition 1"
    echo "${d}1"
    return
  fi

  echo "Could not auto-pick a key USB. Removable/USB disks:" >&2
  lsblk -o NAME,SIZE,TRAN,RM,MODEL,FSTYPE,LABEL,MOUNTPOINT >&2
  die "Set USB_BY_ID=/dev/disk/by-id/usb-YOURSTICK-0:0 (whole disk) or ...-part1"
}

require_root
command -v cryptsetup >/dev/null || die "cryptsetup missing"
command -v mkfs.ext4 >/dev/null || die "mkfs.ext4 missing"

part=$(pick_usb_partition)
pk=$(lsblk -nr -o PKNAME "$part" | head -1)
disk_model=""
if [[ -n "$pk" ]]; then
  disk_model=$(lsblk -nr -o MODEL "/dev/$pk" 2>/dev/null | head -1 || true)
fi
label=$(lsblk -nr -o LABEL "$part" || true)
echo "==> Using USB partition $part (label=${label:-none} model=${disk_model:-unknown})"

# Hard safety: refuse WD Elements / plex mount
case "$label|$disk_model" in
  Elements*|*\ Elements*|*\Elements*|*\WDC\ WD180*)
    die "Refusing to use WD Elements / Plex USB. Use the ~128GB Norelsys stick."
    ;;
esac
if findmnt -n "$part" 2>/dev/null | grep -q plex-usb; then
  die "Refusing partition currently mounted as plex-usb."
fi
if [[ -n "$USB_BY_ID" ]] && ! grep -qi 'norelsys' <<<"$USB_BY_ID"; then
  echo "WARN: USB_BY_ID is not the Norelsys stick — continuing with explicit override." >&2
fi

mkdir -p "$STICK_MNT" "$VAULT_MNT"
if ! findmnt -n "$STICK_MNT" >/dev/null 2>&1; then
  fstype=$(lsblk -nr -o FSTYPE "$part" | head -1)
  case "${fstype,,}" in
    vfat|fat32) mount -t vfat "$part" "$STICK_MNT" -o rw,uid=0,gid=0,umask=0077 ;;
    exfat) mount -t exfat "$part" "$STICK_MNT" -o rw,uid=0,gid=0,umask=0077 ;;
    ntfs|ntfs3) mount -t ntfs3 "$part" "$STICK_MNT" -o rw 2>/dev/null || mount -t ntfs-3g "$part" "$STICK_MNT" -o rw ;;
    *) mount "$part" "$STICK_MNT" ;;
  esac
fi

vault_dir="$STICK_MNT/$VAULT_FOLDER"
img="$vault_dir/$IMG_NAME"
meta="$vault_dir/vault-meta.json"
mkdir -p "$vault_dir"

if [[ -e "$img" ]]; then
  die "Vault image already exists: $img — dismount/remove first or pick another stick."
fi

need=$((SIZE_MB + 16))
avail_kb=$(df -Pk "$STICK_MNT" | awk 'NR==2{print $4}')
avail_mb=$((avail_kb / 1024))
[[ "$avail_mb" -ge "$need" ]] || die "Need ~${need} MB free on USB; only ${avail_mb} MB available."

if [[ -z "$PASSPHRASE" ]]; then
  PASSPHRASE=$(openssl rand -base64 24 | tr -d '/+=' | head -c 28)
  GENERATED=1
else
  GENERATED=0
fi
[[ ${#PASSPHRASE} -ge 10 ]] || die "PASSPHRASE must be at least 10 characters."

echo "==> Creating ${SIZE_MB} MB LUKS image at $img ..."
dd if=/dev/zero of="$img" bs=1M count="$SIZE_MB" status=progress
# LUKS2 format (batch)
printf '%s' "$PASSPHRASE" | cryptsetup luksFormat --type luks2 --batch-mode "$img" -
printf '%s' "$PASSPHRASE" | cryptsetup open --key-file - "$img" "$MAPPER_NAME"
mkfs.ext4 -L SM-Keys "/dev/mapper/$MAPPER_NAME" >/dev/null
mount "/dev/mapper/$MAPPER_NAME" "$VAULT_MNT"
mkdir -p "$VAULT_MNT/ssh"
chmod 700 "$VAULT_MNT/ssh"
cat >"$VAULT_MNT/ssh/README.txt" <<'EOF'
ServerManager USB key vault (Proxmox / Linux LUKS)
Keep private keys in this volume only.
Dismount when finished so keys are not left unlocked.
This is NOT a YubiKey — keys can be copied while unlocked.
EOF

python3 - <<PY
import json, datetime
meta = {
  "created_at": datetime.datetime.now().isoformat(),
  "usb_partition": "$part",
  "img_path": "$img",
  "mapper": "$MAPPER_NAME",
  "vault_mount": "$VAULT_MNT",
  "stick_mount": "$STICK_MNT",
  "size_mb": $SIZE_MB,
  "purpose": "ServerManager SSH private key vault (LUKS file on USB)",
  "not_yubikey": True,
}
open("$meta", "w", encoding="utf-8").write(json.dumps(meta, indent=2) + "\n")
PY

mkdir -p /var/lib/servermanager-key-vault
cat >/var/lib/servermanager-key-vault/last-mount.json <<EOF
{"img_path":"$img","mapper":"$MAPPER_NAME","vault_mount":"$VAULT_MNT","stick_mount":"$STICK_MNT","mounted_at":"$(date -Iseconds)"}
EOF
chmod 600 /var/lib/servermanager-key-vault/last-mount.json

echo
echo "Vault ready."
echo "  USB folder : $vault_dir"
echo "  LUKS image : $img"
echo "  Mounted at : $VAULT_MNT/ssh/"
if [[ "$GENERATED" -eq 1 ]]; then
  echo
  echo "════════════════════════════════════════════════════════"
  echo "  SAVE THIS LUKS PASSPHRASE (shown once):"
  echo "  $PASSPHRASE"
  echo "════════════════════════════════════════════════════════"
  echo "  Store it in a password manager. It is NOT saved on disk."
fi
echo
echo "Next: bash new-sm-usb-ssh-key.sh"
echo "Then: bash dismount-sm-usb-key-vault.sh"
