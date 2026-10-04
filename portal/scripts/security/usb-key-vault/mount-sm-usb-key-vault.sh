#!/usr/bin/env bash
# Mount / unlock the ServerManager LUKS USB key vault on Proxmox/Linux.
set -euo pipefail

VAULT_FOLDER="${VAULT_FOLDER:-ServerManagerKeyVault}"
IMG_NAME="${IMG_NAME:-ServerManagerKeys.img}"
MAPPER_NAME="${MAPPER_NAME:-sm-key-vault}"
STICK_MNT="${STICK_MNT:-/mnt/sm-usb-stick}"
VAULT_MNT="${VAULT_MNT:-/mnt/sm-key-vault}"
USB_BY_ID="${USB_BY_ID:-}"
PASSPHRASE="${PASSPHRASE:-}"
ADD_TO_SSH_AGENT="${ADD_TO_SSH_AGENT:-0}"
AGENT_TTL_MINUTES="${AGENT_TTL_MINUTES:-60}"

die() { echo "ERROR: $*" >&2; exit 1; }
[[ "$(id -u)" -eq 0 ]] || die "Run as root on the Proxmox host."

pick_usb_partition() {
  if [[ -n "$USB_BY_ID" ]]; then
    local cand
    cand=$(readlink -f "$USB_BY_ID")
    if [[ -b "${cand}1" ]]; then echo "${cand}1"; return; fi
    if lsblk -nr -o TYPE "$cand" | grep -qx part; then echo "$cand"; return; fi
    die "No partition for $USB_BY_ID"
  fi
  local cand part
  for cand in /dev/disk/by-id/usb-NORELSYS_* /dev/disk/by-id/usb-Norelsys_*; do
    [[ -e "$cand" ]] || continue
    [[ "$cand" =~ part ]] && continue
    part=$(readlink -f "$cand")
    [[ -b "${part}1" ]] && { echo "${part}1"; return; }
  done
  # Look for stick already containing the vault folder while mounted, or scan FAT labels
  local name tran model
  while read -r name tran model; do
    [[ "$tran" == "usb" ]] || continue
    [[ "$model" == *Elements* || "$model" == *WDC* ]] && continue
    [[ -b "/dev/${name}1" ]] || continue
    echo "/dev/${name}1"
    return
  done < <(lsblk -dn -o NAME,TRAN,MODEL)
  die "Key USB not found. Plug in the ~128GB Norelsys stick or set USB_BY_ID."
}

part=$(pick_usb_partition)
label=$(lsblk -nr -o LABEL "$part" || true)
[[ "$label" != "Elements" ]] || die "Refusing WD Elements."

mkdir -p "$STICK_MNT" "$VAULT_MNT"
if ! findmnt -n "$STICK_MNT" >/dev/null 2>&1; then
  fstype=$(lsblk -nr -o FSTYPE "$part" | head -1)
  case "${fstype,,}" in
    vfat|fat32) mount -t vfat "$part" "$STICK_MNT" -o rw,uid=0,gid=0,umask=0077 ;;
    *) mount "$part" "$STICK_MNT" ;;
  esac
fi

img="$STICK_MNT/$VAULT_FOLDER/$IMG_NAME"
[[ -f "$img" ]] || die "Vault image missing: $img — run new-sm-usb-key-vault.sh first."

if [[ ! -e "/dev/mapper/$MAPPER_NAME" ]]; then
  if [[ -z "$PASSPHRASE" ]]; then
    # Interactive when possible
    if [[ -t 0 ]]; then
      cryptsetup open "$img" "$MAPPER_NAME"
    else
      die "Set PASSPHRASE=... to unlock non-interactively."
    fi
  else
    printf '%s' "$PASSPHRASE" | cryptsetup open --key-file - "$img" "$MAPPER_NAME"
  fi
fi

if ! findmnt -n "$VAULT_MNT" >/dev/null 2>&1; then
  mount "/dev/mapper/$MAPPER_NAME" "$VAULT_MNT"
fi
mkdir -p "$VAULT_MNT/ssh"
chmod 700 "$VAULT_MNT/ssh"

mkdir -p /var/lib/servermanager-key-vault
cat >/var/lib/servermanager-key-vault/last-mount.json <<EOF
{"img_path":"$img","mapper":"$MAPPER_NAME","vault_mount":"$VAULT_MNT","stick_mount":"$STICK_MNT","mounted_at":"$(date -Iseconds)"}
EOF
chmod 600 /var/lib/servermanager-key-vault/last-mount.json

echo "Vault mounted at $VAULT_MNT/ssh/"

if [[ "$ADD_TO_SSH_AGENT" == "1" ]]; then
  key="$VAULT_MNT/ssh/id_ed25519"
  if [[ ! -f "$key" ]]; then
    echo "WARN: no private key at $key — run new-sm-usb-ssh-key.sh" >&2
  else
    if ! pgrep -u root ssh-agent >/dev/null 2>&1; then
      eval "$(ssh-agent -s)"
      echo "export SSH_AUTH_SOCK=$SSH_AUTH_SOCK" >/var/lib/servermanager-key-vault/agent.env
      echo "export SSH_AGENT_PID=$SSH_AGENT_PID" >>/var/lib/servermanager-key-vault/agent.env
      chmod 600 /var/lib/servermanager-key-vault/agent.env
    elif [[ -f /var/lib/servermanager-key-vault/agent.env ]]; then
      # shellcheck disable=SC1091
      source /var/lib/servermanager-key-vault/agent.env
    fi
    ssh-add -t "$((AGENT_TTL_MINUTES * 60))" "$key"
    echo "Key loaded into ssh-agent for ~${AGENT_TTL_MINUTES} minutes."
  fi
fi
