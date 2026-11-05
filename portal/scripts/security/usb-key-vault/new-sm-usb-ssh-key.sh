#!/usr/bin/env bash
# Generate ed25519 SSH key inside the mounted ServerManager USB key vault.
set -euo pipefail

VAULT_MNT="${VAULT_MNT:-/mnt/sm-key-vault}"
COMMENT="${COMMENT:-servermanager-usb-vault}"
KEY_NAME="${KEY_NAME:-id_ed25519}"
FORCE="${FORCE:-0}"
KEY_PASSPHRASE="${KEY_PASSPHRASE:-}"  # empty = ssh-keygen interactive, or set for batch

die() { echo "ERROR: $*" >&2; exit 1; }
[[ "$(id -u)" -eq 0 ]] || die "Run as root on the Proxmox host."
command -v ssh-keygen >/dev/null || die "ssh-keygen missing"

ssh_dir="$VAULT_MNT/ssh"
[[ -d "$ssh_dir" ]] || die "Vault not mounted at $VAULT_MNT — run mount-sm-usb-key-vault.sh first."

key="$ssh_dir/$KEY_NAME"
pub="$key.pub"
if [[ -e "$key" && "$FORCE" != "1" ]]; then
  die "Private key already exists: $key (set FORCE=1 to overwrite)"
fi
rm -f "$key" "$pub"

echo "==> Generating ed25519 key at $key ..."
if [[ -n "$KEY_PASSPHRASE" ]]; then
  ssh-keygen -t ed25519 -f "$key" -C "$COMMENT" -N "$KEY_PASSPHRASE"
else
  # Batch-safe default: empty key passphrase (vault LUKS already encrypts at rest).
  # Prefer setting KEY_PASSPHRASE for defense in depth.
  ssh-keygen -t ed25519 -f "$key" -C "$COMMENT" -N ""
fi
chmod 600 "$key"
chmod 644 "$pub"

echo
echo "Key pair created."
echo "  Private : $key  (keep only on this vault — never copy off)"
echo "  Public  : $pub"
echo
echo "Public key (paste into portal Security → VPS SSH keys):"
cat "$pub"
echo
echo "When finished: bash dismount-sm-usb-key-vault.sh"
