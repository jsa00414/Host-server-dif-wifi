#!/usr/bin/env bash
# Unload SSH keys and dismount the ServerManager LUKS USB key vault.
set -euo pipefail

MAPPER_NAME="${MAPPER_NAME:-sm-key-vault}"
STICK_MNT="${STICK_MNT:-/mnt/sm-usb-stick}"
VAULT_MNT="${VAULT_MNT:-/mnt/sm-key-vault}"
KEEP_AGENT_KEYS="${KEEP_AGENT_KEYS:-0}"

die() { echo "ERROR: $*" >&2; exit 1; }
[[ "$(id -u)" -eq 0 ]] || die "Run as root on the Proxmox host."

if [[ "$KEEP_AGENT_KEYS" != "1" ]]; then
  if [[ -f /var/lib/servermanager-key-vault/agent.env ]]; then
    # shellcheck disable=SC1091
    source /var/lib/servermanager-key-vault/agent.env || true
  fi
  if [[ -n "${SSH_AUTH_SOCK:-}" ]] && command -v ssh-add >/dev/null; then
    ssh-add -D 2>/dev/null || true
  fi
fi

if findmnt -n "$VAULT_MNT" >/dev/null 2>&1; then
  echo "Unmounting $VAULT_MNT ..."
  umount "$VAULT_MNT"
fi

if [[ -e "/dev/mapper/$MAPPER_NAME" ]]; then
  echo "Closing LUKS mapper $MAPPER_NAME ..."
  cryptsetup close "$MAPPER_NAME"
fi

if findmnt -n "$STICK_MNT" >/dev/null 2>&1; then
  echo "Unmounting USB stick $STICK_MNT ..."
  umount "$STICK_MNT"
fi

rm -f /var/lib/servermanager-key-vault/last-mount.json
echo "Vault dismounted. Private keys are no longer accessible until you mount again."
