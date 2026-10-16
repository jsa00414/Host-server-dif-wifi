# USB encrypted key vault

Creates a **private virtual drive** on a USB stick and stores your SSH private
key inside it. Mount only when you need admin access; dismount when done so the
key is not sitting unlocked.

## Important limitation

This is **not** the same as a YubiKey / TPM hardware key.

| | USB vault (this) | YubiKey / TPM |
|---|---|---|
| Key leaves the device? | Yes, while vault is unlocked | No (signs inside the chip) |
| If malware runs while unlocked | Key can be stolen | Much harder |
| Offline theft of USB | Protected by LUKS / BitLocker password | PIN + touch still required |

## Proxmox host (primary — ~128GB Norelsys stick)

Your key stick is the **Norelsys ~128GB** flash drive on the Proxmox PC
(`/dev/disk/by-id/usb-NORELSYS_1081_…`). The **WD Elements** Plex drive is
never used.

Requires root on Proxmox (or run via VPS hop).

```bash
# From this repo (cloud agent / laptop with VPS access):
python3 portal/scripts/security/usb-key-vault/run-usb-key-vault-via-vps.py setup

# Or on the Proxmox host directly:
cd /path/to/usb-key-vault
USB_BY_ID=/dev/disk/by-id/usb-NORELSYS_1081_F9CB2147CF3A-0:0 \
  bash ./new-sm-usb-key-vault.sh          # prints LUKS passphrase once — save it
bash ./new-sm-usb-ssh-key.sh             # prints public key for portal
bash ./dismount-sm-usb-key-vault.sh

# Later, when you need SSH:
PASSPHRASE='…' bash ./mount-sm-usb-key-vault.sh
# optional: ADD_TO_SSH_AGENT=1 …
bash ./dismount-sm-usb-key-vault.sh
```

### Layout on the USB

```
<USB>:/ServerManagerKeyVault/
  ServerManagerKeys.img     # LUKS2 virtual drive (~256 MB)
  vault-meta.json           # mount hints (no secrets)
```

Inside the unlocked vault (`/mnt/sm-key-vault`):

```
/ssh/
  id_ed25519                # private key (never leave the vault)
  id_ed25519.pub            # public key (safe to copy)
  README.txt
```

Copy the **public** key into portal Security → VPS SSH keys. Keep the
**private** key only on the USB vault.

## Windows PC (optional)

PowerShell scripts (`New-SmUsbKeyVault.ps1`, etc.) create a VHDX + BitLocker
vault the same way if the stick is plugged into a Windows machine instead.

## Hide a recovery note inside a PNG (steganography)

`stego-text-in-png.py` embeds short text in the low bits of a PNG. Useful for a
**recovery reminder** you keep offline (e.g. printed or on another drive). This
is concealment, not strong crypto — use `--password`, or encrypt first.

```bash
# Hide (generates a plain cover PNG if you don't pass --cover)
python3 stego-text-in-png.py hide --out vault-hint.png \
  --text 'LUKS: …' --password 'recall-phrase'

# Reveal
python3 stego-text-in-png.py reveal --image vault-hint.png --password 'recall-phrase'
```

Or use a real photo: `--cover myphoto.png --out vault-hint.png`.

## Out of scope

True hardware-backed portal step-up (WebAuthn / YubiKey) is separate work.
