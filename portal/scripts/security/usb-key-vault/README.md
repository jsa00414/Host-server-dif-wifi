# USB encrypted key vault (Windows)

Creates a **private virtual drive (VHDX)** on a USB stick and stores your SSH
private key inside it. Mount the vault only when you need admin access; dismount
when done so the key is not sitting unlocked on the PC.

## Important limitation

This is **not** the same as a YubiKey / TPM hardware key.

| | USB VHDX vault (this) | YubiKey / TPM |
|---|---|---|
| Key leaves the device? | Yes, while vault is unlocked | No (signs inside the chip) |
| If malware runs while unlocked | Key can be stolen | Much harder |
| Offline theft of USB | Protected if BitLocker password is strong | PIN + touch still required |

Use this as a **strong improvement** over keys living in `C:\Users\…\.ssh`.
For true hardware-backed portal step-up, add WebAuthn / YubiKey later.

## Requirements

- Windows 10/11
- PowerShell **as Administrator** (creating/mounting VHDX + BitLocker)
- OpenSSH Client optional (`ssh-keygen`, `ssh-add`) — Windows optional feature
- A USB drive with ~1 GB free

## Quick start (on the PC where the USB is plugged in)

```powershell
cd path\to\repo\portal\scripts\security\usb-key-vault

# 1) Create 256 MB encrypted virtual drive on the USB
.\New-SmUsbKeyVault.ps1 -SizeMB 256 -BitLocker

# 2) Generate an ed25519 key inside the vault (do not copy the private key off it)
.\New-SmUsbSshKey.ps1 -Comment "james@vpstruelord-usb"

# 3) When you need SSH: mount + load into agent (asks confirmation)
.\Mount-SmUsbKeyVault.ps1 -AddToSshAgent

# 4) When finished: unload agent key + dismount vault
.\Dismount-SmUsbKeyVault.ps1
```

Copy the **public** key (`.pub`) into the portal Security → VPS SSH keys panel
(or `authorized_keys`). Keep the **private** key only on the USB vault.

## Files created on the USB

```
<USB>:\ServerManagerKeyVault\
  ServerManagerKeys.vhdx          # virtual drive image
  vault-meta.json                 # mount hints (no secrets)
```

Inside the mounted vault volume (drive letter varies):

```
\ssh\
  id_ed25519                      # private key (never leave the vault)
  id_ed25519.pub                  # public key (safe to copy)
  README.txt
```

## Tips

- Prefer **BitLocker** (`-BitLocker`) so a lost USB is not readable.
- After mounting, confirm the vault drive letter in Explorer before generating keys.
- Use `ssh-add -D` (or `Dismount-SmUsbKeyVault.ps1`) so keys do not stay in the agent.
- For portal login step-up, this vault does not replace Authenticator TOTP yet —
  that needs WebAuthn in the portal (separate work).
