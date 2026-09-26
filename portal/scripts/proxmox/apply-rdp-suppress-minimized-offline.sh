#!/bin/bash
# Set RemoteDesktop_SuppressWhenMinimized=2 on Windows VM 100 (RDP client)
# so minimizing mstsc does not throttle the remote session / webcam.
# Uses virt-win-reg (offline). Run on Proxmox as root.
set -euo pipefail
VMID="${VMID:-100}"
DISK="${DISK:-/dev/pve/vm-${VMID}-disk-1}"
# NOTE: James-Gaming-PC C: is BitLocker-encrypted — virt-win-reg cannot
# merge into the live OS volume. Prefer in-guest .ps1/.reg or QEMU sendkeys.
# Boot disk may be sda4 VG; pve disk-1 still holds EFI + BitLocker C:.
export LIBGUESTFS_BACKEND=direct

echo "==> cleanup stale guestfs"
pkill -9 -f "guestmount -a ${DISK}" 2>/dev/null || true
pkill -9 -f "qemu-system-x86_64.*guestfs" 2>/dev/null || true
sleep 1

command -v virt-win-reg >/dev/null || { echo "missing virt-win-reg"; exit 1; }
[[ -e "$DISK" ]] || { echo "missing $DISK"; exit 1; }

st=$(qm status "$VMID" | awk '{print $2}')
WAS_RUNNING=0
if [[ "$st" != "stopped" ]]; then
  WAS_RUNNING=1
  echo "Stopping VM $VMID for offline registry edit…"
  qm stop "$VMID" --timeout 90 || true
  sleep 2
fi
qm status "$VMID"

REG=/tmp/rdp-suppress-minimized.reg
cat >"$REG" <<'EOF'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Terminal Server Client]
"RemoteDesktop_SuppressWhenMinimized"=dword:00000002
EOF

echo "==> Merge HKLM Terminal Server Client SuppressWhenMinimized=2"
virt-win-reg --merge "$DISK" "$REG"
echo "Registry OK (HKLM)"

# Also stamp each user NTUSER.DAT (HKCU) via guestmount when available
if command -v guestmount >/dev/null && command -v hivexregedit >/dev/null; then
  MNT=$(mktemp -d /tmp/win100-mnt-XXXXXX)
  cleanup() { guestunmount "$MNT" 2>/dev/null || umount "$MNT" 2>/dev/null || true; rmdir "$MNT" 2>/dev/null || true; }
  trap cleanup EXIT
  echo "==> Mounting Windows volume to patch HKCU NTUSER.DAT hives"
  if guestmount -a "$DISK" -i --ro=false "$MNT" 2>/dev/null || guestmount -a "$DISK" -i "$MNT"; then
    USER_REG=/tmp/rdp-suppress-minimized-hkcu.reg
    cat >"$USER_REG" <<'EOF'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\Software\Microsoft\Terminal Server Client]
"RemoteDesktop_SuppressWhenMinimized"=dword:00000002
EOF
    # hivexregedit merges into a hive file; path is relative to hive root so we fake HKLM->root
    cat >"$USER_REG" <<'EOF'
Windows Registry Editor Version 5.00

[\Software\Microsoft\Terminal Server Client]
"RemoteDesktop_SuppressWhenMinimized"=dword:00000002
EOF
    count=0
    while IFS= read -r -d '' hive; do
      echo "  patch $hive"
      hivexregedit --merge "$hive" "$USER_REG" && count=$((count + 1)) || true
    done < <(find "$MNT/Users" -maxdepth 2 -iname 'NTUSER.DAT' -print0 2>/dev/null)
    # Default user profile
    if [[ -f "$MNT/Users/Default/NTUSER.DAT" ]]; then
      hivexregedit --merge "$MNT/Users/Default/NTUSER.DAT" "$USER_REG" && count=$((count + 1)) || true
    fi
    echo "HKCU hives patched: $count"
    guestunmount "$MNT" 2>/dev/null || umount "$MNT" 2>/dev/null || true
    trap - EXIT
    rmdir "$MNT" 2>/dev/null || true
  else
    echo "guestmount failed — HKLM merge alone should still work"
  fi
else
  echo "guestmount/hivexregedit not available — HKLM merge alone should still work"
fi

if [[ "$WAS_RUNNING" -eq 1 ]]; then
  echo "==> Starting VM $VMID"
  qm start "$VMID"
  sleep 5
fi
qm status "$VMID"
echo DONE
