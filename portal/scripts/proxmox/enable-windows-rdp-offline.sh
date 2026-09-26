#!/bin/bash
# Enable RDP on Windows VM 100 using virt-win-reg (guestfs-tools) — no apt.
set -euo pipefail
VMID="${VMID:-100}"
DISK="${DISK:-/dev/pve/vm-${VMID}-disk-1}"
export LIBGUESTFS_BACKEND=direct

echo "==> cleanup stale guestfs"
pkill -9 -f "guestmount -a ${DISK}" 2>/dev/null || true
pkill -9 -f "qemu-system-x86_64.*guestfs" 2>/dev/null || true
sleep 1

command -v virt-win-reg >/dev/null || { echo "missing virt-win-reg"; exit 1; }
[[ -e "$DISK" ]] || { echo "missing $DISK"; exit 1; }

st=$(qm status "$VMID" | awk '{print $2}')
if [[ "$st" != "stopped" ]]; then
  echo "Stopping VM $VMID…"
  qm stop "$VMID" --timeout 90 || true
  sleep 2
fi
qm status "$VMID"

echo "==> Detect Current control set"
# Read Select\\Current
CUR=$(virt-win-reg "$DISK" 'HKLM\SYSTEM\Select' 2>/dev/null | awk -F: '/Current/ {gsub(/[^0-9]/,"",$2); print $2; exit}')
CUR=${CUR:-1}
CCS=$(printf 'ControlSet%03d' "$CUR")
echo "Using $CCS"

echo "==> Enable RDP + open firewall (disable firewall profiles)"
# Import a .reg via virt-win-reg --merge
REG=/tmp/enable-rdp.reg
cat > "$REG" <<EOF
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\\SYSTEM\\${CCS}\\Control\\Terminal Server]
"fDenyTSConnections"=dword:00000000

[HKEY_LOCAL_MACHINE\\SYSTEM\\${CCS}\\Control\\Terminal Server\\WinStations\\RDP-Tcp]
"UserAuthentication"=dword:00000000

[HKEY_LOCAL_MACHINE\\SYSTEM\\${CCS}\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile]
"EnableFirewall"=dword:00000000

[HKEY_LOCAL_MACHINE\\SYSTEM\\${CCS}\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile]
"EnableFirewall"=dword:00000000

[HKEY_LOCAL_MACHINE\\SYSTEM\\${CCS}\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile]
"EnableFirewall"=dword:00000000
EOF

virt-win-reg --merge "$DISK" "$REG"
echo "Registry OK"

echo "==> Starting VM"
qm start "$VMID"
sleep 5
qm status "$VMID"
echo DONE
