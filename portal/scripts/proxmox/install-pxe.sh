#!/bin/bash
# Install PXE / network boot on a Proxmox VE host (Debian/PVE).
# Safe to re-run. Expects LAN 192.168.8.0/24 and bridge vmbr0.
set -euo pipefail

TFTP="${TFTP:-/srv/tftp}"
PVE_IP="${PVE_IP:-192.168.8.160}"
BRIDGE="${BRIDGE:-vmbr0}"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq dnsmasq pxelinux syslinux-common syslinux-efi ipxe wget curl ca-certificates tftp-hpa

mkdir -p "$TFTP/pxelinux.cfg" "$TFTP/efi64"

cp -f /usr/lib/PXELINUX/pxelinux.0 "$TFTP/"
cp -f /usr/lib/syslinux/modules/bios/ldlinux.c32 "$TFTP/"
cp -f /usr/lib/syslinux/modules/bios/menu.c32 "$TFTP/"
cp -f /usr/lib/syslinux/modules/bios/libutil.c32 "$TFTP/"
cp -f /usr/lib/syslinux/modules/bios/libcom32.c32 "$TFTP/" 2>/dev/null || true
cp -f /usr/lib/syslinux/modules/bios/vesamenu.c32 "$TFTP/" 2>/dev/null || true
cp -f /usr/lib/syslinux/modules/bios/reboot.c32 "$TFTP/" 2>/dev/null || true

for f in ipxe.efi ipxe.lkrn undionly.kpxe snponly.efi; do
  [ -f "/usr/lib/ipxe/$f" ] && cp -f "/usr/lib/ipxe/$f" "$TFTP/"
done
# Debian sometimes names the EFI binary differently
if [ ! -f "$TFTP/ipxe.efi" ]; then
  find /usr/lib/ipxe -name '*.efi' -exec cp -f {} "$TFTP/ipxe.efi" \; -quit 2>/dev/null || true
fi

wget -q -O "$TFTP/netboot.xyz.kpxe" https://boot.netboot.xyz/ipxe/netboot.xyz.kpxe
wget -q -O "$TFTP/netboot.xyz.efi" https://boot.netboot.xyz/ipxe/netboot.xyz.efi

cat > "$TFTP/pxelinux.cfg/default" <<EOF
DEFAULT menu.c32
PROMPT 0
TIMEOUT 100
ONTIMEOUT local
MENU TITLE Proxmox PXE (${PVE_IP})

LABEL local
  MENU LABEL Boot from local disk
  LOCALBOOT 0

LABEL netbootxyz
  MENU LABEL netboot.xyz (many OS installers)
  KERNEL netboot.xyz.kpxe

LABEL ipxe
  MENU LABEL iPXE undionly
  KERNEL undionly.kpxe
EOF

cat > /etc/dnsmasq.d/pxe-boot.conf <<EOF
# PXE / network boot — proxyDHCP (Flint keeps real DHCP)
interface=${BRIDGE}
bind-interfaces
listen-address=${PVE_IP}
port=0
log-dhcp

dhcp-range=192.168.8.0,proxy,255.255.255.0

enable-tftp
tftp-root=${TFTP}
tftp-no-blocksize

dhcp-match=set:bios,option:client-arch,0
dhcp-match=set:efi-x86,option:client-arch,6
dhcp-match=set:efi-x64-bc,option:client-arch,7
dhcp-match=set:efi-x64,option:client-arch,9

dhcp-boot=tag:bios,pxelinux.0
dhcp-boot=tag:efi-x86,netboot.xyz.efi
dhcp-boot=tag:efi-x64-bc,netboot.xyz.efi
dhcp-boot=tag:efi-x64,netboot.xyz.efi

dhcp-no-override
EOF

systemctl enable dnsmasq
systemctl restart dnsmasq
systemctl --no-pager --full status dnsmasq | head -20
echo "OK PXE on ${PVE_IP} tftp=${TFTP}"
