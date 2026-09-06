# Proxmox network boot (PXE)

Proxmox host `192.168.8.160` runs **dnsmasq** as:

- **proxyDHCP** (does not replace Flint DHCP leases)
- **TFTP** root `/srv/tftp`

## What clients get

| Firmware | Boot file |
|----------|-----------|
| BIOS/Legacy | `pxelinux.0` → menu (local disk / netboot.xyz) |
| UEFI | `netboot.xyz.efi` |

Flint DHCP also advertises option 66/67 → `192.168.8.160` / `pxelinux.0` for BIOS clients.

## Re-apply on Proxmox

```bash
# packages
apt-get install -y dnsmasq pxelinux syslinux-common syslinux-efi ipxe

# config lives at:
#   /etc/dnsmasq.d/pxe-boot.conf
#   /srv/tftp/
systemctl enable --now dnsmasq
```

## Boot a machine

1. Put the PC/VM on the `192.168.8.0/24` LAN (same as Flint).
2. Enable **network / PXE boot** in firmware (or set VM boot order to Network).
3. BIOS: pxelinux menu → choose **netboot.xyz** or local disk.
4. UEFI: netboot.xyz menu loads directly.

## Notes

- DNS on dnsmasq is disabled (`port=0`); only PXE + TFTP.
- For a Proxmox VE installer over PXE, add the ISO kernel/initrd under `/srv/tftp` and a `pxelinux.cfg` label.
