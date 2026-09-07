# Proxmox DNS (bypass Pi-hole)

Home LAN DNS normally goes:

`device → Flint → VPN → AdGuard → Pi-hole → Unbound`

That path can break Proxmox updates. These scripts send **only** the Proxmox host (`192.168.8.160`) to public DNS (`1.1.1.1`).

## Apply

From the VPS (with Flint reachable over OpenVPN):

```bash
# 1) Flint: DNAT Proxmox DNS away from Pi-hole
ROUTER_HOST=10.9.0.2 ROUTER_PASS='...' ./bypass-pihole-dns.sh

# 2) Allowlist Proxmox domains for other devices still on Pi-hole
./pihole-allow-proxmox.sh
```

After (1), renew DHCP on Proxmox if it uses DHCP. Static DNS to the router is rewritten by Flint DNAT either way.

## Network boot (PXE)

See [PXE.md](./PXE.md) and `./install-pxe.sh`.

## Chassis LEDs (Alienware AW-ELC)

`alienware-leds` on the Proxmox host drives:

- Alienware AW-ELC USB `187c:0550` (Aurora R14 ≈ **77** zones, ≤25 IDs/packet)
- `alienware-wmi` global brightness + `rgb_zones`

**On / rainbow** plays an OpenRGB-style spectrum morph (phased wave across zones).
**Off** is ARGB-safe: static black at dim 0 (keeps the data line alive). A
one-minute refresh timer reasserts black while state=off.

```bash
install -m 755 alienware-leds /usr/local/sbin/alienware-leds
install -m 755 aw-elc-usb-owner /usr/local/sbin/aw-elc-usb-owner
alienware-leds on|rainbow|off|auto|status
aw-elc-usb-owner status|to-windows|to-host
```

### Windows FX Lighting handoff (full motherboard lighting)

Motherboard lighting can only be owned by **one** side at a time:

- **Host (portal)** — Settings → Rainbow / Off / schedule (`alienware-leds` + `alienware-wmi`)
- **Windows VM 100** (`win11-pro-gpu`) — Alienware FX Lighting / AWCC

`to-windows` does both:

1. Pass AW-ELC USB `187c:0550` into VM 100
2. Unload + blacklist host `alienware-wmi` so Linux is not driving `rgb_zones`

The chipset USB controller is **not** PCI-passed (same IOMMU group as SATA + NIC).

```bash
aw-elc-usb-owner to-windows   # full motherboard lighting → Windows FX
# …set effects in Alienware FX Lighting / AWCC…
aw-elc-usb-owner to-host      # reclaim USB + reload alienware-wmi
```

Portal Settings: **Windows (FX Lighting)** / **Return to host**.
When FX looks right, say so and we can copy those settings onto the host script.

Portal Settings → Chassis LEDs calls these binaries over SSH (`on` = rainbow).