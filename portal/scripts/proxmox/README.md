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
alienware-leds on|rainbow|off|auto|status
```

Portal Settings → Chassis LEDs calls the same binary over SSH (`on` = rainbow).