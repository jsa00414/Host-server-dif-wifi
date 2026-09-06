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

## Chassis LEDs (Alienware AW-ELC + DeepCool)

`alienware-leds` on the Proxmox host drives:

- Alienware AW-ELC USB `187c:0550` (Aurora R14 ≈ **77** zones, ≤25 IDs/packet)
- `alienware-wmi` global brightness + `rgb_zones`
- DeepCool USB `3633:*` when present (Digital / LQ / LM)

ARGB-only DeepCool pumps (LS/LE) follow the motherboard 5V ARGB header. If that cable is on a power-only splitter, the pump stays in auto-rainbow and software cannot turn it off.

```bash
install -m 755 alienware-leds /usr/local/sbin/alienware-leds
# also keep /usr/local/sbin/alienware-leds as the path the portal calls
alienware-leds on|off|auto|status
```

Portal Settings calls the same binary over SSH.