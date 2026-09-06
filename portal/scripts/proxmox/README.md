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

`alienware-leds` talks to USB `187c:0550` on the Proxmox host (Aurora R14 reports **77** zones). Install on the host:

```bash
install -m 755 alienware-leds /usr/local/sbin/alienware-leds
alienware-leds on|off|auto|status
```

Dim/color updates are split into packets of ≤25 zone IDs. Portal Settings calls the same binary over SSH.
