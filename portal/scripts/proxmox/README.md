# Proxmox host scripts

## DNS (bypass Pi-hole)

Home LAN DNS normally goes:

`device → Flint → VPN → AdGuard → Pi-hole → Unbound`

That path can break Proxmox updates. These scripts send **only** the Proxmox host (`192.168.8.160`) to public DNS (`1.1.1.1`).

### Apply

From the VPS (with Flint reachable over OpenVPN):

```bash
# 1) Flint: DNAT Proxmox DNS away from Pi-hole
ROUTER_HOST=10.9.0.2 ROUTER_PASS='...' ./bypass-pihole-dns.sh

# 2) Allowlist Proxmox domains for other devices still on Pi-hole
./pihole-allow-proxmox.sh
```

After (1), renew DHCP on Proxmox if it uses DHCP. Static DNS to the router is rewritten by Flint DNAT either way.

## Plex LXC

`install-plex-lxc.sh` creates **CT 101** (`plex` @ `192.168.8.161`) with Plex Media Server on `:32400`.

```bash
# On Proxmox host:
./install-plex-lxc.sh

# Or from the VPS:
scp install-plex-lxc.sh root@192.168.8.160:/tmp/
ssh root@192.168.8.160 bash /tmp/install-plex-lxc.sh
```

Portal exposes it as **https://plex.vpstruelord.com/web** (Network → Plex tab).
