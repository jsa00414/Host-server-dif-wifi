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

`install-plex-lxc.sh` creates **CT 101** (`plex-server` @ `192.168.8.161`) with **Plex Media Server** on `:32400` (not Plex player/desktop).

Plex is **not** embedded in the portal. Use the Proxmox container (and optional public URL).

```bash
# On Proxmox host:
./install-plex-lxc.sh
# Optional: reverse-proxy prefs + NAS media mount (needs /root/.plex-nas.cred)
./configure-plex-server.sh

# Or from the VPS:
scp install-plex-lxc.sh configure-plex-server.sh root@192.168.8.160:/tmp/
ssh root@192.168.8.160 bash /tmp/install-plex-lxc.sh
ssh root@192.168.8.160 bash /tmp/configure-plex-server.sh
```

- **Claim/setup (use this):** **https://plex.vpstruelord.com/web**
- LAN IP `http://192.168.8.161:32400/web` only works on **home Wi‑Fi** or **home VPN** (not from the public internet)
- Media (if NAS mounted): `/mnt/media` inside the CT
- WD Elements USB (host `/mnt/plex-usb` → CT `/mnt/usb`): detach from Windows VM 100, then:

```bash
# From repo (needs VPS_SSH_*):
python3 portal/scripts/proxmox/run-mount-plex-usb-via-vps.py
# Or on Proxmox:
./mount-plex-usb.sh && ./add-plex-usb-libraries.sh
```

Creates Plex libraries **USB Movies** / **USB TV** from folders like `Movies`, `New Movies`, `Kids Movies`, `TV Shows`, etc.

`DisableRemoteSecurity=1` is set until first claim so the public URL can finish setup.
