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

## Chassis LEDs (Alienware AW-ELC)

`alienware-leds` on the Proxmox host drives:

- Alienware AW-ELC USB `187c:0550` (Aurora R14 ≈ **77** zones, ≤25 IDs/packet)
- `alienware-wmi` global brightness + `rgb_zones`

**Spectrum / on** plays a synced rainbow across all zones.
**Off** is ARGB-safe: static black at dim 0 (keeps the data line alive).

```bash
install -m 755 alienware-leds /usr/local/sbin/alienware-leds
install -m 755 aw-elc-usb-owner /usr/local/sbin/aw-elc-usb-owner
alienware-leds on|rainbow|off|auto|status
aw-elc-usb-owner status|to-windows|to-host
```

Motherboard lighting can only be owned by **one** side at a time (host script vs Windows VM FX Lighting). Portal **Settings → Chassis lighting** calls these binaries over SSH (`on` = spectrum).

AW-ELC uses USB slot **`usb5`** by default (Bluetooth occupies **`usb4`**).

## Bluetooth (Windows VM)

`bt-usb-owner` hands the Realtek Bluetooth Radio USB `0bda:2852` (RTL8852 companion) between the Proxmox host and **Windows VM 100**, so controllers / headsets work in Windows when you use the PC over VPN / remote.

```bash
install -m 755 bt-usb-owner /usr/local/sbin/bt-usb-owner
bt-usb-owner status|to-windows|to-host
```

Portal **Settings → Bluetooth** calls this over SSH. Default slot is **`usb4`** (`host=0bda:2852,usb3=1`).

## Xbox controller (Windows VM)

`xbox-usb-owner` hands the Microsoft Xbox Series USB controller `045e:0b12` between the Proxmox host and **Windows VM 100**.

Do **not** map the same port twice (e.g. both `usb2: host=1-1` and `usb5: host=1-1`) — that makes the pad reconnect in a loop and fail in Windows.

```bash
install -m 755 xbox-usb-owner /usr/local/sbin/xbox-usb-owner
xbox-usb-owner status|to-windows|to-host
```

Portal **Settings → Xbox controller** calls this over SSH. Default slot is **`usb2`** (`host=045e:0b12,usb3=1`). Host `xpad` is blacklisted while Windows owns it.

## Elements USB → Plex

`elements-plex-hookup` mounts WD Elements (`1058:25a3`) at `/mnt/plex-usb` and binds it into **Plex CT 101** at `/mnt/usb`.

```bash
install -m 755 elements-plex-hookup /usr/local/sbin/elements-plex-hookup
install -m 755 mount-plex-usb.sh /usr/local/sbin/mount-plex-usb
elements-plex-hookup install          # udev + timer + auto-on
elements-plex-hookup status|attach|auto-on|auto-off
```

Portal **Settings → Elements USB (Plex)** shows status, **Attach to Plex**, and an **Auto-hookup** switch.

## Seagate 8TB → Windows VM (1TB slice)

`attach-tu-1tb-to-vm.sh` registers LVM storage `tu-hdd` on VG `tu` (Seagate ST8000DM004 `/dev/sda`) and attaches a **1TB** LV to VM **100** as `sata2`. Remaining ~6.28T stays free on the VG.

```bash
# On Proxmox:
./attach-tu-1tb-to-vm.sh attach
./attach-tu-1tb-to-vm.sh status
```

In Windows: Disk Management → Rescan Disks → Initialize/format the new disk.
