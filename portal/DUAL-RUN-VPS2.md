# VPS cutover complete → `74.208.76.213`

Primary is now **74.208.76.213** (`vps2.vpstruelord.com`). Old `74.208.54.132` is retired.

## Live now

| Service | URL |
| --- | --- |
| Portal | https://portal.vpstruelord.com/ |
| WireGuard UI | https://vpn.vpstruelord.com/ (or `:5001`) |
| AdGuard | https://dns.vpstruelord.com/ |
| Pi-hole | https://pihole.vpstruelord.com/ |

Cloudflare A records for `*.vpstruelord.com` point at **74.208.76.213**.  
Caddy has real TLS again. Dual-run bridge to the old VPS is removed.  
WireGuard peers restored (same keys); server endpoint host = `74.208.76.213:5000`.

## Required once: update Flint (home GL-MT6000)

LAN / Buffalo stay down until Flint’s WireGuard **Endpoint** leaves the old IP:

1. On home Wi‑Fi open http://192.168.8.1  
2. VPN → WireGuard → edit **GL-MT6000**  
3. Set Endpoint to **`74.208.76.213:5000`**  
   - or re-import from https://vpn.vpstruelord.com  
4. Enable / reconnect  

VPS copy of the client config: `/root/GL-MT6000-new-vps.conf`

After reconnect: `ping 10.8.0.3` and Buffalo from the portal should work.

## Manual DNS (truemailor.com)

This Cloudflare token only manages `vpstruelord.com`. Still on the old IP:

- `mail.truemailor.com`
- `truemailor.com`
- `remote.truemailor.com`

Point those A records to **74.208.76.213** at their DNS provider.

## Deploy portal

```bash
VPS=root@74.208.76.213 ./portal/deploy-to-vps.sh
```
