# Primary VPS: `74.208.76.213`

**Only VPS in use.** Former host `74.208.54.132` is decommissioned — no SSH/UI access, no dual-run bridge, do not point anything at it.

## Live now

| Service | URL |
| --- | --- |
| Portal | https://portal.vpstruelord.com/ |
| WireGuard UI | https://vpn.vpstruelord.com/ (or `:5001`) |
| AdGuard | https://dns.vpstruelord.com/ |
| Pi-hole | https://pihole.vpstruelord.com/ |

Cloudflare A records for `*.vpstruelord.com` → **74.208.76.213**.  
WireGuard server endpoint → **`74.208.76.213:5000`**.

## Flint (home GL-MT6000)

Endpoint must be **`74.208.76.213:5000`** (not the old IP):

1. On home Wi‑Fi open http://192.168.8.1  
2. VPN → WireGuard → edit **GL-MT6000**  
3. Set Endpoint to **`74.208.76.213:5000`** or re-import from https://vpn.vpstruelord.com  
4. Enable / reconnect  

VPS copy: `/root/GL-MT6000-new-vps.conf`

## Manual DNS (truemailor.com) — still required

Cloudflare token in portal env only manages **`vpstruelord.com`**. Update these A records at the `truemailor.com` DNS provider to **74.208.76.213**:

- `mail.truemailor.com`
- `truemailor.com`
- `remote.truemailor.com`

Until that change, those names still resolve to the dead old IP.

## Scrub leftover old-IP refs on this VPS

```bash
bash /opt/wireguard/port-forward-ui/scripts/security/retire-old-vps-ip.sh
```

## Deploy portal

```bash
VPS=root@74.208.76.213 ./portal/deploy-to-vps.sh
```
