# Dual-run: old VPS + new VPS (`74.208.76.213`)

Primary (DNS / HTTPS): `74.208.54.132` (`mail.truemailor.com`)  
Standby clone: `74.208.76.213` (`vps2.vpstruelord.com`)

Both are online until you delete the old host. Domains still resolve to the old IP.

## What was copied

| Stack | Path on both |
| --- | --- |
| Portal (ServerManager) | `/opt/wireguard/port-forward-ui` + `port-forward-ui.service` |
| WireGuard (wg-easy) | `/opt/wireguard` — **fresh** peer DB on new (new endpoint IP) |
| DNS (AdGuard / Pi-hole / Unbound) | `/opt/dns` |
| Caddy + mail + facesearch | `/opt/truemail` (+ mail-data) |
| Surfshark / Tailscale helpers | `/opt/surfshark`, `/opt/dns/ts-*` |
| Remote desktop | `/opt/remote-desktop` |
| Backup agent files | `/opt/servermanager-backup` |

## How to use the new server now

- Portal: **http://74.208.76.213/** (login same as old: `admin` / portal password)
- WireGuard admin UI: **http://74.208.76.213:5001/**
- LAN (Buffalo / Flint): works on new via host WireGuard client `vps2-to-old` → old VPS → home
  - Config: `/etc/wireguard/vps2-to-old.conf` (enabled as `wg-quick@vps2-to-old`)
- HTTPS domain certs on new use `tls internal` until DNS points here (avoids Let’s Encrypt fights with old)

## Edits made on the new server only

- `WG_HOST` / `VPS_PUBLIC_IP` → `74.208.76.213`
- Caddy: `http://74.208.76.213` → portal; domain blocks use `tls internal` + `auto_https disable_redirects`
- Old VPS Caddy VPN allowlists include `74.208.76.213/32` so dual access stays consistent

## Before deleting the old server

1. Cloudflare: point `portal`, `vpn`, `dns`, `pihole`, `buffalo`, `router`, mail hosts, etc. A records to `74.208.76.213`.
2. On new Caddyfile: remove `tls internal` and `auto_https disable_redirects`; reload Caddy so Let’s Encrypt can issue.
3. Move Flint / home WireGuard endpoint to the new VPS (add peer on new wg-easy, update Flint), then `wg-quick down vps2-to-old` and disable that unit.
4. Confirm mail MX / SPF / DKIM for the new IP.
5. Retire `74.208.54.132`.

## Deploy portal code to either host

```bash
# old
VPS=root@74.208.54.132 ./portal/deploy-to-vps.sh

# new
VPS=root@74.208.76.213 ./portal/deploy-to-vps.sh
```
