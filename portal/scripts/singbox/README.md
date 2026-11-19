# sing-box (VLESS + REALITY) for guest-DNS users

Campus-friendly proxy for visitors / out-of-circle devices. DNS is forced to
guest DNS (`10.42.42.45`) — no AdGuard admin rewrites, no private LAN access.
Trust-circle members should keep using **Xray** (`:8444`) instead.

## Server

- Binary: `/usr/local/bin/sing-box`
- Config: `/opt/singbox/config.json`
- Clients: `/opt/singbox/clients.json`
- REALITY keys: `/opt/singbox/reality.keys`
- systemd: `sm-singbox.service`
- Listen: TCP `8445` (`SINGBOX_PORT`)
- DNS: guest VIP `10.42.42.45` (`VPN_GUEST_DNS` / `SINGBOX_GUEST_DNS`)
- SNI / handshake: `www.microsoft.com`
- Host in share links: `vpn.vpstruelord.com` (`SINGBOX_HOST`)

Install / refresh:

```bash
sudo bash /opt/wireguard/port-forward-ui/scripts/singbox/setup-singbox.sh
```

## Portal

- UI: https://portal.vpstruelord.com/singbox.html (sidebar **Sing-box**)
- Status: `GET /api/singbox/status`
- Clients: `GET|POST /api/singbox/clients`

Create named guest UUIDs from the portal. `Sync guests` issues a UUID for each
**pending public WAN** peer (skips home LAN / OpenVPN VIPs — those stay on
guest DNS via IKEv2/OpenVPN gates).

## Clients

Import the `vless://` share link into sing-box / v2rayN / Hiddify / Streisand.
Traffic leaves via the VPS; name resolution uses guest DNS semantics.
