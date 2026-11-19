# Cloudflare CDN VPN bypass

Campus-friendly path when direct VPS ports (OpenVPN / Xray REALITY `:8444`)
are blocked. Traffic looks like normal HTTPS to **Cloudflare**, then reaches
your origin over the orange-cloud proxy.

```
phone/laptop
  → Cloudflare edge :443  (cdn.vpstruelord.com)
  → Caddy on VPS (TLS)
  → Xray VLESS+WebSocket on 172.18.0.1:18444 (docker-bridge host IP)
  → internet
```

Uses the **same circle UUIDs** as Xray REALITY. Portal Xray page shows both
share links.

## Install / refresh (on VPS)

```bash
sudo bash /opt/wireguard/port-forward-ui/scripts/cloudflare-cdn/setup-cf-cdn.sh
```

Needs `CF_API_TOKEN` in `/opt/wireguard/port-forward-ui.env` (same token used
for portal DNS). Creates/updates:

| Piece | Value |
|-------|--------|
| DNS | `cdn.vpstruelord.com` A → VPS IP, **Proxied** |
| Caddy | site block reverse-proxying `/vless-cf` → `172.18.0.1:18444` |
| Xray | inbound `vless-cf-ws` (docker-bridge WS; Caddy is containerized) |

## Cloudflare dashboard

- SSL/TLS mode: **Full (strict)**
- WebSockets: enabled (default)
- Keep other portal hosts (**vpn.** / **portal.**) DNS-only so WireGuard hairpin still works

## Clients

Import the **CF CDN** `vless://` link from https://portal.vpstruelord.com/xray.html
into v2rayN / v2rayNG / Streisand / Hiddify.

Env overrides:

- `XRAY_CF_HOST` (default `cdn.vpstruelord.com`)
- `XRAY_CF_WS_PATH` (default `/vless-cf`)
- `XRAY_CF_WS_PORT` (default `18444`)
