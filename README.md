# VPS WireGuard Setup

One-click Windows installer that deploys **WireGuard Easy v15.3.0**, **Caddy**, and a **VPN-only Domain Manager** to your VPS server.

## ServerManager Backup Setup (separate EXE)

See [`backup-setup/`](backup-setup/) for a Windows EXE that connects to your VPS and installs automatic config backups to the private GitHub repo [jsa00414/ServerManagerBackup](https://github.com/jsa00414/ServerManagerBackup).

## What it does

1. **Setup EXE (Windows)** — GUI wizard to enter VPS SSH credentials, WireGuard UI port, and domain settings
2. **SSH deploy** — Installs Docker, uploads the server stack, and starts all services
3. **WireGuard Easy v15.3.0** — Full WireGuard VPN with web UI ([AGPL-3.0-only](https://github.com/wg-easy/wg-easy), © 2021-2026 Emile Nijssen)
4. **Caddy reverse proxy** — Automatic HTTPS for your WireGuard UI and deployed domains
5. **Caddy Domain Manager** — Web UI to add/remove reverse-proxy domains, **accessible only from WireGuard-connected devices**

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                        VPS Server                        │
│                                                          │
│  ┌──────────────┐   ┌─────────┐   ┌─────────────────┐  │
│  │ WireGuard    │   │  Caddy  │   │ Domain Manager  │  │
│  │ Easy v15.3.0 │◄──│  :443   │──►│ (VPN-only UI)   │  │
│  │ UI + VPN     │   │  :80    │   │                 │  │
│  │ :51821/:51820│   └─────────┘   └─────────────────┘  │
│  └──────────────┘                                        │
└─────────────────────────────────────────────────────────┘
         ▲                              ▲
         │ WireGuard tunnel             │ HTTPS (VPN IP only)
         │                              │
    ┌────┴────┐                   ┌────┴────┐
    │ Client  │                   │ Client  │
    │ Device  │                   │ Device  │
    └─────────┘                   └─────────┘
```

## Build the Setup EXE (Windows)

Requirements: **Python 3.11+** on Windows

```bat
cd setup
build.bat
```

Output: `setup/dist/VPS-WireGuard-Setup.exe`

## Run the Setup EXE

1. Launch `VPS-WireGuard-Setup.exe`
2. **VPS Server tab** — Enter VPS IP, SSH user, password or private key
3. **WireGuard Easy tab** — Set UI port (default `51821`) and tunnel port (default `51820`)
4. **Caddy Domains tab** — Set Domain Manager hostname (e.g. `domains.example.com`)
5. Click **Deploy to VPS**
6. Open the WireGuard Easy URL and complete the **first-time setup wizard**
7. Connect a device via WireGuard, then open the **Domain Manager URL** to deploy Caddy domains

## Manual server install (Linux VPS)

If you prefer to install directly on the VPS without the Windows EXE:

```bash
git clone <this-repo>
cd server
cp .env.template .env
# Edit .env with your values
bash install.sh
```

## Ports

| Port | Protocol | Service |
|------|----------|---------|
| 51820 | UDP | WireGuard tunnel (default, configurable) |
| 51821 | TCP | WireGuard Easy UI (default, configurable) |
| 80 | TCP | Caddy HTTP |
| 443 | TCP/UDP | Caddy HTTPS |

Open these ports in your VPS firewall and cloud provider security group.

## Domain Manager (VPN-only)

The Domain Manager lets WireGuard-connected devices:

- Add reverse-proxy domains pointing to any upstream (e.g. `app.example.com → 192.168.1.10:8080`)
- Choose TLS mode: Let's Encrypt, internal CA, or HTTP-only
- Remove domains and reload Caddy automatically

Access is restricted by Caddy's `remote_ip` matcher to the WireGuard client subnet (default `10.8.0.0/24`).

## Cloudflare integration

The setup EXE includes a **Cloudflare** tab:

| Field | Purpose |
|-------|---------|
| API token | Cloudflare API token with `Zone:DNS:Edit` permission |
| Root zone | e.g. `example.com` (used to resolve Zone ID) |
| Zone ID | Optional — auto-detected if blank |
| Auto-create DNS | Creates A records for WireGuard UI + Domain Manager hostnames |
| DNS-01 TLS | Uses Cloudflare DNS challenge for Caddy HTTPS certificates |
| Proxied | Orange-cloud proxy for HTTP domains (WireGuard records stay DNS-only) |

When Cloudflare is configured, the Domain Manager also creates A records automatically when you deploy new domains over VPN.

Create a token at [dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens) with **Edit DNS** permission for your zone.

## Third-party licenses

| Component | Version | License |
|-----------|---------|---------|
| WireGuard Easy | 15.3.0 | AGPL-3.0-only |
| Caddy | 2.10.0 | Apache-2.0 |
| Domain Manager | 1.0.0 | MIT (this project) |

WireGuard Easy is © 2021-2026 Emile Nijssen. Source: https://github.com/wg-easy/wg-easy

## Troubleshooting

**SSH connection fails** — Verify VPS IP, port 22 open, and credentials.

**WireGuard UI not loading** — Check firewall allows your UI port (default 51821/tcp).

**Domain Manager returns 403** — Connect via WireGuard first. Verify your client IP is in the configured VPN subnet.

**Caddy reload fails** — Check `docker logs caddy` on the VPS.
