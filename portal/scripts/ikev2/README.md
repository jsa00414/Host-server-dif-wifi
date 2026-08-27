# Windows built-in VPN (IKEv2)

ServerManager runs **strongSwan IKEv2** so Windows can connect with its built-in VPN client (no OpenVPN/WireGuard app).

## Setup / refresh on the VPS

```bash
bash /opt/ikev2/setup-ikev2.sh
# or from the repo copy:
bash /opt/wireguard/port-forward-ui/scripts/ikev2/setup-ikev2.sh
```

Uses the Let's Encrypt cert for `portal.vpstruelord.com` from Caddy when available.

## Connect from Windows

1. Portal → **Windows VPN** (or open `/windows-vpn.html`)
2. Download `Setup-ServerManagerVpn.ps1` and run it in PowerShell
3. Connect with the shown username/password

Or manually: Settings → VPN → IKEv2 → server `portal.vpstruelord.com`.

## Details

| Item | Value |
|------|--------|
| Protocol | IKEv2 + EAP-MSCHAPv2 |
| Ports | UDP 500, 4500 |
| Pool | `10.10.0.0/24` |
| DNS | `10.9.0.1` → AdGuard → Pi-hole |
