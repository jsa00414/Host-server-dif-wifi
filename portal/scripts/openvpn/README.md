# OpenVPN (TCP 8443 / multiplexed on 443) for campus

Server lives on the VPS at `/opt/openvpn`. Clients:

- Flint site-to-site: `flint.ovpn` / `GL-MT6000.ovpn` (no full-tunnel)
- Phone: `james-iphone.ovpn` (full tunnel)
- Windows PC: `windows.ovpn` (full tunnel + AdGuard DNS)

Portal downloads (login required, VPN-only):

- https://portal.vpstruelord.com/api/openvpn/flint
- https://portal.vpstruelord.com/api/openvpn/phone
- https://portal.vpstruelord.com/api/openvpn/clients/windows

## Portal through OpenVPN

Full-tunnel clients push:

```
dhcp-option DNS 10.9.0.1
block-outside-dns
redirect-gateway def1 bypass-dhcp
```

AdGuard rewrites `portal.vpstruelord.com` → `10.9.0.1`, so HTTPS stays on-tunnel
and Caddy `@vpn_clients` matches `10.9.0.0/24`.

Rebuild a profile after changing DNS defaults:

```bash
OVPN_REDIRECT_GATEWAY=1 bash /opt/openvpn/scripts/build-client.sh windows
```

### Windows setup

1. Install [OpenVPN Connect](https://openvpn.net/client/) or OpenVPN Community GUI.
2. Import `/opt/openvpn/clients/windows.ovpn` (download from portal while on phone VPN, or from the OpenVPN clients tab).
3. Connect, then open https://portal.vpstruelord.com

On Flint: disable WireGuard, import OpenVPN, enable. Endpoint `74.208.76.213:443` TCP (sslh) or `:8443`.
