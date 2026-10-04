# OpenVPN (TCP 8443 / multiplexed on 443) for campus

Server lives on the VPS at `/opt/openvpn`. Clients:

- Flint site-to-site: `flint.ovpn` / `GL-MT6000.ovpn` (no full-tunnel) — **VIP `10.9.0.2`**
- Phone: `james-iphone.ovpn` (full tunnel) — **VIP `10.9.0.3`**
- Test phone: `test-phone.ovpn` — **VIP `10.9.0.4`**
- Windows PC: `windows.ovpn` (full tunnel + AdGuard DNS) — **VIP `10.9.0.10`**

CCD files under `/opt/openvpn/ccd/` pin those addresses. **Never** let a phone,
Windows, or any other client take `10.9.0.2` — that VIP is Flint’s site-to-site
address. When something else steals it, home Wi‑Fi/LAN loses its data plane
(OpenVPN still “connected”, but Flint can no longer route), and Caddy’s
`router.vpstruelord.com` upstream 502s. Install the matching `ccd-*` files before
issuing a new client cert.

Also never DNAT public TCP 8443 to Flint HTTPS; OpenVPN owns that port.

Portal downloads (login required, VPN-only):

- https://portal.vpstruelord.com/api/openvpn/flint
- https://portal.vpstruelord.com/api/openvpn/phone
- https://portal.vpstruelord.com/api/openvpn/clients/windows

## Portal through OpenVPN

Full-tunnel clients push (OpenVPN Connect–compatible):

```
dhcp-option DNS 10.42.42.44
redirect-gateway def1
```

Portal/router stay on the public A record (`74.208.76.213`); sticky home-WAN ACL
in Caddy covers gateway-excluded Windows traffic.

Rebuild a profile after changing DNS defaults:

```bash
OVPN_REDIRECT_GATEWAY=1 bash /opt/openvpn/scripts/build-client.sh windows
install -m 644 /opt/openvpn/scripts/ccd-windows /opt/openvpn/ccd/windows
```

### Windows setup

1. Install [OpenVPN Connect](https://openvpn.net/client/) or OpenVPN Community GUI.
2. Import `/opt/openvpn/clients/windows.ovpn` (download from portal while on phone VPN, or from the OpenVPN clients tab).
3. Connect, then open https://portal.vpstruelord.com

On Flint: disable WireGuard, import OpenVPN, enable. Endpoint `74.208.76.213:443` TCP (sslh) or `:8443`.
