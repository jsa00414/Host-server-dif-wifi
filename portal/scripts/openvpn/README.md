# OpenVPN (TCP 8443) for campus

Server lives on the VPS at `/opt/openvpn`. Clients:

- Flint site-to-site: `flint.ovpn` / `GL-MT6000.ovpn` (no full-tunnel)
- Phone: `james-iphone.ovpn` (full tunnel)

Portal downloads (login required):

- https://portal.vpstruelord.com/api/openvpn/flint
- https://portal.vpstruelord.com/api/openvpn/phone

On Flint: disable WireGuard, import OpenVPN, enable. Endpoint `74.208.76.213:8443` TCP.
