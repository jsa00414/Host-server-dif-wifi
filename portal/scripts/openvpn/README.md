# OpenVPN (TCP 8443 / sslh :443) for campus

Server lives on the VPS at `/opt/openvpn`. Clients:

- Flint site-to-site: `flint.ovpn` / `GL-MT6000.ovpn` (no full-tunnel) — VIP `10.9.0.2`
- Phone: `james-iphone.ovpn` (full tunnel) — VIP `10.9.0.3`
- Windows PC: `windows.ovpn` (full tunnel) — VIP `10.9.0.10`

Portal downloads (login required):

- https://portal.vpstruelord.com/api/openvpn/flint
- https://portal.vpstruelord.com/api/openvpn/phone
- https://portal.vpstruelord.com/api/openvpn/clients/windows

On Flint: disable WireGuard, import OpenVPN, enable. Endpoint `74.208.76.213:443` TCP
(sslh demux → OpenVPN on 8443).

## Portal trust circle

Caddy `@vpn_clients` trusts **only** the Flint OVPN VIP `10.9.0.2/32` from the
`10.9.0.0/24` pool (MASQ + `router.vpstruelord.com` upstream). Other CCD clients
(`windows` `10.9.0.10`, phones) do **not** get portal automatically — add their
VIP as an allowlisted `/32` if campus OpenVPN should reach portal. A blanket
`10.9.0.0/24` previously let `windows.ovpn` bypass the Authenticator LAN circle.

## Speed tuning (~100Mbps target)

`openvpn-speed-tune.sh` raises kernel TCP buffers (16MiB). `server.conf` sets
`sndbuf`/`rcvbuf` 8MiB, prefers `AES-128-GCM`, `mssfix 1280`, `txqueuelen 10000`.
Re-import client profiles after rebuilding so phones/Flint pick up matching buffers.

## UDP speed path (Flint)

`openvpn-server-udp-sm` listens on **UDP 1194** (`10.9.1.0/24`, Flint `10.9.1.2`).
Use `flint-udp.ovpn` / re-import `GL-MT6000.ovpn` for bulk traffic toward ~100Mbps.
TCP `:443` remains for campus phone/laptop clients.
