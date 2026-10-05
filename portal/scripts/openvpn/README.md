# OpenVPN (TCP 8443 / sslh :443) for campus

Server lives on the VPS at `/opt/openvpn`. Clients:

- Flint site-to-site: `flint.ovpn` / `GL-MT6000.ovpn` (no full-tunnel)
- Phone: `james-iphone.ovpn` (full tunnel)

Portal downloads (login required):

- https://portal.vpstruelord.com/api/openvpn/flint
- https://portal.vpstruelord.com/api/openvpn/phone

On Flint: disable WireGuard, import OpenVPN, enable. Endpoint `74.208.76.213:443` TCP
(sslh demux → OpenVPN on 8443).

## Speed tuning (~100Mbps target)

`openvpn-speed-tune.sh` raises kernel TCP buffers (16MiB). `server.conf` sets
`sndbuf`/`rcvbuf` 8MiB, prefers `AES-128-GCM`, `mssfix 1280`, `txqueuelen 10000`.
Re-import client profiles after rebuilding so phones/Flint pick up matching buffers.

## UDP speed path (Flint)

`openvpn-server-udp-sm` listens on **UDP 1194** (`10.9.1.0/24`, Flint `10.9.1.2`).
Use `flint-udp.ovpn` / re-import `GL-MT6000.ovpn` for bulk traffic toward ~100Mbps.
TCP `:443` remains for campus phone/laptop clients.
