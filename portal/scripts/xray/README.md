# Xray (VLESS + REALITY) for trust-circle users

Campus-friendly proxy on the VPS. UUID clients are issued from the portal
(login required) for people in the Authenticator trust circle.

## Server

- Binary: `/usr/local/bin/xray`
- Config: `/opt/xray/config.json`
- Clients: `/opt/xray/clients.json`
- REALITY keys: `/opt/xray/reality.keys`
- systemd: `sm-xray.service`
- Listen: TCP `8444` (override with `XRAY_PORT`)
- SNI / dest: `www.microsoft.com` (override `XRAY_SNI` / `XRAY_DEST`)
- Host in share links: `vpn.vpstruelord.com` (`XRAY_HOST`)

Install / refresh:

```bash
sudo bash /opt/wireguard/port-forward-ui/scripts/xray/setup-xray.sh
```

## Portal

- UI: https://portal.vpstruelord.com/xray.html (sidebar **Xray**)
- Status: `GET /api/xray/status`
- Clients: `GET|POST /api/xray/clients`
- Share link: `GET /api/xray/clients/{name}/link`

`Sync circle` creates a VLESS UUID for every key-bound allowlisted device
(LAN / OpenVPN / sticky WAN) that does not already have one.

## Clients

Import the `vless://` share link into v2rayN / v2rayNG / Streisand / Hiddify.
DNS on the client can stay default; for circle admin names over Xray, point
DNS at AdGuard `10.42.42.44` only when also on OVPN/LAN.

## Authenticator Surfshark exit (always via Xray)

When Exit → Surfshark is selected in the Authenticator app for a Circle
device, TCP is redirected into Xray dokodemo `:18082`, then Xray’s
`via-surfshark` outbound (fwmark `0x184`) leaves through the Surfshark
WireGuard interface:

`device → Xray → Surfshark → internet`

Both dokodemo inbounds listen on `0.0.0.0` because iptables `REDIRECT`
delivers to the ingress interface address (e.g. `10.9.0.1:18082` on
`tun0`), not loopback. `setup-xray.sh` drops those ports on the public
NIC so they stay VPN/local-only.

UDP still policy-routes with the same mark (not redirected). Direct
circle LAN traffic (no Surfshark exit) continues to use dokodemo `:18080`
→ VPS public IP.
