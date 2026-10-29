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
