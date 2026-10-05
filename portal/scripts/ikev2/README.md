# Windows built-in VPN (IKEv2)

ServerManager runs **strongSwan IKEv2** with a **Let's Encrypt RSA** certificate (Windows rejects LE ECDSA for IKEv2).

## Setup / refresh on the VPS

```bash
bash /opt/ikev2/setup-ikev2.sh
```

Certbot cert name: `ikev2-portal-rsa` (renews automatically; `sync-ikev2-cert.sh` reloads strongSwan).

## Connect from Windows

1. Portal → **Windows VPN**
2. Download `Setup-ServerManagerVpn.ps1` + `.cmd`
3. Double-click the `.cmd` (Administrator) to recreate the profile
4. Connect with the shown username/password

No private CA install is required.

## Details

| Item | Value |
|------|--------|
| Protocol | IKEv2 + EAP-MSCHAPv2 |
| Ports | UDP 500, 4500 |
| Pool | `10.10.0.0/24` |
| DNS | `10.9.0.1` → AdGuard → Pi-hole |
| Server cert | Let's Encrypt RSA (`ikev2-portal-rsa`) |

## Flint LAN → portal (HTTP/2 abort fix)

Home LAN egress shares campus WAN `192.81.235.246`, which Caddy hard-denies with
`abort` (Chrome shows `ERR_HTTP2_PROTOCOL_ERROR`). GL.iNet also forces the VPS
public IP via WAN so OpenVPN does not loop.

`ensure-flint-portal-via-ovpn.sh` (timer `sm-flint-portal-via-ovpn.timer`) rewrites
Flint DNS for `portal`/`router` to VIP `10.11.0.1` and routes that VIP over
`ovpnclient1`, so LAN browsers hit Caddy as `10.9.0.2`.

```bash
bash /opt/ikev2/ensure-flint-portal-via-ovpn.sh
```
