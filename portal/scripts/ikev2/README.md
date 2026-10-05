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

## Flint LAN → portal (HTTP/2 abort + Windows TLS timeout)

Home LAN egress shares campus WAN `192.81.235.246`. Caddy still campus-denies
**router** (and other vpn_only sites). **Portal** skips `@denied_wan` so a
Secure-DNS miss does not become `ERR_EMPTY_RESPONSE`; auth + `@vpn_clients`
still gate the app.

Preferred path (timer `sm-flint-portal-via-ovpn.timer`):

1. Flint DNS: `portal` → `192.168.8.1` (DoH canaries sinkholed)
2. Flint **nginx** terminates TLS (LE cert) → reverse-proxy to VIP `10.11.0.1` over OVPN
3. Fallback: key-bound LAN `/32` REDIRECT `:443` → `socat :9443` → VIP
4. Caddy sees source `10.9.0.2` (in `@vpn_clients`)

```bash
bash /opt/ikev2/ensure-flint-portal-via-ovpn.sh   # also runs ensure-flint-portal-nginx.sh
```