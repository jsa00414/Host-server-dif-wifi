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

## Flint LAN → portal (HTTP/2 abort + timeout fix)

Home LAN egress shares campus WAN `192.81.235.246`, which Caddy hard-denies with
`abort` (Chrome shows `ERR_HTTP2_PROTOCOL_ERROR`). GL.iNet also forces the VPS
public IP via WAN so OpenVPN does not loop. Direct DNAT+FORWARD over OVPN also
stalls Windows TLS (`ERR_CONNECTION_TIMED_OUT`) due to MSS/MTU.

`ensure-flint-portal-via-ovpn.sh` (timer `sm-flint-portal-via-ovpn.timer`):

- Rewrites Flint DNS for `portal`/`router` → VIP `10.11.0.1`
- For key-bound LAN `/32`s only, REDIRECTs `:443` to a single `socat` relay on
  Flint (`:9443` → VIP) **without `reuseaddr`**, with `mss=1200`
- Blocks HTTP/3 (UDP/443), DNS-over-QUIC (UDP/7844), and DoT (853) at the head
  of `FORWARD` so Surface Secure DNS cannot bypass router DNS
- Clamps LAN SYN MSS toward portal; OVPN MTU 1200
- Rejects non-circle LAN → VIP so DNAT cannot skip the trust circle

`ensure-portal-http1-alpn.sh` (run on the VPS):

- Forces portal TLS ALPN to `http/1.1` only
- Removes `@denied_wan` / `abort` from **portal only** (campus Shared NAT was
  producing Chrome `ERR_EMPTY_RESPONSE` when Surface missed the VIP relay).
  Login auth still applies; other hostnames keep campus deny.

```bash
bash /opt/ikev2/ensure-flint-portal-via-ovpn.sh
bash /opt/ikev2/ensure-portal-http1-alpn.sh
```

### Surface still failing while other LAN devices work?

1. Close every `portal.vpstruelord.com` tab (kills cached h2/h3 sessions).
2. On the Surface: `ipconfig /flushdns` (Admin CMD).
3. Chrome → Settings → Privacy → Security → **Use secure DNS** → Off (while on Flint).
4. Toggle Wi‑Fi off/on, then open https://portal.vpstruelord.com/
