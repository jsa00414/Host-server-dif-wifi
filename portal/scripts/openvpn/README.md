# OpenVPN (TCP 8443 / multiplexed on 443) for campus

Server lives on the VPS at `/opt/openvpn`. Clients:

- Flint site-to-site: `flint.ovpn` / `GL-MT6000.ovpn` (no full-tunnel) — **VIP `10.9.0.2`**
- Phone: `james-iphone.ovpn` (full tunnel)
- Windows PC: `windows.ovpn` (full tunnel + AdGuard DNS) — **VIP `10.9.0.10`**

CCD files under `/opt/openvpn/ccd/` pin those addresses. Do not let Windows (or
any other client) take `10.9.0.2` — Caddy proxies `router.vpstruelord.com` to
that VIP, so a stolen address produces HTTP 502.

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

## Reinstall server (keep PKI / client profiles)

Do **not** wipe `/opt/openvpn/easy-rsa` or `/opt/openvpn/clients` — that invalidates
Flint/phone/Windows certs. Package + service refresh only:

```bash
systemctl stop openvpn-server-sm
tar -C /opt -czf /root/openvpn-pki-$(date +%Y%m%d%H%M).tgz openvpn
apt-get install --reinstall -y openvpn easy-rsa
# refresh unit + conf + scripts from repo (or /opt/openvpn/scripts copies)
install -m 0644 /opt/openvpn/scripts/server.conf /opt/openvpn/server.conf
install -m 0644 /opt/openvpn/scripts/openvpn-server-sm.service /etc/systemd/system/openvpn-server-sm.service
systemctl daemon-reload
: > /var/log/openvpn.log
systemctl restart openvpn-server-sm sslh
ss -tlnp | grep -E ':443|:8443'
head /var/log/openvpn-status.log
```

OpenVPN 2.6 needs `data-ciphers` (CBC alone is ignored for negotiation). Flint
reconnects on its own once the server is listening again; if home killswitch is
up with no WAN, toggle OpenVPN on the Flint UI at `192.168.8.1`.
