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
| DNS | AdGuard `10.42.42.44` (portal VIP `10.11.0.1`) |
| Server cert | Let's Encrypt RSA (`ikev2-portal-rsa`) |
| VIP source | in-memory `rightsourceip` pool (DHCP plugin **must stay load=no**) |

## Windows stuck on “Assigning IPv4”

That status is the INTERNAL_IP4_ADDRESS / CP stage. Two server-side traps:

1. **DHCP plugin** (`/etc/strongswan.d/charon/dhcp.conf` `load = yes`) with no DHCP
   server — charon waits forever and Windows never gets a VIP.
2. **`rightsourceip` on `conn %default`** — `passthrough-vps` inherits the pool
   (“reusing virtual IP address pool”) and trap install fails.

`setup-ikev2.sh` keeps the VIP/DNS options on `ikev2-eap` only and forces
`dhcp` `load = no`. After a fix, restart under systemd:

```bash
systemctl restart strongswan-starter
ipsec statusall   # pool on ikev2-eap; passthrough-vps should be PASS/shunt
```

## Windows drops / “terminated by the remote computer” (phone OK)

Windows MOBIKE will path-flip onto Flint’s OpenVPN (`10.9.0.2`) when strongSwan
advertises private `ADD_4_ADDR` (docker/tun). Phone usually stays on the WAN.

Public mode must:

1. `mobike=no` on `ikev2-eap` (and restart strongSwan after editing)
2. `interfaces_use = ens6` so only `74.208.76.213` is advertised
3. `ensure-ikev2-no-nest.sh` — drop UDP 500/4500 from `tun0` / `10.9.0.0/24`

```bash
bash /opt/ikev2/ensure-ikev2-public.sh
bash /opt/ikev2/ensure-ikev2-no-nest.sh
```

Then on the PC: disconnect VPN → optional re-run `Setup-ServerManagerVpn.ps1` → reconnect.

## IKEv2 via OpenVPN (optional nested mode)

Default is **public** IKEv2 on UDP 500/4500. To lock IKEv2 behind OpenVPN instead:

```bash
IKEV2_VIA_OPENVPN=1 bash /opt/ikev2/setup-ikev2.sh
# or
bash /opt/ikev2/ensure-ikev2-via-openvpn.sh
```

Restore public IKEv2:

```bash
bash /opt/ikev2/ensure-ikev2-public.sh
```

## Portal / admin sites while on IKEv2

iOS/Windows exclude the VPN gateway public IP from the tunnel. If DNS returns
`74.208.76.213`, HTTPS to `portal.vpstruelord.com` leaves the tunnel and Caddy
returns **403 Forbidden**.

Fix (VPN DNS only — public DNS unchanged):

```bash
bash /opt/ikev2/ensure-vpn-split-dns.sh
```

AdGuard rewrites VPN-gated hostnames to `10.11.0.1` (lo VIP) so traffic stays on-tunnel
with a private source IP that matches Caddy `@vpn_clients`.

**Guest vs trust DNS:** unapproved IKEv2 peers are DNAT'd pool-wide to
`VPN_GUEST_DNS` (default `1.1.1.1`) so they never see those admin rewrites.
Allowlisted / sticky WAN peers get a per-VIP DNAT upgrade to AdGuard
(`ensure-vpn-client-gate.sh`).

After applying: **disconnect/reconnect VPN** (or flush DNS), then open the portal.

## Windows still Forbidden (DoH / gateway exclusion)

Windows often keeps talking to `74.208.76.213` on the WAN even while IKEv2 is up
(browser Secure DNS / DoH, or gateway-IP exclusion).

```bash
bash /opt/ikev2/ensure-ikev2-peer-acl.sh
systemctl enable --now sm-ikev2-peer-acl.timer
```

This syncs each **active IKEv2 peer public IP** into Caddy `@vpn_clients` every 30s
so portal works for the connected Windows/phone WAN IP without opening it to the world.

## Hairpin (speedtest shows VPS IP, portal still Forbidden)

Full-tunnel IKEv2 makes speedtests show `74.208.76.213`. Hitting the portal A record
can hairpin through MASQUERADE so Caddy sees that same IP and returns 403.

```bash
bash /opt/ikev2/ensure-ikev2-forward.sh   # installs NO-HAIRPIN-MASQ RETURN rule
bash /opt/ikev2/ensure-ikev2-peer-acl.sh  # also allows 74.208.76.213/32 in Caddy
```

## Portal tab flashes then blank (HTTP/3)

UDP/443 is WireGuard on this host. Caddy must not advertise HTTP/3:

```bash
bash /opt/ikev2/ensure-caddy-no-h3.sh
```

