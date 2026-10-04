# Guest NXDOMAIN DNS (`sm-guest-dns`)

Out-of-circle / pending clients are forced to this resolver (`VPN_GUEST_DNS`,
default VIP `10.42.42.45`) instead of a public resolver.

Admin hostnames (`portal`, `router`, `vpn`, …) answer **NXDOMAIN**, so Chrome
shows a real `DNS_PROBE_FINISHED_NXDOMAIN` page — not a Caddy HTML lookalike.

`keys.vpstruelord.com` is intentionally **not** blocked (Authenticator enroll).

Deployed from `/opt/dns` compose as service `guest-dns`.
