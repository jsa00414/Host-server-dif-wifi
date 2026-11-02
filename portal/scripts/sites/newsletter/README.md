# newsletter

Public newsletter site served at [newsletter.vpstruelord.com](https://newsletter.vpstruelord.com).

## Local

```bash
npm start
# http://localhost:3017
```

## VPS

Deployed under `/opt/sites/newsletter` via `portal/scripts/sites/deploy-newsletter.sh`
(systemd `newsletter-site.service`, Caddy, Cloudflare DNS).
