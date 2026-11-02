# Sunshine Second Grade

Gated second-grade class site served at
[newsletter.vpstruelord.com](https://newsletter.vpstruelord.com).

## Features

- **Admin login** at `/admin/login` — first visit creates the class + password; later visits sign in with password only
- **Family gate** at `/gate` — shared authenticator QR unlocks the main site
- **PDF newsletters** with a **bottom-right QR** that opens the hidden slideshow at `/s/<secret-token>` (not in site nav)

## Local

```bash
npm ci
cp .env.example .env   # set SESSION_SECRET + NEXT_PUBLIC_APP_URL
npm run dev
```

Open http://localhost:3000/admin/login

## VPS

Deployed under `/opt/sites/newsletter` via `../deploy-newsletter.sh`
(systemd `newsletter-site.service`, Caddy, Cloudflare DNS).

On a small VPS prefer a prebuilt standalone bundle:

```bash
NEWSLETTER_BUNDLE=/tmp/newsletter-standalone.tar.gz \
  bash /opt/wireguard/port-forward-ui/scripts/sites/deploy-newsletter.sh
```

Or build from this source tree (needs enough RAM for `next build`):

```bash
bash /opt/wireguard/port-forward-ui/scripts/sites/deploy-newsletter.sh
```

Persisted across deploys: `/opt/sites/newsletter/.env` and `/opt/sites/newsletter/data/`.
