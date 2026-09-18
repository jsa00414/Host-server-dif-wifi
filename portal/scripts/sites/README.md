# Troop 3 site (`troop3.vpstruelord.com`)

Deploys [jsa00414/troop-3-test-site](https://github.com/jsa00414/troop-3-test-site) on the VPS behind Caddy.

## Deploy / update

On the VPS as root:

```bash
bash /path/to/portal/scripts/sites/deploy-troop3.sh
```

What it does:

1. Clones/updates the repo under `/opt/sites/troop3`
2. Runs `npm ci` + `npm run build`
3. Installs/restarts systemd unit `troop3-site` on port `3013`
4. Adds a Caddy reverse_proxy block for `troop3.vpstruelord.com` (outside managed hookups)
5. Creates/updates the Cloudflare A record (uses `CF_API_TOKEN` from `/opt/wireguard/port-forward-ui.env`)

## Overrides

| Env | Default |
|-----|---------|
| `TROOP3_DOMAIN` | `troop3.vpstruelord.com` |
| `TROOP3_REPO` | `https://github.com/jsa00414/troop-3-test-site.git` |
| `TROOP3_BRANCH` | `main` |
| `TROOP3_PORT` | `3013` |
| `TROOP3_ROOT` | `/opt/sites/troop3` |
