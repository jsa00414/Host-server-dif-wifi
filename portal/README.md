# ServerManager portal (live panel)

Snapshot of the VPS panel at `/opt/wireguard/port-forward-ui/`.

## Backup tab

- Sidebar **Backup** view + Overview shortcut
- `GET /api/backup` — status (never returns the GitHub token)
- `POST /api/backup/run` — run `/opt/servermanager-backup/sm-backup.sh` now

## Surfshark tab

- Sidebar **Surfshark** view (WireGuard VPN Exit for WG clients)
- `GET /api/surfshark` — status + server list from `/opt/surfshark/conf/*.conf`
- `POST /api/surfshark` — enable/disable Surfshark WireGuard VPN exit for WG clients only
- Scripts deployed to `/opt/surfshark/` (`ss-vpn-exit.sh`, `ss-manage.sh`)

Deploy to the VPS (panel reads HTML from `static/index.html`):

```bash
# From repo root, with SSH access to the VPS:
VPS=root@74.208.54.132 ./portal/deploy-to-vps.sh

# Or manually:
scp portal/server.py root@74.208.54.132:/opt/wireguard/port-forward-ui/server.py
scp portal/static/index.html root@74.208.54.132:/opt/wireguard/port-forward-ui/static/index.html
ssh root@74.208.54.132 systemctl restart port-forward-ui
```

Then hard-refresh the portal (Ctrl+Shift+R).
