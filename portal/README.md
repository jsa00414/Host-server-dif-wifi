# ServerManager portal (live panel)

Snapshot of the VPS panel at `/opt/wireguard/port-forward-ui/`.

## Backup tab

- Sidebar **Backup** view + Overview shortcut
- `GET /api/backup` — status (never returns the GitHub token)
- `POST /api/backup/run` — run `/opt/servermanager-backup/sm-backup.sh` now

## Surfshark tab

- Sidebar **Surfshark** view (mirrors Tailscale VPN Exit pattern)
- `GET /api/surfshark` — status + server list from `/opt/surfshark/conf/*.conf`
- `POST /api/surfshark` — enable/disable Surfshark WireGuard VPN exit for WG clients only
- Scripts deployed to `/opt/surfshark/` (`ss-vpn-exit.sh`, `ss-manage.sh`)

Deploy by copying `server.py` and `index.html` to the VPS and restarting `port-forward-ui`.
