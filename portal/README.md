# ServerManager portal (live panel)

Snapshot of the VPS panel at `/opt/wireguard/port-forward-ui/`.

## Backup tab

- Sidebar **Backup** view + Overview shortcut
- `GET /api/backup` — status (never returns the GitHub token)
- `POST /api/backup/run` — run `/opt/servermanager-backup/sm-backup.sh` now

Deploy by copying `server.py` and `index.html` to the VPS and restarting `port-forward-ui`.
