# ServerManager Backup Setup

Windows EXE + VPS agent that backs up your ServerManager / DNS / Caddy config to a **private** GitHub repo:

**https://github.com/jsa00414/ServerManagerBackup**

## What it does

1. **Setup EXE (Windows)** — enter VPS SSH + GitHub token
2. Creates the private repo if it does not exist (token must allow `repo`)
3. Installs `/opt/servermanager-backup` on the VPS
4. Runs an immediate backup, then a **daily** systemd timer (default 03:15 UTC)

### Backed up

- `/opt/wireguard/port-forward-ui/` (+ `.env`)
- `/opt/dns/` configs (skips large gravity DBs / AdGuard work)
- `/opt/truemail/Caddyfile`
- Related systemd units
- Host meta (`docker ps`, hostname, public IP)

> Keep the GitHub repo **private** — backups can include secrets.

## Build the EXE (Windows)

```bat
cd backup-setup
build.bat
```

Output: `backup-setup\dist\ServerManager-Backup-Setup.exe`

## Use the EXE

1. Create a GitHub PAT: https://github.com/settings/tokens (classic: `repo` scope)
2. Run the EXE
3. **VPS Server** tab — IP, SSH user, password or key → Test SSH
4. **GitHub Backup** tab — owner `jsa00414`, repo `ServerManagerBackup`, paste token → Test GitHub
5. **Install Backup on VPS**

If auto-create fails, manually create an empty private repo named `ServerManagerBackup`, then install again.

## On the VPS (after install)

```bash
systemctl list-timers sm-backup.timer
journalctl -u sm-backup.service -n 50
tail -f /opt/servermanager-backup/backup.log
# manual run:
/opt/servermanager-backup/sm-backup.sh
```

## Security

- Token stored only on the VPS at `/opt/servermanager-backup/secrets.env` (mode `600`)
- Prefer a fine-grained token limited to `ServerManagerBackup` contents: write
