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

## Twilio SMS (Truemailor)

Portal two-factor can use Twilio SMS alongside Authenticator and Truemailor email codes.
Put these in `/opt/truemail/.env` (or the portal env):

- `TWILIO_ACCOUNT_SID`
- `TWILIO_AUTH_TOKEN`
- `TWILIO_FROM_NUMBER` (E.164) and/or `TWILIO_MESSAGING_SERVICE_SID`
- `SMS_CODE_TO` (E.164 destination)

US long codes need an approved **A2P 10DLC** brand/campaign (Twilio error `30034` otherwise).

### A2P Privacy Policy / Terms URLs

Public pages (no login):

- Privacy: `https://mail.truemailor.com/privacy.html`
- Terms: `https://mail.truemailor.com/terms.html`
- Portal fallback: `https://portal.vpstruelord.com/privacy.html`

Publish on the VPS:

```bash
sudo bash /opt/wireguard/port-forward-ui/scripts/truemail/install-legal-pages.sh
```

Apply Twilio env (with SSH access):

```bash
set -a; source ./twilio.env; set +a
VPS=root@74.208.76.213 ./portal/scripts/configure-twilio-truemail.sh
```

Smoke test: `/sms-code-test.html` → `POST /api/sms-code/send` + `/api/sms-code/verify`.

## NAS Files (WebAccess)

- Sidebar / Overview **Files** tile embeds Buffalo WebAccess
- Same-origin proxy: `/nas-files/*` → `http://192.168.8.159:9000/*`
- Default iframe entry: `/nas-files/ui/`
- SSO: `GET /api/buffalo-sso` logs into admin + WebAccess and sets `sid` / `webaxs_session` cookies
  (`BUFFALO_USER`, `BUFFALO_PASS_B64` in `port-forward-ui.env`)

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
