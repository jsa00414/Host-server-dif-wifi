#!/bin/bash
# Install ServerManager backup agent on this VPS
set -euo pipefail

ROOT="/opt/servermanager-backup"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

GITHUB_OWNER="${GITHUB_OWNER:?}"
GITHUB_REPO="${GITHUB_REPO:?}"
GITHUB_TOKEN="${GITHUB_TOKEN:?}"
GITHUB_BRANCH="${GITHUB_BRANCH:-main}"
BACKUP_NAME="${BACKUP_NAME:-vps}"
BACKUP_HOUR="${BACKUP_HOUR:-3}"
GIT_NAME="${GIT_NAME:-ServerManager Backup}"
GIT_EMAIL="${GIT_EMAIL:-servermanager-backup@local}"

mkdir -p "$ROOT"
install -m 0755 "${SCRIPT_DIR}/sm-backup.sh" "$ROOT/sm-backup.sh"

umask 077
# Quote every value so spaces (e.g. GIT_NAME) survive `source`
{
  printf 'GITHUB_OWNER=%q\n' "$GITHUB_OWNER"
  printf 'GITHUB_REPO=%q\n' "$GITHUB_REPO"
  printf 'GITHUB_TOKEN=%q\n' "$GITHUB_TOKEN"
  printf 'GITHUB_BRANCH=%q\n' "$GITHUB_BRANCH"
  printf 'BACKUP_NAME=%q\n' "$BACKUP_NAME"
  printf 'GIT_NAME=%q\n' "$GIT_NAME"
  printf 'GIT_EMAIL=%q\n' "$GIT_EMAIL"
} > "$ROOT/secrets.env"
chmod 600 "$ROOT/secrets.env"

# Ensure git + rsync + curl
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq git rsync curl ca-certificates >/dev/null

# Ensure remote repo exists (private) using token
API="https://api.github.com"
CODE=$(curl -s -o /tmp/sm-repo.json -w "%{http_code}" \
  -H "Authorization: Bearer ${GITHUB_TOKEN}" \
  -H "Accept: application/vnd.github+json" \
  "${API}/repos/${GITHUB_OWNER}/${GITHUB_REPO}")
if [[ "$CODE" == "404" ]]; then
  echo "Creating private repo ${GITHUB_OWNER}/${GITHUB_REPO}…"
  curl -sS -X POST \
    -H "Authorization: Bearer ${GITHUB_TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    "${API}/user/repos" \
    -d "{\"name\":\"${GITHUB_REPO}\",\"private\":true,\"description\":\"ServerManager VPS config backups\",\"auto_init\":true}" \
    | head -c 400
  echo
  sleep 2
elif [[ "$CODE" != "200" ]]; then
  echo "WARN: GitHub API returned HTTP ${CODE} for repo check (continuing)"
  cat /tmp/sm-repo.json 2>/dev/null | head -c 300; echo
fi

# systemd service + daily timer
cat > /etc/systemd/system/sm-backup.service <<EOF
[Unit]
Description=ServerManager GitHub backup
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${ROOT}/sm-backup.sh
Nice=10
EOF

cat > /etc/systemd/system/sm-backup.timer <<EOF
[Unit]
Description=Daily ServerManager GitHub backup

[Timer]
OnCalendar=*-*-* ${BACKUP_HOUR}:15:00
Persistent=true
RandomizedDelaySec=600

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now sm-backup.timer

echo "Running first backup…"
"${ROOT}/sm-backup.sh" || true

systemctl list-timers sm-backup.timer --no-pager || true
echo "Installed. Logs: ${ROOT}/backup.log"
echo "Repo: https://github.com/${GITHUB_OWNER}/${GITHUB_REPO}"
