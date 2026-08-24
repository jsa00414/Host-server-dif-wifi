#!/bin/bash
# ServerManager → GitHub backup agent
set -euo pipefail

ROOT="/opt/servermanager-backup"
ENV_FILE="${ROOT}/secrets.env"
WORK="${ROOT}/work"
LOG="${ROOT}/backup.log"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

log() {
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*" | tee -a "$LOG"
}

if [[ ! -f "$ENV_FILE" ]]; then
  log "ERROR: missing $ENV_FILE"
  exit 1
fi
# shellcheck disable=SC1090
source "$ENV_FILE"

: "${GITHUB_OWNER:?}"
: "${GITHUB_REPO:?}"
: "${GITHUB_TOKEN:?}"
GITHUB_BRANCH="${GITHUB_BRANCH:-main}"
BACKUP_NAME="${BACKUP_NAME:-vps}"

REPO_URL="https://x-access-token:${GITHUB_TOKEN}@github.com/${GITHUB_OWNER}/${GITHUB_REPO}.git"

mkdir -p "$WORK"
cd "$WORK"

if [[ ! -d .git ]]; then
  log "Cloning ${GITHUB_OWNER}/${GITHUB_REPO}…"
  rm -rf "${WORK:?}/"* "${WORK}/.[!.]*" 2>/dev/null || true
  git clone --depth 1 --branch "$GITHUB_BRANCH" "$REPO_URL" "$WORK" 2>/dev/null \
    || git clone --depth 1 "$REPO_URL" "$WORK"
  cd "$WORK"
  git checkout -B "$GITHUB_BRANCH" 2>/dev/null || true
else
  git remote set-url origin "$REPO_URL"
  git fetch origin "$GITHUB_BRANCH" 2>/dev/null || git fetch origin
  git checkout -B "$GITHUB_BRANCH" "origin/${GITHUB_BRANCH}" 2>/dev/null \
    || git checkout -B "$GITHUB_BRANCH"
fi

git config user.email "${GIT_EMAIL:-servermanager-backup@local}"
git config user.name "${GIT_NAME:-ServerManager Backup}"

DEST="${WORK}/${BACKUP_NAME}"
rm -rf "$DEST"
mkdir -p "$DEST"/{wireguard,dns,caddy,systemd,meta}

# --- WireGuard / panel ---
if [[ -d /opt/wireguard ]]; then
  rsync -a --delete \
    --exclude '**/__pycache__/' \
    --exclude '**/*.pyc' \
    --exclude '**/*.bak*' \
    --exclude '**/wg_data/**' \
    --exclude '**/lib/**' \
    /opt/wireguard/port-forward-ui/ "$DEST/wireguard/port-forward-ui/" 2>/dev/null || true
  [[ -f /opt/wireguard/port-forward-ui.env ]] && cp -a /opt/wireguard/port-forward-ui.env "$DEST/wireguard/"
  [[ -d /opt/wireguard/coredns ]] && rsync -a /opt/wireguard/coredns/ "$DEST/wireguard/coredns/" 2>/dev/null || true
  [[ -d /opt/wireguard/scripts ]] && rsync -a /opt/wireguard/scripts/ "$DEST/wireguard/scripts/" 2>/dev/null || true
fi

# --- DNS stack (configs only; skip large gravity DBs if huge) ---
if [[ -d /opt/dns ]]; then
  rsync -a \
    --exclude 'adguard/work/' \
    --exclude '**/gravity.db' \
    --exclude '**/gravity_old.db' \
    --exclude '**/pihole-FTL.db' \
    --exclude '**/__pycache__/' \
    /opt/dns/ "$DEST/dns/" 2>/dev/null || true
fi

# --- Caddy ---
[[ -f /opt/truemail/Caddyfile ]] && cp -a /opt/truemail/Caddyfile "$DEST/caddy/"
[[ -d /opt/truemail ]] && rsync -a --include 'Caddyfile*' --exclude '*' /opt/truemail/ "$DEST/caddy/" 2>/dev/null || true

# --- systemd units ---
for u in port-forward-ui.service sm-ts-vpn-exit.service sm-ts-exit-dns.service sm-ts-exit-watchdog.timer sm-ts-exit-watchdog.service; do
  [[ -f "/etc/systemd/system/$u" ]] && cp -a "/etc/systemd/system/$u" "$DEST/systemd/" || true
done

# --- meta ---
{
  echo "timestamp=${STAMP}"
  echo "hostname=$(hostname)"
  echo "public_ip=$(curl -4 -s --max-time 5 ifconfig.me || true)"
  echo "uname=$(uname -a)"
  docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}' 2>/dev/null || true
} > "$DEST/meta/status.txt"

# Never commit live GitHub token mirror
rm -f "$DEST/dns/secrets.env" 2>/dev/null || true
find "$DEST" -name 'secrets.env' -delete 2>/dev/null || true

# README in backup tree
cat > "$WORK/README.md" <<EOF
# ServerManagerBackup

Automated VPS configuration backups from ServerManager.

- Latest snapshot folder: \`${BACKUP_NAME}/\`
- Last run (UTC): \`${STAMP}\`
- Host: \`$(hostname)\`

> This repository may contain secrets (panel env, tokens). Keep it **private**.
EOF

git add -A
if git diff --cached --quiet; then
  log "No changes to commit."
  exit 0
fi

git commit -m "backup: ${STAMP} ($(hostname))"
git push -u origin "$GITHUB_BRANCH"
log "Pushed backup ${STAMP} to ${GITHUB_OWNER}/${GITHUB_REPO}@${GITHUB_BRANCH}"
