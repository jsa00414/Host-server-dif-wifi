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

on_err() {
  local ec=$?
  log "ERROR: backup failed (exit ${ec})"
  exit "$ec"
}
trap on_err ERR

if [[ ! -f "$ENV_FILE" ]]; then
  log "ERROR: missing $ENV_FILE"
  exit 1
fi
# shellcheck disable=SC1090
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

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
  if ! git clone --depth 1 --branch "$GITHUB_BRANCH" "$REPO_URL" "$WORK"; then
    git clone --depth 1 "$REPO_URL" "$WORK"
  fi
  cd "$WORK"
  git checkout -B "$GITHUB_BRANCH" 2>/dev/null || true
else
  git remote set-url origin "$REPO_URL"
  if ! git fetch origin "$GITHUB_BRANCH"; then
    git fetch origin
  fi
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
for u in port-forward-ui.service sm-backup.service sm-backup.timer sm-ts-vpn-exit.service sm-ts-exit-dns.service sm-ts-exit-watchdog.timer sm-ts-exit-watchdog.service; do
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

# Panel trust-circle state (allowlist / sticky / devices / encrypted enroll vault)
mkdir -p "$DEST/panel"
for f in vpn-allowlist.json caddy-sticky-vpn-ips.txt auth-app-devices.json ssh-panel-2fa.json \
         enroll-secrets.enc enroll-vault.key webauthn-credentials.json; do
  [[ -f "/opt/servermanager/panel/$f" ]] && cp -a "/opt/servermanager/panel/$f" "$DEST/panel/" || true
done
# OpenVPN CCD pins
if [[ -d /opt/openvpn/ccd ]]; then
  mkdir -p "$DEST/openvpn/ccd"
  rsync -a /opt/openvpn/ccd/ "$DEST/openvpn/ccd/" 2>/dev/null || true
fi

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
