#!/usr/bin/env bash
# Install / update Grafana for ServerManager portal embed.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
DEST="${GRAFANA_DIR:-/opt/grafana}"
PORT="${GRAFANA_PORT:-3016}"
DOMAIN="${GF_DOMAIN:-grafana.vpstruelord.com}"
ROOT_URL="${GF_ROOT_URL:-https://${DOMAIN}}"

mkdir -p "$DEST"
cp -f "$ROOT/docker-compose.yml" "$DEST/docker-compose.yml"

ENV_FILE="$DEST/.env"
if [[ ! -f "$ENV_FILE" ]]; then
  # Prefer portal panel password when available
  ADMIN_PASS=""
  if [[ -f /opt/wireguard/port-forward-ui.env ]]; then
    # shellcheck disable=SC1091
    ADMIN_PASS="$(grep -E '^PF_PASS=' /opt/wireguard/port-forward-ui.env | head -1 | cut -d= -f2- | tr -d '"' | tr -d "'")"
  fi
  if [[ -z "$ADMIN_PASS" ]]; then
    ADMIN_PASS="$(openssl rand -base64 18 | tr -d '=+/')x1"
  fi
  cat >"$ENV_FILE" <<EOF
GF_ADMIN_USER=admin
GF_ADMIN_PASSWORD=${ADMIN_PASS}
GF_DOMAIN=${DOMAIN}
GF_ROOT_URL=${ROOT_URL}
EOF
  chmod 600 "$ENV_FILE"
  echo "Wrote $ENV_FILE (admin password from portal PF_PASS or generated)"
else
  echo "Keeping existing $ENV_FILE"
fi

cd "$DEST"
docker compose pull
docker compose up -d
sleep 2
docker compose ps
echo "Grafana listening on 127.0.0.1:${PORT} → ${ROOT_URL}"
curl -sS -o /dev/null -w "health_http=%{http_code}\n" "http://127.0.0.1:${PORT}/api/health" || true
