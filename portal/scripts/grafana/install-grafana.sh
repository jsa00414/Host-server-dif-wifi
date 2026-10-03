#!/usr/bin/env bash
# Install / update Grafana for ServerManager portal embed.
# - Listens on 127.0.0.1:3016 only (not public 0.0.0.0)
# - Joins Caddy's Docker network so grafana.vpstruelord.com → sm-grafana:3000
# - Admin password is unique (never reused from portal PF_PASS)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
DEST="${GRAFANA_DIR:-/opt/grafana}"
PORT="${GRAFANA_PORT:-3016}"
DOMAIN="${GF_DOMAIN:-grafana.vpstruelord.com}"
ROOT_URL="${GF_ROOT_URL:-https://${DOMAIN}}"

mkdir -p "$DEST"/{dashboards,prometheus,provisioning/dashboards,provisioning/datasources}
cp -f "$ROOT/docker-compose.yml" "$DEST/docker-compose.yml"
cp -a "$ROOT/dashboards/." "$DEST/dashboards/" 2>/dev/null || true
cp -a "$ROOT/prometheus/." "$DEST/prometheus/" 2>/dev/null || true
cp -a "$ROOT/provisioning/." "$DEST/provisioning/" 2>/dev/null || true

portal_pass() {
  local p=""
  if [[ -f /opt/wireguard/port-forward-ui.env ]]; then
    p="$(grep -E '^PF_PASS=' /opt/wireguard/port-forward-ui.env | head -1 | cut -d= -f2- | tr -d '"' | tr -d "'")"
  fi
  printf '%s' "$p"
}

gen_unique_pass() {
  local portal p
  portal="$(portal_pass)"
  while true; do
    p="$(openssl rand -base64 24 | tr -d '=+/' | head -c 24)Gx!"
    if [[ -n "$p" && "$p" != "$portal" ]]; then
      printf '%s' "$p"
      return
    fi
  done
}

ENV_FILE="$DEST/.env"
PORTAL_PASS="$(portal_pass)"
if [[ ! -f "$ENV_FILE" ]]; then
  ADMIN_PASS="$(gen_unique_pass)"
  cat >"$ENV_FILE" <<EOF
GF_ADMIN_USER=admin
GF_ADMIN_PASSWORD=${ADMIN_PASS}
GF_DOMAIN=${DOMAIN}
GF_ROOT_URL=${ROOT_URL}
EOF
  chmod 600 "$ENV_FILE"
  echo "Wrote $ENV_FILE (unique admin password)"
else
  # Keep file, but rotate if password missing or equals portal password.
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
  CUR="${GF_ADMIN_PASSWORD:-}"
  if [[ -z "$CUR" || ( -n "$PORTAL_PASS" && "$CUR" == "$PORTAL_PASS" ) ]]; then
    ADMIN_PASS="$(gen_unique_pass)"
    if grep -q '^GF_ADMIN_PASSWORD=' "$ENV_FILE"; then
      sed -i "s|^GF_ADMIN_PASSWORD=.*|GF_ADMIN_PASSWORD=${ADMIN_PASS}|" "$ENV_FILE"
    else
      echo "GF_ADMIN_PASSWORD=${ADMIN_PASS}" >>"$ENV_FILE"
    fi
    chmod 600 "$ENV_FILE"
    echo "Rotated GF_ADMIN_PASSWORD (was missing or matched portal)"
    ROTATE_IN_CONTAINER=1
  else
    ADMIN_PASS="$CUR"
    ROTATE_IN_CONTAINER=0
    echo "Keeping existing $ENV_FILE"
  fi
fi

# Ensure domain/url keys exist
grep -q '^GF_DOMAIN=' "$ENV_FILE" || echo "GF_DOMAIN=${DOMAIN}" >>"$ENV_FILE"
grep -q '^GF_ROOT_URL=' "$ENV_FILE" || echo "GF_ROOT_URL=${ROOT_URL}" >>"$ENV_FILE"
grep -q '^GF_ADMIN_USER=' "$ENV_FILE" || echo "GF_ADMIN_USER=admin" >>"$ENV_FILE"
chmod 600 "$ENV_FILE"

cd "$DEST"
docker compose pull
docker compose up -d

# If password was rotated after first boot, push it into Grafana's DB too.
if [[ "${ROTATE_IN_CONTAINER:-0}" == "1" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if docker exec sm-grafana grafana cli admin reset-admin-password "$GF_ADMIN_PASSWORD" >/dev/null 2>&1; then
      echo "Grafana admin password reset in container"
      break
    fi
    sleep 2
  done
fi

# Belt-and-suspenders: ensure Caddy network attachment even if compose external net failed once.
docker network connect truemail_truemail sm-grafana 2>/dev/null || true

sleep 2
docker compose ps
echo "Grafana listening on 127.0.0.1:${PORT} (not public); Caddy → sm-grafana:3000 → ${ROOT_URL}"
curl -sS -o /dev/null -w "health_localhost=%{http_code}\n" "http://127.0.0.1:${PORT}/api/health" || true
# Public bind check (should fail / connection refused from wildcard perspective)
if ss -lntp | grep -q '0.0.0.0:3016'; then
  echo "WARNING: Grafana still published on 0.0.0.0:3016" >&2
  exit 1
fi
ss -lntp | grep 3016 || true
