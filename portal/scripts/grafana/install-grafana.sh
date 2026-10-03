#!/usr/bin/env bash
# Install / update Grafana + Prometheus monitoring for ServerManager portal.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
DEST="${GRAFANA_DIR:-/opt/grafana}"
PORT="${GRAFANA_PORT:-3016}"
DOMAIN="${GF_DOMAIN:-grafana.vpstruelord.com}"
ROOT_URL="${GF_ROOT_URL:-https://${DOMAIN}}"

mkdir -p "$DEST" \
  "$DEST/prometheus" \
  "$DEST/provisioning/datasources" \
  "$DEST/provisioning/dashboards" \
  "$DEST/dashboards"

cp -f "$ROOT/docker-compose.yml" "$DEST/docker-compose.yml"
cp -f "$ROOT/prometheus/prometheus.yml" "$DEST/prometheus/prometheus.yml"
cp -f "$ROOT/provisioning/datasources/datasource.yml" "$DEST/provisioning/datasources/datasource.yml"
cp -f "$ROOT/provisioning/dashboards/dashboards.yml" "$DEST/provisioning/dashboards/dashboards.yml"
cp -f "$ROOT/dashboards/"*.json "$DEST/dashboards/"

ENV_FILE="$DEST/.env"
if [[ ! -f "$ENV_FILE" ]]; then
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
sleep 4
docker compose ps

echo "Grafana listening on 0.0.0.0:${PORT} → ${ROOT_URL}"
curl -sS -o /dev/null -w "grafana_health=%{http_code}\n" "http://127.0.0.1:${PORT}/api/health" || true
curl -sS -o /dev/null -w "prometheus_health=%{http_code}\n" "http://127.0.0.1:9090/-/healthy" || true
curl -sS -o /dev/null -w "node_exporter=%{http_code}\n" "http://127.0.0.1:9100/metrics" || true
curl -sS -o /dev/null -w "cadvisor=%{http_code}\n" "http://127.0.0.1:9101/metrics" || true

echo
echo "Dashboards:"
echo "  ServerManager — VPS Overview"
echo "  ServerManager — Docker Containers"
echo "Login: admin / (portal password or generated in $ENV_FILE)"
