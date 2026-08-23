#!/usr/bin/env bash
# VPS server bootstrap — installs Docker, WireGuard Easy v15.3.0, Caddy, and Domain Manager
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/vps-wireguard}"
ENV_FILE="${INSTALL_DIR}/.env"

echo "==> VPS WireGuard Setup — installing to ${INSTALL_DIR}"

if ! command -v docker &>/dev/null; then
  echo "==> Installing Docker..."
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker || true
fi

if ! docker compose version &>/dev/null; then
  echo "ERROR: docker compose plugin not found after Docker install."
  exit 1
fi

mkdir -p "${INSTALL_DIR}/domains"
cd "${INSTALL_DIR}"

if [[ -f "${ENV_FILE}" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
  set +a
fi

echo "==> Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.src_valid_mark=1

if [[ -f /etc/sysctl.conf ]] && ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
  echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi

echo "==> Building and starting stack..."
docker compose --env-file "${ENV_FILE}" pull wg-easy caddy 2>/dev/null || true
docker compose --env-file "${ENV_FILE}" build domain-manager
docker compose --env-file "${ENV_FILE}" up -d

echo ""
echo "============================================"
echo "  Deployment complete!"
echo "============================================"
echo ""
echo "WireGuard Easy UI:  http://${VPS_HOST:-localhost}:${WG_UI_PORT:-51821}"
echo "  Complete the setup wizard in your browser."
echo ""
echo "WireGuard tunnel:   UDP ${WG_TUNNEL_PORT:-51820}"
echo ""
if [[ -n "${DOMAIN_MANAGER_HOST:-}" ]]; then
  echo "Domain Manager:     https://${DOMAIN_MANAGER_HOST}"
  echo "  (VPN-only — connect via WireGuard first)"
  if [[ -n "${DOMAIN_ADMIN_TOKEN:-}" ]]; then
    echo "  Admin URL:        https://${DOMAIN_MANAGER_HOST}?token=${DOMAIN_ADMIN_TOKEN}"
  fi
fi
if [[ -n "${WG_DOMAIN:-}" && "${WG_DOMAIN}" != "localhost" ]]; then
  echo "WireGuard UI (TLS): https://${WG_DOMAIN}"
fi
echo ""
echo "WireGuard Easy v15.3.0 © 2021-2026 Emile Nijssen — AGPL-3.0-only"
echo "============================================"
