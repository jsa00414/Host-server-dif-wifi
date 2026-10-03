#!/usr/bin/env bash
# Enforce tight permissions on VPS secret/env/TLS private key files.
# Safe to re-run. Does not print file contents.
set -euo pipefail

fix_mode() {
  local path="$1"
  local mode="$2"
  if [[ ! -e "$path" ]]; then
    echo "skip (missing): $path"
    return 0
  fi
  if [[ -L "$path" ]]; then
    path="$(readlink -f "$path" || true)"
    [[ -n "$path" && -e "$path" ]] || return 0
  fi
  local before
  before="$(stat -c '%a' "$path" 2>/dev/null || echo '?')"
  chown root:root "$path" 2>/dev/null || true
  chmod "$mode" "$path"
  local after
  after="$(stat -c '%a' "$path")"
  if [[ "$before" != "$after" ]]; then
    echo "fixed: $path ${before} → ${after}"
  else
    echo "ok:    $path mode=${after}"
  fi
}

fix_mode /opt/wireguard/.env 600
fix_mode /opt/wireguard/port-forward-ui.env 600
fix_mode /opt/grafana/.env 600
fix_mode /opt/truemail/.env 600
fix_mode /opt/servermanager-backup/secrets.env 600
fix_mode /opt/wireguard/nas-smb-gateway/credentials 600

# Panel state that can hold TOTP seed / circle membership.
fix_mode /opt/servermanager/panel/ssh-panel-2fa.json 600
fix_mode /opt/servermanager/panel/auth-app-devices.json 600
fix_mode /opt/servermanager/panel/vpn-allowlist.json 600
fix_mode /opt/servermanager/panel/caddy-sticky-vpn-ips.txt 600
fix_mode /opt/servermanager/panel/lan-circle-block.txt 600

fix_mode /opt/truemail/config/ssl/key.pem 600
fix_mode /opt/truemail/config/ssl/cert.pem 644
if [[ -d /opt/truemail/config/ssl ]]; then
  chmod 755 /opt/truemail/config/ssl
  chown root:root /opt/truemail/config/ssl
  echo "ok:    /opt/truemail/config/ssl dir"
fi

echo "secret permission harden complete"
