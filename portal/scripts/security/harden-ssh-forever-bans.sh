#!/usr/bin/env bash
# Make fail2ban sshd bans permanent (bantime=-1) and apply a forever ban list.
# Safe to re-run.
set -euo pipefail

JAIL_DROPIN="${JAIL_DROPIN:-/etc/fail2ban/jail.d/sshd-forever.conf}"
BAN_LIST_SRC="${BAN_LIST_SRC:-}"
BAN_LIST_DST="${BAN_LIST_DST:-/opt/servermanager/panel/ssh-forever-bans.txt}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -z "$BAN_LIST_SRC" ]]; then
  if [[ -f "$SCRIPT_DIR/ssh-forever-ban-list.txt" ]]; then
    BAN_LIST_SRC="$SCRIPT_DIR/ssh-forever-ban-list.txt"
  elif [[ -f "$BAN_LIST_DST" ]]; then
    BAN_LIST_SRC="$BAN_LIST_DST"
  else
    BAN_LIST_SRC=""
  fi
fi

if ! command -v fail2ban-client >/dev/null 2>&1; then
  echo "fail2ban-client not found" >&2
  exit 1
fi

mkdir -p "$(dirname "$JAIL_DROPIN")" /opt/servermanager/panel

cat >"$JAIL_DROPIN" <<'CONF'
# Managed by harden-ssh-forever-bans.sh — permanent sshd bans
[sshd]
enabled = true
bantime = -1
findtime = 1d
maxretry = 3
CONF
echo "wrote $JAIL_DROPIN (bantime=-1, maxretry=3, findtime=1d)"

if [[ -n "$BAN_LIST_SRC" && -f "$BAN_LIST_SRC" ]]; then
  # Merge into destination (keep comments + unique IPs)
  {
    echo "# Permanent sshd bans — managed by harden-ssh-forever-bans.sh"
    echo "# Updated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    if [[ -f "$BAN_LIST_DST" ]]; then
      grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' "$BAN_LIST_DST" || true
    fi
    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' "$BAN_LIST_SRC" || true
  } | awk 'BEGIN{print "# Permanent sshd bans — managed by harden-ssh-forever-bans.sh"} /^#/{next} NF{ if(!seen[$0]++){ print } }' >"${BAN_LIST_DST}.tmp"
  # rewrite with header timestamp
  {
    echo "# Permanent sshd bans — managed by harden-ssh-forever-bans.sh"
    echo "# Updated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' "${BAN_LIST_DST}.tmp" || true
  } >"$BAN_LIST_DST"
  rm -f "${BAN_LIST_DST}.tmp"
  chmod 600 "$BAN_LIST_DST"
  echo "ban list: $BAN_LIST_DST ($(grep -cE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' "$BAN_LIST_DST") IPs)"
fi

systemctl reload fail2ban 2>/dev/null || systemctl restart fail2ban
sleep 1
# Confirm bantime
bt="$(fail2ban-client get sshd bantime 2>/dev/null || echo '?')"
echo "sshd bantime now: $bt (want -1)"

if [[ -f "$BAN_LIST_DST" ]]; then
  ok=0
  skip=0
  while read -r ip; do
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
    if fail2ban-client get sshd banip 2>/dev/null | tr ' ' '\n' | grep -qx "$ip"; then
      skip=$((skip + 1))
      continue
    fi
    if fail2ban-client set sshd banip "$ip" >/dev/null; then
      ok=$((ok + 1))
    fi
  done < <(grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' "$BAN_LIST_DST")
  echo "banned_new=$ok already=$skip"
fi

fail2ban-client status sshd | grep -E 'Currently banned|Total banned|Banned IP' || true
