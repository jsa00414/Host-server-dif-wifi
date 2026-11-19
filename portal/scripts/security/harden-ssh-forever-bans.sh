#!/usr/bin/env bash
# SSH progressive bans via fail2ban:
#   sshd:     3 fails → 10 minute ban (same day window)
#   recidive: 5 ban rounds in 1 day → permanent ban
# Also re-applies a manual forever-ban list (permanent).
# Safe to re-run.
set -euo pipefail

JAIL_DROPIN="${JAIL_DROPIN:-/etc/fail2ban/jail.d/sshd-forever.conf}"
BAN_LIST_SRC="${BAN_LIST_SRC:-}"
BAN_LIST_DST="${BAN_LIST_DST:-/opt/servermanager/panel/ssh-forever-bans.txt}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SSHD_BANTIME="${SSHD_BANTIME:-10m}"
SSHD_FINDTIME="${SSHD_FINDTIME:-1d}"
SSHD_MAXRETRY="${SSHD_MAXRETRY:-3}"
RECIDIVE_MAXRETRY="${RECIDIVE_MAXRETRY:-5}"
RECIDIVE_FINDTIME="${RECIDIVE_FINDTIME:-1d}"

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

if [[ ! -f /etc/fail2ban/filter.d/recidive.conf ]]; then
  echo "missing /etc/fail2ban/filter.d/recidive.conf" >&2
  exit 1
fi

cat >"$JAIL_DROPIN" <<CONF
# Managed by harden-ssh-forever-bans.sh
# Policy: 3 fails → ${SSHD_BANTIME}; 5 rounds in ${RECIDIVE_FINDTIME} → permanent
[sshd]
enabled = true
bantime = ${SSHD_BANTIME}
findtime = ${SSHD_FINDTIME}
maxretry = ${SSHD_MAXRETRY}

[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
backend = auto
banaction = %(banaction_allports)s
bantime = -1
findtime = ${RECIDIVE_FINDTIME}
maxretry = ${RECIDIVE_MAXRETRY}
CONF
echo "wrote $JAIL_DROPIN"
echo "  sshd:     maxretry=${SSHD_MAXRETRY} bantime=${SSHD_BANTIME} findtime=${SSHD_FINDTIME}"
echo "  recidive: maxretry=${RECIDIVE_MAXRETRY} bantime=-1 findtime=${RECIDIVE_FINDTIME}"

if [[ -n "$BAN_LIST_SRC" && -f "$BAN_LIST_SRC" ]]; then
  {
    echo "# Permanent sshd/recidive bans — managed by harden-ssh-forever-bans.sh"
    echo "# Updated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    if [[ -f "$BAN_LIST_DST" ]]; then
      grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' "$BAN_LIST_DST" || true
    fi
    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' "$BAN_LIST_SRC" || true
  } | awk '
    BEGIN { hdr=0 }
    /^#/ { next }
    NF {
      if (!seen[$0]++) ips[++n]=$0
    }
    END {
      print "# Permanent ssh / recidive bans — managed by harden-ssh-forever-bans.sh"
      print "# Updated: '"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"
      print "# Policy note: auto path is 3 fails→10m; 5 rounds/day→permanent"
      for (i=1;i<=n;i++) print ips[i]
    }
  ' >"${BAN_LIST_DST}.tmp"
  mv "${BAN_LIST_DST}.tmp" "$BAN_LIST_DST"
  chmod 600 "$BAN_LIST_DST"
  echo "ban list: $BAN_LIST_DST ($(grep -cE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' "$BAN_LIST_DST") IPs)"
fi

systemctl reload fail2ban 2>/dev/null || systemctl restart fail2ban
# reload sometimes does not pick new jails — restart if recidive missing
sleep 1
if ! fail2ban-client status recidive >/dev/null 2>&1; then
  systemctl restart fail2ban
  sleep 2
fi

echo "sshd bantime:     $(fail2ban-client get sshd bantime 2>/dev/null || echo '?')"
echo "sshd maxretry:    $(fail2ban-client get sshd maxretry 2>/dev/null || echo '?')"
echo "recidive bantime: $(fail2ban-client get recidive bantime 2>/dev/null || echo '?')"
echo "recidive maxretry:$(fail2ban-client get recidive maxretry 2>/dev/null || echo '?')"

# Manual forever list → recidive jail (permanent)
if [[ -f "$BAN_LIST_DST" ]] && fail2ban-client status recidive >/dev/null 2>&1; then
  ok=0
  skip=0
  while read -r ip; do
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
    if fail2ban-client get recidive banip 2>/dev/null | tr ' ' '\n' | grep -qx "$ip"; then
      skip=$((skip + 1))
      continue
    fi
    if fail2ban-client set recidive banip "$ip" >/dev/null; then
      ok=$((ok + 1))
    fi
  done < <(grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' "$BAN_LIST_DST")
  echo "recidive forever list: banned_new=$ok already=$skip"
fi

echo
echo "=== sshd ==="
fail2ban-client status sshd | grep -E 'Currently banned|Total banned|maxretry|Banned IP' || fail2ban-client status sshd | tail -8
echo "=== recidive (permanent) ==="
fail2ban-client status recidive | grep -E 'Currently banned|Total banned|Banned IP' || fail2ban-client status recidive | tail -8
