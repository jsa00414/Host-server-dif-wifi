#!/usr/bin/env bash
# Restrict host Samba (smbd :445/:139) to LAN/VPN clients.
# - UFW: remove Anywhere allows for 445/139; add per-CIDR allows
# - Samba: hosts allow/deny drop-in (keeps listen on all ifaces so
#   \\public-ip works over VPN, while public Internet is rejected)
# Safe to re-run.
set -euo pipefail

VPN_UFW_FROM="${VPN_UFW_FROM:-10.8.0.0/24 10.9.0.0/24 100.64.0.0/10 192.168.8.0/24}"
# Extra sources that reach host SMB via Docker/WG-easy / loopback
SMB_EXTRA_ALLOW="${SMB_EXTRA_ALLOW:-10.42.42.0/24 172.16.0.0/12 127.0.0.1}"

SMB_DROPIN_DIR="/etc/samba/smb.conf.d"
SMB_DROPIN="${SMB_DROPIN_DIR}/00-vpn-only.conf"
SMB_CONF="/etc/samba/smb.conf"
INCLUDE_LINE="include = /etc/samba/smb.conf.d/00-vpn-only.conf"
COMMENT_445="samba-smb-vpn"
COMMENT_139="samba-netbios-vpn"

sources=()
for p in ${VPN_UFW_FROM//,/ }; do
  [[ -n "${p// }" ]] && sources+=("$p")
done
for p in ${SMB_EXTRA_ALLOW//,/ }; do
  [[ -n "${p// }" ]] && sources+=("$p")
done
# de-dupe
declare -A seen=()
uniq_sources=()
for s in "${sources[@]}"; do
  [[ -n "${seen[$s]:-}" ]] && continue
  seen[$s]=1
  uniq_sources+=("$s")
done
sources=("${uniq_sources[@]}")

echo "SMB allow sources: ${sources[*]}"

# --- UFW: drop Anywhere (and stale) 445/139, add VPN/LAN allows ---
if command -v ufw >/dev/null 2>&1; then
  # Delete numbered rules matching 445/139 (IPv4+IPv6). Repeat until none left.
  for _ in $(seq 1 40); do
    numbered="$(ufw status numbered 2>/dev/null || true)"
    # Pick highest matching rule number so deletions stay stable
    num="$(
      printf '%s\n' "$numbered" | awk '
        /^\[[[:space:]]*[0-9]+\]/ {
          line=$0
          if (line ~ /(^|\s)(445|139)\/(tcp|udp)(\s|\()/ || line ~ /(^|\s)(445|139)(\s|\()/) {
            if (match(line, /\[[[:space:]]*[0-9]+\]/)) {
              n=substr(line, RSTART+1, RLENGTH-2)
              gsub(/[[:space:]]/, "", n)
              print n+0
            }
          }
        }' | sort -nr | head -1
    )"
    [[ -z "${num:-}" ]] && break
    ufw --force delete "$num" >/dev/null || true
  done

  for src in "${sources[@]}"; do
    # Skip pure loopback for UFW (local always works via lo/before.rules)
    [[ "$src" == "127.0.0.1" || "$src" == "127.0.0.0/8" ]] && continue
    ufw allow from "$src" to any port 445 proto tcp comment "$COMMENT_445" >/dev/null || true
    ufw allow from "$src" to any port 139 proto tcp comment "$COMMENT_139" >/dev/null || true
  done
  echo "ufw: 445/139 restricted to VPN/LAN CIDRs"
else
  echo "ufw: not installed (skipped)"
fi

# --- Samba hosts allow/deny ---
mkdir -p "$SMB_DROPIN_DIR"
allow_list="127.0.0.1"
for s in "${sources[@]}"; do
  [[ "$s" == "127.0.0.1" ]] && continue
  allow_list+=" $s"
done

cat >"$SMB_DROPIN" <<EOF
# Managed by ServerManager harden-smb-vpn-only.sh — do not edit by hand
[global]
   hosts allow = ${allow_list}
   hosts deny = ALL
EOF
chmod 644 "$SMB_DROPIN"
echo "wrote $SMB_DROPIN"

if [[ -f "$SMB_CONF" ]]; then
  if ! grep -qF "$INCLUDE_LINE" "$SMB_CONF"; then
    # Insert include into [global] after the section header when possible
    if grep -qE '^\[global\]' "$SMB_CONF"; then
      awk -v inc="$INCLUDE_LINE" '
        BEGIN { done=0 }
        /^\[global\]/ && !done {
          print
          print inc
          done=1
          next
        }
        { print }
        END {
          if (!done) print inc
        }
      ' "$SMB_CONF" >"${SMB_CONF}.tmp"
      mv "${SMB_CONF}.tmp" "$SMB_CONF"
    else
      printf '\n%s\n' "$INCLUDE_LINE" >>"$SMB_CONF"
    fi
    echo "enabled include in $SMB_CONF"
  else
    echo "include already present in $SMB_CONF"
  fi
fi

if command -v testparm >/dev/null 2>&1; then
  if ! testparm -s >/dev/null 2>&1; then
    echo "ERROR: testparm failed after smb.conf change" >&2
    testparm -s >&2 || true
    exit 1
  fi
fi

if systemctl is-active --quiet smbd 2>/dev/null; then
  systemctl reload smbd 2>/dev/null || systemctl restart smbd
  echo "smbd: reloaded"
elif systemctl list-unit-files smbd.service >/dev/null 2>&1; then
  systemctl restart smbd 2>/dev/null || true
  echo "smbd: restarted (was inactive)"
fi

echo "Samba/SMB VPN-only harden complete"
ufw status numbered 2>/dev/null | grep -E '445|139' || true
ss -lntp 2>/dev/null | grep -E ':445|:139' || true
