#!/usr/bin/env bash
# Restrict NAS FTP (:2121 + PASV 50100-50200) and NAS SMB gateway (:1445)
# to LAN/VPN clients. Safe to re-run.
set -euo pipefail

VPN_UFW_FROM="${VPN_UFW_FROM:-10.8.0.0/24 10.9.0.0/24 100.64.0.0/10 192.168.8.0/24}"
NAS_EXTRA_ALLOW="${NAS_EXTRA_ALLOW:-10.42.42.0/24 172.16.0.0/12}"
FTP_PORT="${NAS_FTP_PUBLIC_PORT:-2121}"
PASV_START="${NAS_FTP_PASV_START:-50100}"
PASV_END="${NAS_FTP_PASV_END:-50200}"
SMB_PORT="${NAS_SMB_PUBLIC_PORT:-1445}"
SFTP_PORT="${NAS_SFTP_PUBLIC_PORT:-2123}"

sources=()
for p in ${VPN_UFW_FROM//,/ }; do
  [[ -n "${p// }" ]] && sources+=("$p")
done
for p in ${NAS_EXTRA_ALLOW//,/ }; do
  [[ -n "${p// }" ]] && sources+=("$p")
done
declare -A seen=()
uniq_sources=()
for s in "${sources[@]}"; do
  [[ -n "${seen[$s]:-}" ]] && continue
  seen[$s]=1
  uniq_sources+=("$s")
done
sources=("${uniq_sources[@]}")

echo "NAS gateway allow sources: ${sources[*]}"

if ! command -v ufw >/dev/null 2>&1; then
  echo "ufw not installed" >&2
  exit 1
fi

needles=(
  "${FTP_PORT}/tcp"
  "${FTP_PORT}/udp"
  "${SMB_PORT}/tcp"
  "${SMB_PORT}/udp"
  "${SFTP_PORT}/tcp"
  "${PASV_START}:${PASV_END}/tcp"
  "nas-ftp-gateway"
  "nas-ftp-pasv"
  "nas-ftp-vpn"
  "nas-ftp-pasv-vpn"
  "nas-sftp-vpn"
  "nas-smb-vpn"
  "GL forward nas-smb"
)

# Delete highest matching rule number repeatedly (stable under renumbering).
for _ in $(seq 1 80); do
  numbered="$(ufw status numbered 2>/dev/null || true)"
  num=""
  while IFS= read -r line; do
    [[ "$line" == \[* ]] || continue
    hit=0
    for n in "${needles[@]}"; do
      if [[ "$line" == *"$n"* ]]; then
        hit=1
        break
      fi
    done
    [[ "$hit" -eq 1 ]] || continue
    nraw="${line%%]*}"
    nraw="${nraw#[}"
    nraw="${nraw// /}"
    [[ "$nraw" =~ ^[0-9]+$ ]] || continue
    if [[ -z "$num" || "$nraw" -gt "$num" ]]; then
      num="$nraw"
    fi
  done <<< "$numbered"
  [[ -z "${num:-}" ]] && break
  ufw --force delete "$num" >/dev/null || true
done

for src in "${sources[@]}"; do
  ufw allow from "$src" to any port "$FTP_PORT" proto tcp comment "nas-ftp-vpn" >/dev/null || true
  ufw allow from "$src" to any port "${PASV_START}:${PASV_END}" proto tcp comment "nas-ftp-pasv-vpn" >/dev/null || true
  ufw allow from "$src" to any port "$SMB_PORT" proto tcp comment "nas-smb-vpn" >/dev/null || true
  ufw allow from "$src" to any port "$SMB_PORT" proto udp comment "nas-smb-vpn" >/dev/null || true
  ufw allow from "$src" to any port "$SFTP_PORT" proto tcp comment "nas-sftp-vpn" >/dev/null || true
done

echo "ufw: ${FTP_PORT}/tcp + ${PASV_START}-${PASV_END}/tcp + ${SMB_PORT}/tcp|udp + ${SFTP_PORT}/tcp → VPN/LAN"

# :1445 is DNAT'd to the NAS (FORWARD path). UFW INPUT alone cannot lock it —
# rewrite SERVERMANAGER_DNAT so only VPN/LAN sources are redirected.
VPS_IP="${VPS_PUBLIC_IP:-$(curl -4 -fsS --max-time 5 ifconfig.me 2>/dev/null || true)}"
VPS_IP="${VPS_IP:-74.208.76.213}"
NAS_SMB_HOST="${NAS_SMB_HOST:-192.168.8.159}"
NAS_SMB_DEST_PORT="${NAS_SMB_DEST_PORT:-445}"
CHAIN="SERVERMANAGER_DNAT"

if iptables -t nat -L "$CHAIN" >/dev/null 2>&1; then
  # Drop every existing 1445 DNAT in the managed chain (scoped or not).
  while iptables -t nat -S "$CHAIN" 2>/dev/null | grep -qE -- "--dport ${SMB_PORT} "; do
    line="$(iptables -t nat -S "$CHAIN" | grep -E -- "--dport ${SMB_PORT} " | head -1 || true)"
    [[ -z "$line" ]] && break
    eval "iptables -t nat ${line/-A/-D}" 2>/dev/null || break
  done
  for src in "${sources[@]}"; do
    iptables -t nat -A "$CHAIN" -s "$src" -d "$VPS_IP" -p tcp --dport "$SMB_PORT" \
      -j DNAT --to-destination "${NAS_SMB_HOST}:${NAS_SMB_DEST_PORT}"
  done
  echo "dnat: ${SMB_PORT}/tcp → ${NAS_SMB_HOST}:${NAS_SMB_DEST_PORT} (VPN/LAN sources only)"
  iptables -t nat -S "$CHAIN" | grep -E -- "--dport ${SMB_PORT} " || true
else
  echo "dnat: chain $CHAIN missing (skip ${SMB_PORT} rewrite)"
fi

ufw status numbered | grep -E "${FTP_PORT}|${SMB_PORT}|${SFTP_PORT}|${PASV_START}|nas-ftp|nas-smb|nas-sftp" || true
ss -lntp 2>/dev/null | grep -E ":${FTP_PORT}|:${SMB_PORT}|:${SFTP_PORT}" || true
echo "NAS FTP/SFTP/SMB gateway VPN-only harden complete"
