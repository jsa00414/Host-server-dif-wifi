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

# Delete existing allows for FTP control, FTP PASV range, and SMB gateway.
# Match 2121, 1445, and 50100:50200 (with or without /tcp|/udp), IPv4+IPv6.
delete_matching() {
  local pattern="$1"
  for _ in $(seq 1 60); do
    numbered="$(ufw status numbered 2>/dev/null || true)"
    num="$(
      printf '%s\n' "$numbered" | awk -v re="$pattern" '
        /^\[[[:space:]]*[0-9]+\]/ {
          line=$0
          if (line ~ re) {
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
}

delete_matching "(^|[[:space:]])${FTP_PORT}/(tcp|udp)([[:space:]]|\\()"
delete_matching "(^|[[:space:]])${FTP_PORT}([[:space:]]|\\()"
delete_matching "(^|[[:space:]])${SMB_PORT}/(tcp|udp)([[:space:]]|\\()"
delete_matching "(^|[[:space:]])${SMB_PORT}([[:space:]]|\\()"
delete_matching "${PASV_START}:${PASV_END}/tcp"
delete_matching "nas-ftp-gateway|nas-ftp-pasv|GL forward nas-smb|nas-smb"

for src in "${sources[@]}"; do
  ufw allow from "$src" to any port "$FTP_PORT" proto tcp comment "nas-ftp-vpn" >/dev/null || true
  ufw allow from "$src" to any port "${PASV_START}:${PASV_END}" proto tcp comment "nas-ftp-pasv-vpn" >/dev/null || true
  ufw allow from "$src" to any port "$SMB_PORT" proto tcp comment "nas-smb-vpn" >/dev/null || true
  ufw allow from "$src" to any port "$SMB_PORT" proto udp comment "nas-smb-vpn" >/dev/null || true
done

echo "ufw: ${FTP_PORT}/tcp + ${PASV_START}-${PASV_END}/tcp + ${SMB_PORT}/tcp|udp → VPN/LAN"
ufw status numbered | grep -E "${FTP_PORT}|${SMB_PORT}|${PASV_START}|nas-ftp|nas-smb" || true
ss -lntp 2>/dev/null | grep -E ":${FTP_PORT}|:${SMB_PORT}" || true
echo "NAS FTP/SMB gateway VPN-only harden complete"
