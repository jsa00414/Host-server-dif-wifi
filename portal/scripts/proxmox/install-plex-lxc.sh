#!/usr/bin/env bash
# Create / update a Plex Media Server LXC on the Proxmox host.
# Run on the Proxmox host (or: ssh root@192.168.8.160 bash -s < install-plex-lxc.sh)
set -euo pipefail

CTID="${CTID:-101}"
CT_HOSTNAME="${CT_HOSTNAME:-plex}"
CT_IP="${CT_IP:-192.168.8.161}"
CT_CIDR="${CT_CIDR:-24}"
CT_GW="${CT_GW:-192.168.8.1}"
BRIDGE="${BRIDGE:-vmbr0}"
STORAGE="${STORAGE:-local-lvm}"
TEMPLATE_STORAGE="${TEMPLATE_STORAGE:-local}"
CORES="${CORES:-2}"
MEMORY_MB="${MEMORY_MB:-4096}"
SWAP_MB="${SWAP_MB:-512}"
DISK_GB="${DISK_GB:-32}"
TEMPLATE_MATCH="${TEMPLATE_MATCH:-debian-12-standard}"
UNPRIVILEGED="${UNPRIVILEGED:-1}"

if ! command -v pct >/dev/null 2>&1; then
  echo "pct not found — run this on the Proxmox host" >&2
  exit 1
fi

echo "==> Ensuring Debian LXC template (${TEMPLATE_MATCH})…"
mapfile -t available < <(pveam available --section system 2>/dev/null | awk '{print $2}' | grep -F "$TEMPLATE_MATCH" | grep amd64 || true)
if [[ ${#available[@]} -eq 0 ]]; then
  echo "No matching template listed by pveam for ${TEMPLATE_MATCH}" >&2
  exit 1
fi
TEMPLATE_FILE="${available[-1]}"
if ! pveam list "$TEMPLATE_STORAGE" 2>/dev/null | grep -qF "$TEMPLATE_FILE"; then
  echo "Downloading ${TEMPLATE_FILE}…"
  pveam download "$TEMPLATE_STORAGE" "$TEMPLATE_FILE"
fi
TEMPLATE_PATH="${TEMPLATE_STORAGE}:vztmpl/${TEMPLATE_FILE}"

if pct status "$CTID" >/dev/null 2>&1; then
  echo "==> CT ${CTID} already exists — leaving config, ensuring it is running…"
else
  echo "==> Creating CT ${CTID} (${CT_HOSTNAME} @ ${CT_IP}/${CT_CIDR})…"
  pct create "$CTID" "$TEMPLATE_PATH" \
    --hostname "$CT_HOSTNAME" \
    --cores "$CORES" \
    --memory "$MEMORY_MB" \
    --swap "$SWAP_MB" \
    --rootfs "${STORAGE}:${DISK_GB}" \
    --net0 "name=eth0,bridge=${BRIDGE},ip=${CT_IP}/${CT_CIDR},gw=${CT_GW}" \
    --nameserver 1.1.1.1 \
    --searchdomain lan \
    --unprivileged "$UNPRIVILEGED" \
    --features nesting=1,keyctl=1 \
    --ostype debian \
    --onboot 1 \
    --start 0
fi

pct set "$CTID" \
  --onboot 1 \
  --hostname "$CT_HOSTNAME" \
  --cores "$CORES" \
  --memory "$MEMORY_MB" \
  --swap "$SWAP_MB" \
  --net0 "name=eth0,bridge=${BRIDGE},ip=${CT_IP}/${CT_CIDR},gw=${CT_GW}" \
  --nameserver 1.1.1.1 \
  --features nesting=1,keyctl=1 \
  --description "Plex Media Server for portal.vpstruelord.com (plex.vpstruelord.com)" >/dev/null

if ! pct status "$CTID" 2>/dev/null | grep -qi running; then
  echo "==> Starting CT ${CTID}…"
  pct start "$CTID"
  sleep 4
fi

echo "==> Installing Plex Media Server inside CT ${CTID}…"
pct exec "$CTID" -- bash -s <<'INNER'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl gnupg ca-certificates apt-transport-https cifs-utils >/dev/null
install -d -m 0755 /usr/share/keyrings
if [[ ! -f /usr/share/keyrings/plex.gpg ]]; then
  curl -fsSL https://downloads.plex.tv/plex-keys/PlexSign.key | gpg --dearmor -o /usr/share/keyrings/plex.gpg
fi
echo "deb [signed-by=/usr/share/keyrings/plex.gpg] https://downloads.plex.tv/repo/deb public main" \
  > /etc/apt/sources.list.d/plexmediaserver.list
apt-get update -qq
apt-get install -y -qq plexmediaserver
systemctl enable --now plexmediaserver
# Give Plex a moment to bind :32400
for i in $(seq 1 20); do
  if ss -ltn 2>/dev/null | grep -q ':32400'; then
    break
  fi
  sleep 1
done
ss -ltn | grep 32400 || true
systemctl is-active plexmediaserver
INNER

echo
echo "Plex LXC ready:"
echo "  CTID     ${CTID}"
echo "  LAN URL  http://${CT_IP}:32400/web"
echo "  Portal   https://plex.vpstruelord.com/web (after portal hookup deploy)"
echo
pct status "$CTID" || true
pct config "$CTID" | sed -n '1,40p'
