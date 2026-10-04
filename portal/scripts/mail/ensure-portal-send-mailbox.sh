#!/usr/bin/env bash
# Ensure the portal-only SMTP mailbox exists (portal@truemailor.com).
# Does not print the password. Safe to re-run.
set -euo pipefail

MAIL_USER="${PORTAL_SMTP_USER:-portal@truemailor.com}"
ENV_FILE="${PORTAL_ENV_FILE:-/opt/wireguard/port-forward-ui.env}"
CONTAINER="${MAILSERVER_CONTAINER:-truemail-mailserver-1}"

if ! docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
  echo "mailserver container missing: $CONTAINER" >&2
  exit 1
fi

if [[ ! -f "$ENV_FILE" ]]; then
  echo "missing $ENV_FILE" >&2
  exit 1
fi

# shellcheck disable=SC1090
set -a
# shellcheck source=/dev/null
. "$ENV_FILE"
set +a

PASS="${PORTAL_SMTP_PASS:-}"
if [[ -z "$PASS" ]]; then
  PASS="$(python3 -c 'import secrets,string; a=string.ascii_letters+string.digits; print("".join(secrets.choice(a) for _ in range(24)))')"
  if grep -q '^PORTAL_SMTP_PASS=' "$ENV_FILE"; then
    sed -i "s|^PORTAL_SMTP_PASS=.*|PORTAL_SMTP_PASS=${PASS}|" "$ENV_FILE"
  else
    printf 'PORTAL_SMTP_PASS=%s\n' "$PASS" >>"$ENV_FILE"
  fi
  chmod 600 "$ENV_FILE"
  echo "generated PORTAL_SMTP_PASS in env"
fi

# Upsert From/To/User defaults
python3 - "$ENV_FILE" "$MAIL_USER" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
user = sys.argv[2]
wanted = {
    "EMAIL_CODE_FROM": user,
    "EMAIL_CODE_TO": "portalvpsserver@truemailor.com",
    "PORTAL_SMTP_USER": user,
}
lines = path.read_text().splitlines()
keys = set()
out = []
for ln in lines:
    if "=" not in ln or ln.lstrip().startswith("#"):
        out.append(ln)
        continue
    k, _, _ = ln.partition("=")
    if k in wanted:
        out.append(f"{k}={wanted[k]}")
        keys.add(k)
    else:
        out.append(ln)
for k, v in wanted.items():
    if k not in keys:
        out.append(f"{k}={v}")
path.write_text("\n".join(out).rstrip() + "\n")
path.chmod(0o600)
print("env From/User set to", user)
PY

if docker exec "$CONTAINER" setup email list 2>/dev/null | grep -qE "^\\* ${MAIL_USER}( |$)"; then
  docker exec "$CONTAINER" setup email update "$MAIL_USER" "$PASS" >/dev/null
  echo "updated mailbox $MAIL_USER"
else
  docker exec "$CONTAINER" setup email add "$MAIL_USER" "$PASS" >/dev/null
  echo "created mailbox $MAIL_USER"
fi

echo "portal send mailbox ready: $MAIL_USER"
