#!/usr/bin/env bash
# Merge Twilio OTP settings into /opt/truemail/.env (+ portal env) on the VPS.
# Secrets come from the environment — never commit them.
#
#   set -a; source /path/to/twilio.env; set +a
#   VPS=root@74.208.76.213 ./portal/scripts/configure-twilio-truemail.sh
set -euo pipefail

VPS="${VPS:-root@74.208.76.213}"

: "${TWILIO_ACCOUNT_SID:?set TWILIO_ACCOUNT_SID}"
: "${TWILIO_AUTH_TOKEN:?set TWILIO_AUTH_TOKEN}"
: "${SMS_CODE_TO:?set SMS_CODE_TO}"

if [[ -z "${TWILIO_FROM_NUMBER:-}" && -z "${TWILIO_MESSAGING_SERVICE_SID:-}" ]]; then
  echo "Set TWILIO_FROM_NUMBER and/or TWILIO_MESSAGING_SERVICE_SID" >&2
  exit 1
fi

SSH_OPTS=()
if [[ -n "${VPS_SSH_KEY_FILE:-}" && -f "${VPS_SSH_KEY_FILE}" ]]; then
  SSH_OPTS=(-i "$VPS_SSH_KEY_FILE")
fi

PAYLOAD_B64="$(
  TWILIO_ACCOUNT_SID="$TWILIO_ACCOUNT_SID" \
  TWILIO_AUTH_TOKEN="$TWILIO_AUTH_TOKEN" \
  SMS_CODE_TO="$SMS_CODE_TO" \
  TWILIO_FROM_NUMBER="${TWILIO_FROM_NUMBER:-}" \
  TWILIO_MESSAGING_SERVICE_SID="${TWILIO_MESSAGING_SERVICE_SID:-}" \
  TRUEMAIL_ENV_PATH="${TRUEMAIL_ENV_PATH:-/opt/truemail/.env}" \
  PANEL_ENV_PATH="${PANEL_ENV_PATH:-/opt/wireguard/port-forward-ui.env}" \
  python3 - <<'PY'
import base64, json, os, re

def norm(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    digits = re.sub(r"\D+", "", raw)
    if raw.startswith("+"):
        return f"+{digits}" if digits else ""
    if len(digits) == 10:
        return f"+1{digits}"
    if len(digits) == 11 and digits.startswith("1"):
        return f"+{digits}"
    return f"+{digits}" if digits else ""

keys = {
    "TWILIO_ACCOUNT_SID": os.environ["TWILIO_ACCOUNT_SID"].strip(),
    "TWILIO_AUTH_TOKEN": os.environ["TWILIO_AUTH_TOKEN"].strip(),
    "SMS_CODE_TO": norm(os.environ["SMS_CODE_TO"]),
}
from_n = norm(os.environ.get("TWILIO_FROM_NUMBER", ""))
svc = (os.environ.get("TWILIO_MESSAGING_SERVICE_SID") or "").strip()
if from_n:
    keys["TWILIO_FROM_NUMBER"] = from_n
if svc:
    keys["TWILIO_MESSAGING_SERVICE_SID"] = svc
payload = {
    "truemail_env": os.environ.get("TRUEMAIL_ENV_PATH", "/opt/truemail/.env"),
    "panel_env": os.environ.get("PANEL_ENV_PATH", "/opt/wireguard/port-forward-ui.env"),
    "keys": keys,
}
print(base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii"))
PY
)"

echo "Configuring Twilio on ${VPS} …"
ssh "${SSH_OPTS[@]}" "$VPS" "PAYLOAD_B64='${PAYLOAD_B64}' python3 - <<'PY'
import base64, json, os
from pathlib import Path

payload = json.loads(base64.b64decode(os.environ['PAYLOAD_B64']).decode('utf-8'))
keys = payload['keys']

def upsert(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = path.read_text(encoding='utf-8', errors='replace') if path.is_file() else ''
    lines = text.splitlines()
    out, seen = [], set()
    for line in lines:
        if not line.strip() or line.lstrip().startswith('#') or '=' not in line:
            out.append(line)
            continue
        k = line.split('=', 1)[0].strip()
        if k in keys:
            out.append(f'{k}={keys[k]}')
            seen.add(k)
        else:
            out.append(line)
    for k, v in keys.items():
        if k not in seen:
            out.append(f'{k}={v}')
    path.write_text('\\n'.join(out).rstrip() + '\\n', encoding='utf-8')
    try:
        path.chmod(0o600)
    except OSError:
        pass
    print(f'updated {path}')

upsert(Path(payload['truemail_env']))
panel = Path(payload['panel_env'])
if panel.parent.is_dir():
    upsert(panel)
PY
systemctl restart port-forward-ui && systemctl is-active port-forward-ui"

echo "Done. Hard-refresh the portal, then try Security → SMS (Twilio) or /sms-code-test.html"
