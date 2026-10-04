#!/usr/bin/env bash
# Restore-drill: copy live panel JSON, sticky IPs, and OpenVPN CCD into a scratch
# tree and verify they parse / look sane. Never overwrites production paths.
set -euo pipefail

SCRATCH="${SM_RESTORE_DRILL_DIR:-/tmp/sm-restore-drill-$$}"
PANEL_DIR="${SERVERMANAGER_PANEL_DIR:-/opt/servermanager/panel}"
CCD_DIR="${OPENVPN_CCD_DIR:-/opt/openvpn/ccd}"
STICKY="${STICKY_VPN_IPS_FILE:-$PANEL_DIR/caddy-sticky-vpn-ips.txt}"
ALLOWLIST="${VPN_ALLOWLIST_FILE:-$PANEL_DIR/vpn-allowlist.json}"
DEVICES="${AUTH_APP_DEVICES_FILE:-$PANEL_DIR/auth-app-devices.json}"
SSH2FA="${SSH_PANEL_2FA_FILE:-$PANEL_DIR/ssh-panel-2fa.json}"
ENROLL_ENC="${ENROLL_SECRETS_VAULT_PATH:-$PANEL_DIR/enroll-secrets.enc}"

echo "restore-drill: scratch=$SCRATCH"
mkdir -p "$SCRATCH"/{panel,ccd,meta}

copy_if() {
  local src="$1" dest="$2"
  if [[ -e "$src" ]]; then
    cp -a "$src" "$dest"
    echo "  ok  $src"
  else
    echo "  miss $src"
  fi
}

copy_if "$ALLOWLIST" "$SCRATCH/panel/vpn-allowlist.json"
copy_if "$STICKY" "$SCRATCH/panel/caddy-sticky-vpn-ips.txt"
copy_if "$DEVICES" "$SCRATCH/panel/auth-app-devices.json"
copy_if "$SSH2FA" "$SCRATCH/panel/ssh-panel-2fa.json"
copy_if "$ENROLL_ENC" "$SCRATCH/panel/enroll-secrets.enc"
if [[ -d "$CCD_DIR" ]]; then
  rsync -a "$CCD_DIR/" "$SCRATCH/ccd/" 2>/dev/null || cp -a "$CCD_DIR"/. "$SCRATCH/ccd/" 2>/dev/null || true
  echo "  ok  $CCD_DIR -> $SCRATCH/ccd/"
else
  echo "  miss $CCD_DIR"
fi

python3 - "$SCRATCH" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
errors = []

def load_json(p):
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, (dict, list)):
            errors.append(f"{p.name}: not object/list")
        else:
            print(f"parse-ok {p.name}")
    except Exception as exc:
        errors.append(f"{p.name}: {exc}")

for name in ("vpn-allowlist.json", "auth-app-devices.json", "ssh-panel-2fa.json"):
    p = root / "panel" / name
    if p.is_file():
        load_json(p)
    else:
        print(f"skip {name} (missing)")

sticky = root / "panel" / "caddy-sticky-vpn-ips.txt"
if sticky.is_file():
    ips = [ln.strip() for ln in sticky.read_text().splitlines() if ln.strip() and not ln.startswith("#")]
    print(f"sticky-lines {len(ips)}")
else:
    print("sticky missing")

ccd = root / "ccd"
if ccd.is_dir():
    files = [p.name for p in ccd.iterdir() if p.is_file()]
    print(f"ccd-files {len(files)}: {', '.join(sorted(files)[:12])}")
else:
    errors.append("ccd dir missing")

enc = root / "panel" / "enroll-secrets.enc"
print(f"enroll-vault {'present' if enc.is_file() else 'missing'}")

meta = root / "meta" / "result.txt"
if errors:
    meta.write_text("FAIL\n" + "\n".join(errors) + "\n")
    print("FAIL")
    for e in errors:
        print(" ", e)
    sys.exit(1)
meta.write_text("ok\n")
print(f"restore-drill OK (scratch={root})")
PY
