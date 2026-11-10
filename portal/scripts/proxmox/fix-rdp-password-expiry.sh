#!/usr/bin/env bash
# Clear Windows "password expired" on win11-rdp (VM 102) and keep the same password.
# Run on the Proxmox host as root. Stops the VM briefly, patches SAM + one-shot AutoLogon.
set -euo pipefail

VMID="${VMID:-102}"
USER_NAME="${RDP_ADMIN_USER:-Admin}"
ADMIN_PASS="${RDP_ADMIN_PASS:-RdpTarget2026!}"
MNT="${MNT:-/mnt/win102-pwd}"
LV="${LV:-/dev/pve/vm-${VMID}-disk-2}"

command -v ntfs-3g >/dev/null || apt-get install -y -qq ntfs-3g
command -v chntpw >/dev/null || apt-get install -y -qq chntpw
python3 -c 'import hivex' 2>/dev/null || apt-get install -y -qq python3-hivex

st=$(qm status "$VMID" | awk '{print $2}')
if [[ "$st" != "stopped" ]]; then
  echo "Stopping VM $VMID…"
  qm shutdown "$VMID" --timeout 60 || qm stop "$VMID" --timeout 90 || true
  sleep 2
fi
[[ -e "$LV" ]] || { echo "missing $LV"; exit 1; }

umount -l "$MNT" 2>/dev/null || true
losetup -D 2>/dev/null || true
sleep 1
LOOP=$(losetup -f --show -P "$LV")
mkdir -p "$MNT"
ntfs-3g -o rw,remove_hiberfile "${LOOP}p3" "$MNT"

SAM="$MNT/Windows/System32/config/SAM"
SOFT="$MNT/Windows/System32/config/SOFTWARE"
cp -a "$SAM" "$SAM.bak.$(date +%s)"
cp -a "$SOFT" "$SOFT.bak.$(date +%s)"

USER_NAME="$USER_NAME" ADMIN_PASS="$ADMIN_PASS" python3 - <<'PY'
import hivex, os
user = os.environ["USER_NAME"]
passwd = os.environ["ADMIN_PASS"]
sam_path = "/mnt/win102-pwd/Windows/System32/config/SAM"
soft_path = "/mnt/win102-pwd/Windows/System32/config/SOFTWARE"

h = hivex.Hivex(sam_path, write=True)
root = h.root()

def child(node, name):
    for c in h.node_children(node):
        if h.node_name(c).lower() == name.lower():
            return c
    raise KeyError(name)

# Resolve Admin RID from Names key, fall back to 000003E8.
names = child(child(child(child(root, "SAM"), "Domains"), "Account"), "Users")
rid_key = "000003E8"
users = names
names_idx = child(users, "Names")
for c in h.node_children(names_idx):
    if h.node_name(c).lower() == user.lower():
        # Default value type encodes RID
        for vid in h.node_values(c):
            if h.value_key(vid) == "":
                t, data = h.value_value(vid)
                if len(data) >= 4:
                    rid = int.from_bytes(data[:4], "little")
                    rid_key = f"{rid:08X}"
                break
        break

n = child(users, rid_key)
f_type = None
f_val = None
for vid in h.node_values(n):
    if h.value_key(vid) == "F":
        f_type, data = h.value_value(vid)
        f_val = bytearray(data)
        break
if f_val is None:
    raise SystemExit("SAM F value missing")

def u16(off):
    return int.from_bytes(f_val[off:off + 2], "little")

ACB_NORMAL = 0x0010
ACB_PWNOEXP = 0x0200
acb_off = 0x38
for off in (0x38, 0x30, 0x34, 0x36, 0x3c):
    if off + 2 <= len(f_val) and (u16(off) & ACB_NORMAL):
        acb_off = off
        break
acb = u16(acb_off) | ACB_NORMAL | ACB_PWNOEXP
f_val[acb_off:acb_off + 2] = acb.to_bytes(2, "little")
h.node_set_value(n, {"key": "F", "t": f_type, "value": bytes(f_val)})
h.commit(sam_path)
print(f"SAM {user} rid={rid_key} acb={acb:#06x} (password never expires)")

hs = hivex.Hivex(soft_path, write=True)
root = hs.root()

def ensure(node, parts):
    for part in parts:
        found = None
        for c in hs.node_children(node):
            if hs.node_name(c).lower() == part.lower():
                found = c
                break
        if found is None:
            found = hs.node_add_child(node, part)
        node = found
    return node

runonce = ensure(root, ["Microsoft", "Windows", "CurrentVersion", "RunOnce"])
cmd = r"cmd.exe /c C:\Windows\Setup\Scripts\FixPwdExpiry.cmd"
hs.node_set_value(
    runonce,
    {"key": "SM_FixPwdExpiry", "t": 1, "value": (cmd + "\x00").encode("utf-16le")},
)
winlogon = ensure(root, ["Microsoft", "Windows NT", "CurrentVersion", "Winlogon"])
for k, v in [
    ("AutoAdminLogon", "1"),
    ("DefaultUserName", user),
    ("DefaultPassword", passwd),
    ("AutoLogonCount", "1"),
]:
    hs.node_set_value(
        winlogon, {"key": k, "t": 1, "value": (v + "\x00").encode("utf-16le")}
    )
hs.commit(soft_path)
print("SOFTWARE RunOnce + one-shot AutoAdminLogon set")
PY

mkdir -p "$MNT/Windows/Setup/Scripts"
python3 - <<PY
from pathlib import Path
user = "${USER_NAME}"
passwd = "${ADMIN_PASS}"
content = f"""@echo off
net user {user} {passwd} >C:\\Windows\\Setup\\Scripts\\fixpwd.log 2>&1
net user {user} /logonpasswordchg:no >>C:\\Windows\\Setup\\Scripts\\fixpwd.log 2>&1
net accounts /maxpwage:unlimited >>C:\\Windows\\Setup\\Scripts\\fixpwd.log 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-LocalUser -Name '{user}' -PasswordNeverExpires \$true" >>C:\\Windows\\Setup\\Scripts\\fixpwd.log 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -Command "\$p=ConvertTo-SecureString '{passwd}' -AsPlainText -Force; Set-LocalUser -Name '{user}' -Password \$p -PasswordNeverExpires \$true" >>C:\\Windows\\Setup\\Scripts\\fixpwd.log 2>&1
reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v AutoAdminLogon /t REG_SZ /d 0 /f >>C:\\Windows\\Setup\\Scripts\\fixpwd.log 2>&1
reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v DefaultPassword /f >>C:\\Windows\\Setup\\Scripts\\fixpwd.log 2>&1
reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" /v SM_FixPwdExpiry /f >>C:\\Windows\\Setup\\Scripts\\fixpwd.log 2>&1
"""
Path("/mnt/win102-pwd/Windows/Setup/Scripts/FixPwdExpiry.cmd").write_bytes(
    content.replace("\n", "\r\n").encode("ascii")
)
print("wrote FixPwdExpiry.cmd")
PY

printf 'q\n' | chntpw -u "$USER_NAME" "$SAM" 2>&1 | grep -E 'Account bits|Pwd don|Username' || true
sync
umount "$MNT"
losetup -d "$LOOP"
qm start "$VMID"
sleep 3
qm status "$VMID"
echo "DONE — reconnect RDP as ${USER_NAME} with the same password"
