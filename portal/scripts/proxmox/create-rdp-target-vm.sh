#!/usr/bin/env bash
# Create Windows 11 VM 102 (RDP target) for win11-pro-gpu (VM 100) to Remote Desktop into.
# Run on Proxmox host as root.
set -euo pipefail

VMID="${RDP_VMID:-102}"
NAME="${RDP_VM_NAME:-win11-rdp}"
MEM_MB="${RDP_MEM_MB:-8192}"
CORES="${RDP_CORES:-4}"
DISK_GB="${RDP_DISK_GB:-80}"
BRIDGE="${RDP_BRIDGE:-vmbr0}"
STORAGE="${RDP_STORAGE:-local-lvm}"
WIN_ISO="${RDP_WIN_ISO:-local:iso/Win11_25H2_English_x64_v2.iso}"
VIRTIO_ISO="${RDP_VIRTIO_ISO:-local:iso/virtio-win.iso}"
ADMIN_USER="${RDP_ADMIN_USER:-Admin}"
ADMIN_PASS="${RDP_ADMIN_PASS:-RdpTarget2026!}"
COMPUTER_NAME="${RDP_COMPUTER_NAME:-WIN11-RDP}"

if qm status "$VMID" &>/dev/null; then
  if [[ "${FORCE_RECREATE:-0}" == "1" ]]; then
    echo "FORCE_RECREATE=1 — destroying VM $VMID"
    qm stop "$VMID" --timeout 30 2>/dev/null || qm stop "$VMID" --skiplock 2>/dev/null || true
    sleep 2
    qm destroy "$VMID" --purge 1 --destroy-unreferenced-disks 1
  else
    echo "VM $VMID already exists:"
    qm config "$VMID"
    exit 0
  fi
fi

WORK="$(mktemp -d /tmp/rdp-vm-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# Minimal Autounattend for UEFI Windows 11 + RDP enable on first logon
cat >"$WORK/Autounattend.xml" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE"
      processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35"
      language="neutral" versionScope="nonSxS"
      xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <SetupUILanguage><UILanguage>en-US</UILanguage></SetupUILanguage>
      <InputLocale>en-US</InputLocale>
      <SystemLocale>en-US</SystemLocale>
      <UILanguage>en-US</UILanguage>
      <UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Setup"
      processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35"
      language="neutral" versionScope="nonSxS"
      xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <DiskConfiguration>
        <Disk wcm:action="add">
          <DiskID>0</DiskID>
          <WillWipeDisk>true</WillWipeDisk>
          <CreatePartitions>
            <CreatePartition wcm:action="add">
              <Order>1</Order><Type>EFI</Type><Size>100</Size>
            </CreatePartition>
            <CreatePartition wcm:action="add">
              <Order>2</Order><Type>MSR</Type><Size>16</Size>
            </CreatePartition>
            <CreatePartition wcm:action="add">
              <Order>3</Order><Type>Primary</Type><Extend>true</Extend>
            </CreatePartition>
          </CreatePartitions>
          <ModifyPartitions>
            <ModifyPartition wcm:action="add">
              <Order>1</Order><PartitionID>1</PartitionID><Format>FAT32</Format><Label>System</Label>
            </ModifyPartition>
            <ModifyPartition wcm:action="add">
              <Order>2</Order><PartitionID>2</PartitionID>
            </ModifyPartition>
            <ModifyPartition wcm:action="add">
              <Order>3</Order><PartitionID>3</PartitionID><Format>NTFS</Format><Label>Windows</Label><Letter>C</Letter>
            </ModifyPartition>
          </ModifyPartitions>
        </Disk>
      </DiskConfiguration>
      <ImageInstall>
        <OSImage>
          <InstallTo><DiskID>0</DiskID><PartitionID>3</PartitionID></InstallTo>
          <InstallFrom>
            <MetaData wcm:action="add">
              <Key>/IMAGE/NAME</Key>
              <Value>Windows 11 Pro</Value>
            </MetaData>
          </InstallFrom>
        </OSImage>
      </ImageInstall>
      <UserData>
        <AcceptEula>true</AcceptEula>
        <FullName>${ADMIN_USER}</FullName>
        <Organization>Home</Organization>
        <!-- Generic Win11 Pro key (install only; not a license) -->
        <ProductKey>
          <Key>VK7JG-NPHTM-C97JM-9MPGT-3V66T</Key>
          <WillShowUI>OnError</WillShowUI>
        </ProductKey>
      </UserData>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup"
      processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35"
      language="neutral" versionScope="nonSxS"
      xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <ComputerName>${COMPUTER_NAME}</ComputerName>
      <TimeZone>Eastern Standard Time</TimeZone>
    </component>
    <component name="Microsoft-Windows-TerminalServices-LocalSessionManager"
      processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35"
      language="neutral" versionScope="nonSxS"
      xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <fDenyTSConnections>false</fDenyTSConnections>
    </component>
    <component name="Microsoft-Windows-TerminalServices-RDP-WinStationExtensions"
      processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35"
      language="neutral" versionScope="nonSxS"
      xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <UserAuthentication>0</UserAuthentication>
    </component>
    <component name="Networking-MPSSVC-Svc"
      processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35"
      language="neutral" versionScope="nonSxS"
      xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <FirewallGroups>
        <FirewallGroup wcm:action="add" wcm:keyValue="RemoteDesktop">
          <Active>true</Active>
          <Group>@FirewallAPI.dll,-28752</Group>
          <Profile>all</Profile>
        </FirewallGroup>
      </FirewallGroups>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup"
      processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35"
      language="neutral" versionScope="nonSxS"
      xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
        <ProtectYourPC>3</ProtectYourPC>
        <SkipMachineOOBE>true</SkipMachineOOBE>
        <SkipUserOOBE>true</SkipUserOOBE>
      </OOBE>
      <UserAccounts>
        <LocalAccounts>
          <LocalAccount wcm:action="add">
            <Name>${ADMIN_USER}</Name>
            <Group>Administrators</Group>
            <Password>
              <Value>${ADMIN_PASS}</Value>
              <PlainText>true</PlainText>
            </Password>
          </LocalAccount>
        </LocalAccounts>
      </UserAccounts>
      <AutoLogon>
        <Enabled>true</Enabled>
        <Username>${ADMIN_USER}</Username>
        <Password>
          <Value>${ADMIN_PASS}</Value>
          <PlainText>true</PlainText>
        </Password>
        <LogonCount>1</LogonCount>
      </AutoLogon>
      <FirstLogonCommands>
        <SynchronousCommand wcm:action="add">
          <Order>1</Order>
          <CommandLine>cmd /c reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f</CommandLine>
        </SynchronousCommand>
        <SynchronousCommand wcm:action="add">
          <Order>2</Order>
          <CommandLine>cmd /c netsh advfirewall firewall set rule group="remote desktop" new enable=Yes</CommandLine>
        </SynchronousCommand>
        <SynchronousCommand wcm:action="add">
          <Order>3</Order>
          <CommandLine>cmd /c powercfg /change standby-timeout-ac 0 &amp; powercfg /change monitor-timeout-ac 0</CommandLine>
        </SynchronousCommand>
      </FirstLogonCommands>
    </component>
  </settings>
</unattend>
EOF

# Build ISO + small FAT disk image with Autounattend.xml.
# Windows Setup reliably finds Autounattend on fixed disks; CD-only is flaky on q35.
if command -v genisoimage >/dev/null 2>&1; then
  genisoimage -J -r -V "AUTOUNATTEND" -o "$WORK/autounattend.iso" "$WORK/Autounattend.xml"
elif command -v mkisofs >/dev/null 2>&1; then
  mkisofs -J -r -V "AUTOUNATTEND" -o "$WORK/autounattend.iso" "$WORK/Autounattend.xml"
else
  apt-get update -qq
  apt-get install -y -qq genisoimage
  genisoimage -J -r -V "AUTOUNATTEND" -o "$WORK/autounattend.iso" "$WORK/Autounattend.xml"
fi

AA_IMG=/var/lib/vz/template/iso/autounattend-rdp.img
dd if=/dev/zero of="$WORK/autounattend.img" bs=1M count=32 status=none
mkfs.vfat -n UNATTEND "$WORK/autounattend.img"
MNT="$WORK/mnt"
mkdir -p "$MNT"
mount -o loop "$WORK/autounattend.img" "$MNT"
cp -f "$WORK/Autounattend.xml" "$MNT/Autounattend.xml"
umount "$MNT"

install -d -m 755 /var/lib/vz/template/iso
install -m 644 "$WORK/autounattend.iso" /var/lib/vz/template/iso/autounattend-rdp.iso
install -m 644 "$WORK/autounattend.img" "$AA_IMG"
install -m 644 "$WORK/Autounattend.xml" /var/lib/vz/template/iso/Autounattend-rdp.xml

echo "=== creating VM ${VMID} (${NAME}) ==="
qm create "$VMID" \
  --name "$NAME" \
  --machine q35 \
  --bios ovmf \
  --ostype win11 \
  --cpu host \
  --cores "$CORES" \
  --sockets 1 \
  --memory "$MEM_MB" \
  --balloon 0 \
  --net0 e1000e,bridge="$BRIDGE",firewall=0 \
  --agent enabled=1 \
  --onboot 0 \
  --tablet 1 \
  --args '-device usb-mouse,id=fakemouse,bus=ehci.0'

qm set "$VMID" --efidisk0 "${STORAGE}:1,efitype=4m,pre-enrolled-keys=0"
qm set "$VMID" --tpmstate0 "${STORAGE}:1,version=v2.0"
# SATA system disk (not VirtIO) so Autounattend works without WinPE driver injection
qm set "$VMID" --sata0 "${STORAGE}:${DISK_GB},discard=on,ssd=1"
# FAT answer-file disk as sata1 — Setup scans fixed volumes for Autounattend.xml
qm importdisk "$VMID" "$AA_IMG" "$STORAGE" --format raw
AA_UNUSED="$(qm config "$VMID" | awk -F': ' '/^unused[0-9]+:/ {print $2; exit}')"
test -n "$AA_UNUSED"
qm set "$VMID" --sata1 "${AA_UNUSED}"
qm set "$VMID" --ide2 "${WIN_ISO},media=cdrom"
qm set "$VMID" --ide3 "local:iso/virtio-win.iso,media=cdrom"
qm set "$VMID" --ide0 "local:iso/autounattend-rdp.iso,media=cdrom"
qm set "$VMID" --boot "order=ide2;sata0"
qm set "$VMID" --vga std

echo "=== VM config ==="
qm config "$VMID"
echo "=== starting installer ==="
qm start "$VMID"

# Windows ISO shows "Press any key to boot from CD or DVD...." — send keys
# during the prompt window so unattended setup actually starts.
(
  sleep 4
  for _ in $(seq 1 90); do
    qm sendkey "$VMID" ret 2>/dev/null || true
    sleep 0.35
    qm sendkey "$VMID" spc 2>/dev/null || true
    sleep 0.35
  done
) >/tmp/rdp-vm-${VMID}-sendkeys.log 2>&1 &
echo "SENDKEYS_PID=$!"

echo "STARTED_VM_${VMID}"
echo "Admin user: ${ADMIN_USER}"
echo "Admin pass: ${ADMIN_PASS}"
echo "Connect from VM 100 (James-Gaming-PC / 192.168.8.163) via mstsc to this VM once DHCP assigns an IP."
