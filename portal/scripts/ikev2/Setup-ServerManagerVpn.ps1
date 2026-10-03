# ServerManager - Windows built-in IKEv2 VPN setup
# Run in elevated PowerShell (Run as administrator) OR use the .cmd launcher.
param(
  [string]$Server = "portal.vpstruelord.com",
  [string]$Name = "ServerManager IKEv2",
  [string]$Username = "windows"
)

$ErrorActionPreference = "Stop"
Write-Host "Creating Windows VPN profile '$Name' -> $Server (IKEv2)..."

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
  Write-Host "ERROR: Right-click PowerShell -> Run as administrator, then re-run this script." -ForegroundColor Red
  exit 1
}

# NAT-T fix (common on home Wi-Fi / school networks)
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PolicyAgent" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\PolicyAgent" -Name "AssumeUDPEncapsulationContextOnSendRule" -Type DWord -Value 2 -Force
# Allow modern DH for IKEv2
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters" -Name "NegotiateDH2048_AES256" -Type DWord -Value 1 -Force

Get-VpnConnection -Name $Name -ErrorAction SilentlyContinue | Remove-VpnConnection -Force -ErrorAction SilentlyContinue
Get-VpnConnection -Name $Name -AllUserConnection -ErrorAction SilentlyContinue | Remove-VpnConnection -Force -AllUserConnection -ErrorAction SilentlyContinue

Add-VpnConnection `
  -Name $Name `
  -ServerAddress $Server `
  -TunnelType Ikev2 `
  -AuthenticationMethod Eap `
  -EncryptionLevel Required `
  -RememberCredential `
  -AllUserConnection `
  -Force

Set-VpnConnectionIPsecConfiguration `
  -ConnectionName $Name `
  -AuthenticationTransformConstants SHA256128 `
  -CipherTransformConstants AES256 `
  -DHGroup Group14 `
  -EncryptionMethod AES256 `
  -IntegrityCheckMethod SHA256 `
  -PfsGroup None `
  -AllUserConnection `
  -Force

# Prefer VPN DNS so AdGuard can rewrite portal/admin → 10.9.0.1 (on-tunnel).
# Edge/Chrome DoH can still bypass this; the server also allows active IKEv2
# peer WAN IPs while the tunnel is up.
try {
  Set-VpnConnection -Name $Name -AllUserConnection -DnsSuffix "vpstruelord.com" -Force -ErrorAction Stop
} catch {
  Write-Host "Note: could not set VpnConnection DnsSuffix ($($_.Exception.Message))"
}

Write-Host ""
Write-Host "Done. Connect from Settings -> Network & internet -> VPN -> $Name"
Write-Host "  Username: $Username"
Write-Host "  Password: (Portal -> Windows VPN)"
Write-Host "Server uses a public Let's Encrypt RSA certificate (no extra CA install)."
Write-Host ""
Write-Host "If portal shows Forbidden while VPN is connected:"
Write-Host "  1) Disconnect/reconnect the VPN"
Write-Host "  2) In elevated CMD: ipconfig /flushdns"
Write-Host "  3) Disable Secure DNS / DoH in the browser (Edge/Chrome) for this test"
Write-Host "  4) Or open https://10.9.0.1 and accept the cert name mismatch"
Write-Host "Press Enter to close..."
[void][System.Console]::ReadLine()
