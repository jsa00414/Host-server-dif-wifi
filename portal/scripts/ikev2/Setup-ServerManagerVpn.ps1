# ServerManager — add Windows built-in IKEv2 VPN
# Run in elevated PowerShell (Run as administrator).
param(
  [string]$Server = "portal.vpstruelord.com",
  [string]$Name = "ServerManager IKEv2",
  [string]$Username = "windows"
)

$ErrorActionPreference = "Stop"
Write-Host "Creating Windows VPN profile '$Name' → $Server (IKEv2)..."

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
  Write-Host "ERROR: Right-click PowerShell → Run as administrator, then re-run this script." -ForegroundColor Red
  exit 1
}

# @@CA_CERT_PEM@@ is replaced by the portal when downloading this script.
$CaPem = @"
@@CA_CERT_PEM@@
"@

if ($CaPem -match "BEGIN CERTIFICATE") {
  $caPath = Join-Path $env:TEMP "ServerManager-IKEv2-CA.crt"
  Set-Content -Path $caPath -Value $CaPem.Trim() -Encoding ASCII
  Import-Certificate -FilePath $caPath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
  Write-Host "Installed ServerManager IKEv2 CA into Trusted Root."
} else {
  Write-Host "WARNING: CA not embedded — download from Portal → Windows VPN if connect fails." -ForegroundColor Yellow
}

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

Write-Host ""
Write-Host "Done. Connect from Settings → Network & internet → VPN → $Name"
Write-Host "  Username: $Username"
Write-Host "  Password: (Portal → Windows VPN)"
