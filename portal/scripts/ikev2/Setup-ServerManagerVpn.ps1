# ServerManager — add Windows built-in IKEv2 VPN
# Run in PowerShell (Admin not required for Add-VpnConnection).
param(
  [string]$Server = "portal.vpstruelord.com",
  [string]$Name = "ServerManager IKEv2",
  [string]$Username = "windows"
)

$ErrorActionPreference = "Stop"
Write-Host "Creating Windows VPN profile '$Name' → $Server (IKEv2)..."

# Remove existing profile with same name
Get-VpnConnection -Name $Name -ErrorAction SilentlyContinue | Remove-VpnConnection -Force -ErrorAction SilentlyContinue

Add-VpnConnection `
  -Name $Name `
  -ServerAddress $Server `
  -TunnelType Ikev2 `
  -AuthenticationMethod Eap `
  -EncryptionLevel Required `
  -RememberCredential `
  -Force

# Prefer modern ciphers (Windows default is often too weak for strongSwan)
Set-VpnConnectionIPsecConfiguration `
  -ConnectionName $Name `
  -AuthenticationTransformConstants SHA256128 `
  -CipherTransformConstants AES256 `
  -DHGroup Group14 `
  -EncryptionMethod AES256 `
  -IntegrityCheckMethod SHA256 `
  -PfsGroup PFS2048 `
  -Force

Write-Host ""
Write-Host "Done. Connect from:"
Write-Host "  Settings → Network & internet → VPN → $Name"
Write-Host "  Username: $Username"
Write-Host "  Password: (from ServerManager portal → Windows VPN)"
Write-Host ""
Write-Host "Or: rasdial `"$Name`" $Username <password>"
