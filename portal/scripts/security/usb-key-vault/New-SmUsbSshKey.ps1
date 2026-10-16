#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Generate an ed25519 SSH key pair inside the mounted ServerManager USB key vault.

.DESCRIPTION
  Writes id_ed25519 (+ .pub) under <vault>:\ssh\. Never copies the private key
  off the vault. Print the public key so you can paste it into the portal.
#>
[CmdletBinding()]
param(
  [string]$Comment = "servermanager-usb-vault",

  [ValidatePattern('^[A-Za-z]$')]
  [string]$VaultDriveLetter,

  [string]$KeyFileName = "id_ed25519",

  [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script in an elevated PowerShell (Run as administrator)."
  }
}

function Find-VaultSshDir {
  param([string]$Letter)
  if ($Letter) {
    $ssh = Join-Path ("{0}:\" -f $Letter.ToUpperInvariant()) "ssh"
    if (Test-Path $ssh) { return $ssh }
    throw "No ssh\ folder on ${Letter}: — mount the vault first (Mount-SmUsbKeyVault.ps1)."
  }

  $statePath = Join-Path $env:LOCALAPPDATA "ServerManagerKeyVault\last-mount.json"
  if (Test-Path $statePath) {
    $st = Get-Content $statePath -Raw | ConvertFrom-Json
    if ($st.mount_letter) {
      $ssh = Join-Path ("{0}:\" -f $st.mount_letter) "ssh"
      if (Test-Path $ssh) { return $ssh }
    }
  }

  $hits = @()
  Get-Volume | Where-Object {
    $_.DriveLetter -and $_.FileSystemLabel -eq 'SM-Keys'
  } | ForEach-Object {
    $ssh = Join-Path ("{0}:\" -f $_.DriveLetter) "ssh"
    if (Test-Path $ssh) { $hits += $ssh }
  }
  if ($hits.Count -eq 1) { return $hits[0] }
  if ($hits.Count -eq 0) {
    throw "Vault not mounted. Run Mount-SmUsbKeyVault.ps1 (or leave New-SmUsbKeyVault.ps1 mounted), then retry."
  }
  Write-Host "Multiple SM-Keys volumes:" -ForegroundColor Cyan
  for ($i = 0; $i -lt $hits.Count; $i++) { Write-Host ("  [{0}] {1}" -f ($i + 1), $hits[$i]) }
  $pick = [int](Read-Host "Select vault ssh folder number") - 1
  if ($pick -lt 0 -or $pick -ge $hits.Count) { throw "Invalid selection" }
  return $hits[$pick]
}

Assert-Admin

if (-not (Get-Command ssh-keygen -ErrorAction SilentlyContinue)) {
  throw "ssh-keygen not found. Install OpenSSH Client (Windows Optional Features)."
}

$sshDir = Find-VaultSshDir -Letter $VaultDriveLetter
$keyPath = Join-Path $sshDir $KeyFileName
$pubPath = "$keyPath.pub"

if ((Test-Path $keyPath) -and -not $Force) {
  throw "Private key already exists: $keyPath`nPass -Force to overwrite, or use a different -KeyFileName."
}

Write-Host "Generating ed25519 key in $keyPath ..." -ForegroundColor Cyan
Write-Host "You will be prompted for a key passphrase (recommended)." -ForegroundColor Yellow

# -N empty would allow no passphrase; interactive prompt is safer — use ssh-keygen without -N
# so the user sets a passphrase. Overwrite handled via -Force after our check.
if (Test-Path $keyPath) { Remove-Item $keyPath, $pubPath -Force -ErrorAction SilentlyContinue }

& ssh-keygen -t ed25519 -f $keyPath -C $Comment
if ($LASTEXITCODE -ne 0) { throw "ssh-keygen failed." }

# Restrict ACLs: current user + SYSTEM only (best-effort on NTFS vault)
try {
  icacls $keyPath /inheritance:r /grant:r "${env:USERNAME}:(R)" "SYSTEM:(F)" | Out-Null
} catch {
  Write-Warning "Could not tighten ACLs on private key (non-fatal)."
}

Write-Host ""
Write-Host "Key pair created." -ForegroundColor Green
Write-Host "  Private : $keyPath  (keep only on this vault — never copy off)"
Write-Host "  Public  : $pubPath"
Write-Host ""
Write-Host "Public key (paste into portal Security → VPS SSH keys):" -ForegroundColor Cyan
Get-Content $pubPath -Raw
Write-Host ""
Write-Host "When finished: .\Dismount-SmUsbKeyVault.ps1"
Write-Host "To use later:  .\Mount-SmUsbKeyVault.ps1 -AddToSshAgent"
