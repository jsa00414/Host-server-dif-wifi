#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Mount the ServerManager USB VHDX key vault and optionally load the SSH key into ssh-agent.
#>
[CmdletBinding()]
param(
  [ValidatePattern('^[A-Za-z]$')]
  [string]$UsbDriveLetter,

  [string]$VaultFolderName = "ServerManagerKeyVault",
  [string]$VhdFileName = "ServerManagerKeys.vhdx",

  [switch]$AddToSshAgent,

  [ValidateRange(1, 1440)]
  [int]$AgentLifetimeMinutes = 60
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

function Find-VaultVhd {
  param([string]$Letter, [string]$Folder, [string]$File)
  if ($Letter) {
    $path = Join-Path ("{0}:\{1}" -f $Letter.ToUpperInvariant(), $Folder) $File
    if (Test-Path $path) { return $path }
    throw "Vault not found at $path"
  }
  $hits = @()
  Get-Volume | Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Removable' } | ForEach-Object {
    $p = Join-Path ("{0}:\{1}" -f $_.DriveLetter, $Folder) $File
    if (Test-Path $p) { $hits += $p }
  }
  if ($hits.Count -eq 1) { return $hits[0] }
  if ($hits.Count -eq 0) { throw "No USB vault VHDX found. Plug in the USB created by New-SmUsbKeyVault.ps1." }
  Write-Host "Multiple vaults found:" -ForegroundColor Cyan
  for ($i = 0; $i -lt $hits.Count; $i++) { Write-Host ("  [{0}] {1}" -f ($i + 1), $hits[$i]) }
  $pick = [int](Read-Host "Select vault number") - 1
  if ($pick -lt 0 -or $pick -ge $hits.Count) { throw "Invalid selection" }
  return $hits[$pick]
}

Assert-Admin
$vhdPath = Find-VaultVhd -Letter $UsbDriveLetter -Folder $VaultFolderName -File $VhdFileName
Write-Host "Mounting $vhdPath ..." -ForegroundColor Cyan

# Unlock BitLocker after mount if needed.
$disk = Mount-VHD -Path $vhdPath -PassThru
$part = Get-Partition -DiskNumber $disk.Number | Where-Object { $_.DriveLetter } | Select-Object -First 1
if (-not $part) { throw "VHD mounted but no drive letter was assigned." }
$letter = $part.DriveLetter
$mount = "{0}:" -f $letter

$bl = Get-BitLockerVolume -MountPoint $mount -ErrorAction SilentlyContinue
if ($bl -and $bl.ProtectionStatus -eq 'On' -and $bl.VolumeStatus -ne 'FullyDecrypted' -and $bl.LockStatus -eq 'Locked') {
  $secure = Read-Host "BitLocker password for key vault $mount" -AsSecureString
  Unlock-BitLocker -MountPoint $mount -Password $secure | Out-Null
}

$sshDir = Join-Path $mount "ssh"
if (-not (Test-Path $sshDir)) {
  New-Item -ItemType Directory -Path $sshDir -Force | Out-Null
}

Write-Host "Vault mounted at $mount\ssh\" -ForegroundColor Green

if ($AddToSshAgent) {
  $key = Join-Path $sshDir "id_ed25519"
  if (-not (Test-Path $key)) {
    Write-Warning "No private key at $key — run New-SmUsbSshKey.ps1 first."
  } else {
    if (-not (Get-Command ssh-add -ErrorAction SilentlyContinue)) {
      throw "ssh-add not found. Install OpenSSH Client (Windows Optional Features)."
    }
    # Ensure agent is running
    $agent = Get-Service ssh-agent -ErrorAction SilentlyContinue
    if ($agent) {
      if ($agent.StartType -eq 'Disabled') { Set-Service ssh-agent -StartupType Manual }
      if ($agent.Status -ne 'Running') { Start-Service ssh-agent }
    }
    Write-Host "Loading key into ssh-agent for ~$AgentLifetimeMinutes minutes..." -ForegroundColor Yellow
    & ssh-add -t ($AgentLifetimeMinutes * 60) $key
    if ($LASTEXITCODE -ne 0) { throw "ssh-add failed (wrong passphrase or agent issue)." }
    Write-Host "Key loaded. Remember to dismount when finished." -ForegroundColor Green
  }
}

# Persist last mount letter for dismount helper
$stateDir = Join-Path $env:LOCALAPPDATA "ServerManagerKeyVault"
New-Item -ItemType Directory -Path $stateDir -Force | Out-Null
[ordered]@{
  vhd_path     = $vhdPath
  mount_letter = $letter
  mounted_at   = (Get-Date).ToString("o")
} | ConvertTo-Json | Set-Content -Path (Join-Path $stateDir "last-mount.json") -Encoding UTF8

Write-Output $mount
