#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Unload SSH keys from the agent and dismount the ServerManager USB VHDX key vault.

.DESCRIPTION
  Clears ssh-agent identities (optional), locks BitLocker if present, and
  dismounts the VHDX so private keys are no longer accessible on the PC.
#>
[CmdletBinding()]
param(
  [ValidatePattern('^[A-Za-z]$')]
  [string]$UsbDriveLetter,

  [string]$VaultFolderName = "ServerManagerKeyVault",
  [string]$VhdFileName = "ServerManagerKeys.vhdx",

  [switch]$KeepAgentKeys
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
  if ($hits.Count -eq 0) {
    # Fall back to last-mount state (USB may still be present but volume enumeration failed)
    $statePath = Join-Path $env:LOCALAPPDATA "ServerManagerKeyVault\last-mount.json"
    if (Test-Path $statePath) {
      $st = Get-Content $statePath -Raw | ConvertFrom-Json
      if ($st.vhd_path -and (Test-Path $st.vhd_path)) { return [string]$st.vhd_path }
    }
    throw "No USB vault VHDX found. Plug in the USB or pass -UsbDriveLetter."
  }
  Write-Host "Multiple vaults found:" -ForegroundColor Cyan
  for ($i = 0; $i -lt $hits.Count; $i++) { Write-Host ("  [{0}] {1}" -f ($i + 1), $hits[$i]) }
  $pick = [int](Read-Host "Select vault number") - 1
  if ($pick -lt 0 -or $pick -ge $hits.Count) { throw "Invalid selection" }
  return $hits[$pick]
}

Assert-Admin

if (-not $KeepAgentKeys) {
  if (Get-Command ssh-add -ErrorAction SilentlyContinue) {
    Write-Host "Clearing ssh-agent identities..." -ForegroundColor Yellow
    & ssh-add -D 2>$null
  }
}

$vhdPath = $null
$statePath = Join-Path $env:LOCALAPPDATA "ServerManagerKeyVault\last-mount.json"
if (Test-Path $statePath) {
  $st = Get-Content $statePath -Raw | ConvertFrom-Json
  if ($st.vhd_path) { $vhdPath = [string]$st.vhd_path }
}

if (-not $vhdPath -or -not (Test-Path $vhdPath)) {
  $vhdPath = Find-VaultVhd -Letter $UsbDriveLetter -Folder $VaultFolderName -File $VhdFileName
}

$vhd = Get-VHD -Path $vhdPath -ErrorAction SilentlyContinue
if (-not $vhd -or -not $vhd.Attached) {
  Write-Host "Vault already dismounted: $vhdPath" -ForegroundColor Green
  if (Test-Path $statePath) { Remove-Item $statePath -Force -ErrorAction SilentlyContinue }
  return
}

$disk = Get-Disk | Where-Object { $_.Location -eq $vhdPath -or $_.Path -like "*$([IO.Path]::GetFileName($vhdPath))*" } | Select-Object -First 1
if (-not $disk) {
  # Prefer partition lookup via Mount-VHD disk number
  try {
    $attached = Get-Disk | Where-Object {
      try {
        $parts = Get-Partition -DiskNumber $_.Number -ErrorAction SilentlyContinue
        $null -ne $parts
      } catch { $false }
    }
    foreach ($d in $attached) {
      $vol = Get-Partition -DiskNumber $d.Number -ErrorAction SilentlyContinue |
        Where-Object { $_.DriveLetter } |
        ForEach-Object { Get-Volume -DriveLetter $_.DriveLetter -ErrorAction SilentlyContinue } |
        Where-Object { $_.FileSystemLabel -eq 'SM-Keys' } |
        Select-Object -First 1
      if ($vol) { $disk = $d; break }
    }
  } catch {}
}

if ($disk) {
  $parts = Get-Partition -DiskNumber $disk.Number | Where-Object { $_.DriveLetter }
  foreach ($part in $parts) {
    $mount = "{0}:" -f $part.DriveLetter
    $bl = Get-BitLockerVolume -MountPoint $mount -ErrorAction SilentlyContinue
    if ($bl -and $bl.LockStatus -eq 'Unlocked' -and $bl.ProtectionStatus -eq 'On') {
      Write-Host "Locking BitLocker on $mount ..." -ForegroundColor Yellow
      try { Lock-BitLocker -MountPoint $mount -ForceDismount -ErrorAction SilentlyContinue | Out-Null } catch {}
    }
  }
}

Write-Host "Dismounting $vhdPath ..." -ForegroundColor Cyan
Dismount-VHD -Path $vhdPath
if (Test-Path $statePath) { Remove-Item $statePath -Force -ErrorAction SilentlyContinue }

Write-Host "Vault dismounted. Private keys are no longer accessible until you mount again." -ForegroundColor Green
