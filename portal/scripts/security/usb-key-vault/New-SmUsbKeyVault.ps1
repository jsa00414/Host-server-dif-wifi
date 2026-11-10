#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Create a private ServerManager key vault (VHDX virtual drive) on a USB stick.

.DESCRIPTION
  Picks a removable USB drive (or -UsbDriveLetter), creates
  <USB>:\ServerManagerKeyVault\ServerManagerKeys.vhdx, initializes NTFS,
  optionally enables BitLocker, and writes vault-meta.json.

  This is encrypted removable storage — not a YubiKey/TPM. See README.md.
#>
[CmdletBinding()]
param(
  [ValidateRange(64, 8192)]
  [int]$SizeMB = 256,

  [ValidatePattern('^[A-Za-z]$')]
  [string]$UsbDriveLetter,

  [switch]$BitLocker,

  [string]$VaultFolderName = "ServerManagerKeyVault",
  [string]$VhdFileName = "ServerManagerKeys.vhdx"
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

function Get-RemovableUsbRoots {
  Get-Volume | Where-Object {
    $_.DriveLetter -and
    $_.DriveType -eq 'Removable' -and
    $_.Size -gt 0
  } | ForEach-Object {
    $letter = $_.DriveLetter
    [pscustomobject]@{
      Letter = $letter
      Root   = ("{0}:\" -f $letter)
      Label  = $_.FileSystemLabel
      FreeGB = [math]::Round(($_.SizeRemaining / 1GB), 2)
      SizeGB = [math]::Round(($_.Size / 1GB), 2)
    }
  }
}

Assert-Admin

$usb = $null
if ($UsbDriveLetter) {
  $want = $UsbDriveLetter.ToUpperInvariant()
  $usb = Get-RemovableUsbRoots | Where-Object { $_.Letter -eq $want } | Select-Object -First 1
  if (-not $usb) { throw "No removable USB volume found on drive $want`:" }
} else {
  $candidates = @(Get-RemovableUsbRoots)
  if ($candidates.Count -eq 0) {
    throw "No removable USB drive detected. Plug in the USB and try again."
  }
  if ($candidates.Count -eq 1) {
    $usb = $candidates[0]
  } else {
    Write-Host "Removable drives:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $candidates.Count; $i++) {
      $c = $candidates[$i]
      Write-Host ("  [{0}] {1}:  label={2}  free={3} GB / {4} GB" -f ($i + 1), $c.Letter, ($c.Label -or "(no label)"), $c.FreeGB, $c.SizeGB)
    }
    $pick = Read-Host "Select USB number"
    $idx = [int]$pick - 1
    if ($idx -lt 0 -or $idx -ge $candidates.Count) { throw "Invalid selection" }
    $usb = $candidates[$idx]
  }
}

Write-Host ("Using USB {0}: ({1})" -f $usb.Letter, ($usb.Label -or "no label")) -ForegroundColor Green

$vaultDir = Join-Path $usb.Root $VaultFolderName
$vhdPath = Join-Path $vaultDir $VhdFileName
$metaPath = Join-Path $vaultDir "vault-meta.json"

if (-not (Test-Path $vaultDir)) {
  New-Item -ItemType Directory -Path $vaultDir -Force | Out-Null
}

if (Test-Path $vhdPath) {
  throw "Vault image already exists: $vhdPath`nDismount/remove it first, or choose another USB."
}

$needBytes = [int64]$SizeMB * 1MB + 64MB
$vol = Get-Volume -DriveLetter $usb.Letter
if ($vol.SizeRemaining -lt $needBytes) {
  throw ("USB needs ~{0} MB free; only {1} MB remaining." -f ($SizeMB + 64), [int]($vol.SizeRemaining / 1MB))
}

Write-Host ("Creating {0} MB VHDX at {1} ..." -f $SizeMB, $vhdPath) -ForegroundColor Cyan
New-VHD -Path $vhdPath -SizeBytes ($SizeMB * 1MB) -Dynamic | Out-Null
$disk = Mount-VHD -Path $vhdPath -PassThru
try {
  Initialize-Disk -Number $disk.Number -PartitionStyle GPT -Confirm:$false
  $part = New-Partition -DiskNumber $disk.Number -UseMaximumSize -AssignDriveLetter
  $vaultLetter = $part.DriveLetter
  Format-Volume -DriveLetter $vaultLetter -FileSystem NTFS -NewFileSystemLabel "SM-Keys" -Confirm:$false | Out-Null

  $sshDir = Join-Path ("{0}:\" -f $vaultLetter) "ssh"
  New-Item -ItemType Directory -Path $sshDir -Force | Out-Null
  @(
    "ServerManager USB key vault",
    "Keep private keys in this volume only.",
    "Dismount the vault when finished so keys are not left unlocked.",
    "This is NOT a YubiKey — keys can be copied while the vault is unlocked."
  ) | Set-Content -Path (Join-Path $sshDir "README.txt") -Encoding UTF8

  if ($BitLocker) {
    Write-Host "Enabling BitLocker on vault volume $vaultLetter`: (set a strong password)..." -ForegroundColor Yellow
    $secure = Read-Host "BitLocker password for the key vault" -AsSecureString
    $secure2 = Read-Host "Confirm BitLocker password" -AsSecureString
    $bstr1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    $bstr2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure2)
    try {
      $p1 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr1)
      $p2 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr2)
      if ($p1 -ne $p2) { throw "BitLocker passwords do not match." }
      if ($p1.Length -lt 10) { throw "Use a BitLocker password of at least 10 characters." }
    } finally {
      [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr1)
      [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr2)
    }
    Enable-BitLocker -MountPoint ("{0}:" -f $vaultLetter) -PasswordProtector -Password $secure -UsedSpaceOnly -EncryptionMethod XtsAes256 | Out-Null
    Write-Host "BitLocker enabled on ${vaultLetter}:" -ForegroundColor Green
  }

  $meta = [ordered]@{
    created_at     = (Get-Date).ToString("o")
    usb_letter     = "$($usb.Letter):"
    vhd_path       = $vhdPath
    vault_label    = "SM-Keys"
    bitlocker      = [bool]$BitLocker
    size_mb        = $SizeMB
    purpose        = "ServerManager SSH private key vault (encrypted VHDX on USB)"
    not_yubikey    = $true
  }
  $meta | ConvertTo-Json -Depth 4 | Set-Content -Path $metaPath -Encoding UTF8

  Write-Host ""
  Write-Host "Vault ready." -ForegroundColor Green
  Write-Host "  USB folder : $vaultDir"
  Write-Host "  VHDX       : $vhdPath"
  Write-Host "  Mounted as : ${vaultLetter}:\ssh\"
  Write-Host ""
  Write-Host "Next:  .\New-SmUsbSshKey.ps1"
  Write-Host "Then:  copy the .pub into portal Security → SSH keys"
  Write-Host "Leave the vault mounted for key generation, then run Dismount-SmUsbKeyVault.ps1"
} catch {
  try { Dismount-VHD -Path $vhdPath -ErrorAction SilentlyContinue } catch {}
  throw
}
