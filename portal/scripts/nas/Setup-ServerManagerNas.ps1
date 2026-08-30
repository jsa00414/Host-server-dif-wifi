# ServerManager - Map Buffalo NAS in Windows File Explorer
# Run while connected to home VPN (OpenVPN / WireGuard / IKEv2).
param(
  [string]$NasHost = "192.168.8.159",
  [string]$Share = "share",
  [string]$Username = "admin",
  [string]$Password = '@@NAS_PASSWORD@@',
  [string]$DriveLetter = "Z",
  [string]$Label = "ServerManager NAS"
)

$ErrorActionPreference = "Stop"
$DriveLetter = ($DriveLetter -replace '[^A-Za-z]', '').Substring(0, 1).ToUpper()

Write-Host "ServerManager NAS -> ${DriveLetter}: ($Label)"
Write-Host "Host: $NasHost  Share: $Share  User: $Username"
Write-Host ""

if (-not (Test-Connection -ComputerName $NasHost -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
  Write-Host "ERROR: Cannot reach $NasHost" -ForegroundColor Red
  Write-Host "Connect to home VPN first (OpenVPN, WireGuard, or Windows IKEv2), then run this script again." -ForegroundColor Yellow
  exit 2
}

$shareCandidates = @($Share, "share", "disk1") | Where-Object { $_ } | Select-Object -Unique
$mapped = $false
$usedShare = ""
$unc = ""

foreach ($candidate in $shareCandidates) {
  $tryUnc = "\\$NasHost\$candidate"
  Write-Host "Trying $tryUnc ..."
  cmdkey /delete:$NasHost 2>$null | Out-Null
  $null = cmdkey /add:$NasHost /user:$Username /pass:$Password
  net use "${DriveLetter}:" /delete /y 2>$null | Out-Null
  $out = net use "${DriveLetter}:" $tryUnc /user:"$Username" "$Password" /persistent:yes 2>&1
  if ($LASTEXITCODE -eq 0) {
    $mapped = $true
    $usedShare = $candidate
    $unc = $tryUnc
    break
  }
  Write-Host "  failed: $out"
}

if (-not $mapped) {
  Write-Host "ERROR: Could not map any SMB share on $NasHost" -ForegroundColor Red
  Write-Host "Tried: $($shareCandidates -join ', ')" -ForegroundColor Yellow
  Write-Host "Check NAS SMB is enabled and the share name in Buffalo admin." -ForegroundColor Yellow
  exit 1
}

try {
  $shell = New-Object -ComObject Scripting.Shell
  $shell.NameSpace("${DriveLetter}:").Self.Name = $Label
} catch {
  # Label is cosmetic; ignore failures
}

Write-Host ""
Write-Host "Mapped ${DriveLetter}: -> $unc ($Label)" -ForegroundColor Green
Write-Host "Open File Explorer -> This PC -> ${DriveLetter}:"
Start-Process explorer.exe "${DriveLetter}:\"
