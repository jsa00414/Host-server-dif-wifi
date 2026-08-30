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

$ErrorActionPreference = "Continue"
$DriveLetter = ($DriveLetter -replace '[^A-Za-z]', '').Substring(0, 1).ToUpper()

Write-Host "ServerManager NAS -> ${DriveLetter}: ($Label)"
Write-Host "Host: $NasHost  Share: $Share  User: $Username"
Write-Host ""

if (-not $Password) {
  Write-Host "ERROR: No password in script. Download again from the portal while logged in." -ForegroundColor Red
  Read-Host "Press Enter to close"
  exit 3
}

if (-not (Test-Connection -ComputerName $NasHost -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
  Write-Host "WARNING: Ping to $NasHost failed (ICMP may be blocked). Trying SMB anyway..." -ForegroundColor Yellow
}

$shareCandidates = @($Share, "share") | Where-Object { $_ } | Select-Object -Unique
$secure = ConvertTo-SecureString $Password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($Username, $secure)

try { net use "${DriveLetter}:" /delete /y 2>$null | Out-Null } catch {}
try { Remove-PSDrive -Name $DriveLetter -Force -ErrorAction SilentlyContinue } catch {}

$mapped = $false
$unc = ""

foreach ($candidate in $shareCandidates) {
  $tryUnc = "\\$NasHost\$candidate"
  Write-Host "Trying $tryUnc ..."

  try {
    $null = New-PSDrive -Name $DriveLetter -PSProvider FileSystem -Root $tryUnc -Credential $cred -Persist -ErrorAction Stop
    $mapped = $true
    $unc = $tryUnc
    break
  } catch {
    Write-Host "  New-PSDrive failed: $($_.Exception.Message)"
  }

  cmdkey /delete:$NasHost 2>$null | Out-Null
  $null = cmdkey /add:$NasHost /user:$Username /pass:$Password
  net use "${DriveLetter}:" /delete /y 2>$null | Out-Null
  # Password must come before /user: for net.exe
  $out = net use "${DriveLetter}:" $tryUnc $Password /user:$Username /persistent:yes 2>&1
  if ($LASTEXITCODE -eq 0) {
    $mapped = $true
    $unc = $tryUnc
    break
  }
  Write-Host "  net use failed: $out"
}

if (-not $mapped) {
  Write-Host ""
  Write-Host "ERROR: Could not map any SMB share on $NasHost" -ForegroundColor Red
  Write-Host "Connect to home VPN first (OpenVPN, WireGuard, or Windows IKEv2), then run again." -ForegroundColor Yellow
  Write-Host "Tried: $($shareCandidates -join ', ')" -ForegroundColor Yellow
  Write-Host ""
  Read-Host "Press Enter to close"
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
Read-Host "Press Enter to close"
