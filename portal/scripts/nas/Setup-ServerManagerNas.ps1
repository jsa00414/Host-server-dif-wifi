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

function Write-Step($msg) { Write-Host $msg }
function Write-Warn($msg) { Write-Host $msg -ForegroundColor Yellow }
function Write-Err($msg) { Write-Host $msg -ForegroundColor Red }

function Test-TcpPort {
  param([string]$HostName, [int]$Port, [int]$TimeoutMs = 4000)
  try {
  $client = New-Object System.Net.Sockets.TcpClient
  $iar = $client.BeginConnect($HostName, $Port, $null, $null)
  $ok = $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
  if ($ok -and $client.Connected) {
    $client.EndConnect($iar) | Out-Null
    $client.Close()
    return $true
  }
  $client.Close()
  } catch {}
  return $false
}

function Get-VpnGateway {
  param([string]$Prefix)
  $addr = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -like "$Prefix*" -and $_.PrefixOrigin -ne 'WellKnown' } |
    Select-Object -First 1
  if (-not $addr) { return $null }
  $octets = $addr.IPAddress.Split('.')
  if ($octets.Count -ne 4) { return $null }
  return ($octets[0..2] -join '.') + '.1'
}

function Ensure-HomeLanRoute {
  param([string]$TargetHost)
  $targetRoute = route print $TargetHost 2>$null | Select-String "192\.168\.8\."
  if ($targetRoute) { return $true }

  $gw = $null
  $label = $null
  if (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -like '10.9.*' }) {
    $gw = Get-VpnGateway -Prefix '10.9.'
    $label = 'OpenVPN'
  } elseif (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -like '10.8.*' }) {
    $gw = Get-VpnGateway -Prefix '10.8.'
    $label = 'WireGuard'
  }

  if (-not $gw) { return $false }

  Write-Warn "Adding home LAN route via $label gateway $gw ..."
  $null = route add 192.168.8.0 mask 255.255.255.0 $gw metric 1 2>&1
  Start-Sleep -Milliseconds 500
  return [bool](route print $TargetHost 2>$null | Select-String "192\.168\.8\.")
}

function Clear-StaleNasCreds {
  param([string]$HostName, [string]$User)
  cmdkey /delete:$HostName 2>$null | Out-Null
  cmdkey /delete:"$HostName\$User" 2>$null | Out-Null
  cmdkey /delete:"\\$HostName" 2>$null | Out-Null
}

function Try-MapShare {
  param(
    [string]$Drive,
    [string]$Unc,
    [string]$User,
    [string]$Pass,
    [System.Management.Automation.PSCredential]$Cred
  )

  try { net use "${Drive}:" /delete /y 2>$null | Out-Null } catch {}
  try { Remove-PSDrive -Name $Drive -Force -ErrorAction SilentlyContinue } catch {}
  try {
    if (Get-Command Remove-SmbMapping -ErrorAction SilentlyContinue) {
      Remove-SmbMapping -LocalPath "${Drive}:" -Force -ErrorAction SilentlyContinue | Out-Null
    }
  } catch {}

  if (Get-Command New-SmbMapping -ErrorAction SilentlyContinue) {
    try {
      $null = New-SmbMapping -RemotePath $Unc -LocalPath "${Drive}:" -UserName $User -Password $Pass -Persistent $true -ErrorAction Stop
      return @{ ok = $true; method = 'New-SmbMapping' }
    } catch {
      Write-Step "  New-SmbMapping failed: $($_.Exception.Message)"
    }
  }

  try {
    $null = New-PSDrive -Name $Drive -PSProvider FileSystem -Root $Unc -Credential $Cred -Persist -ErrorAction Stop
    return @{ ok = $true; method = 'New-PSDrive' }
  } catch {
    Write-Step "  New-PSDrive failed: $($_.Exception.Message)"
  }

  Clear-StaleNasCreds -HostName $NasHost -User $User
  $null = cmdkey /add:$NasHost /user:$User /pass:$Pass
  $out = net use "${Drive}:" $Unc $Pass /user:$User /persistent:yes 2>&1
  if ($LASTEXITCODE -eq 0) {
    return @{ ok = $true; method = 'net use' }
  }
  return @{ ok = $false; error = "$out" }
}

Write-Step "ServerManager NAS -> ${DriveLetter}: ($Label)"
Write-Step "Host: $NasHost  Share: $Share  User: $Username"
Write-Step ""

if (-not $Password) {
  Write-Err "ERROR: No password in script. Download again from the portal while logged in."
  Read-Host "Press Enter to close"
  exit 3
}

if (-not (Test-Connection -ComputerName $NasHost -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
  Write-Warn "WARNING: Ping to $NasHost failed (ICMP may be blocked)."
}

if (-not (Test-TcpPort -HostName $NasHost -Port 445)) {
  Write-Warn "Cannot reach SMB port 445 on $NasHost yet."
  $routed = Ensure-HomeLanRoute -TargetHost $NasHost
  if ($routed) {
    Write-Step "Home LAN route added. Retesting SMB port ..."
  } else {
    Write-Warn "Could not add a home LAN route automatically."
    Write-Warn "OpenVPN users: reconnect after the server route update, or use WireGuard with 192.168.8.0/24 allowed."
  }
  Start-Sleep -Seconds 1
}

if (-not (Test-TcpPort -HostName $NasHost -Port 445)) {
  Write-Err ""
  Write-Err "ERROR: Still cannot reach $NasHost on TCP port 445 (SMB)."
  Write-Err "Connect to home VPN first, then run this script again."
  Write-Err "If you use OpenVPN, disconnect and reconnect so the home LAN route is installed."
  Write-Err "If you use WireGuard, ensure AllowedIPs includes 192.168.8.0/24."
  Write-Err ""
  Read-Host "Press Enter to close"
  exit 2
}

$shareCandidates = @($Share, "share") | Where-Object { $_ } | Select-Object -Unique
$userCandidates = @($Username, ".\$Username", "$NasHost\$Username") | Select-Object -Unique
$secure = ConvertTo-SecureString $Password -AsPlainText -Force
$mapped = $false
$unc = ""
$method = ""

foreach ($candidate in $shareCandidates) {
  $tryUnc = "\\$NasHost\$candidate"
  Write-Step "Trying $tryUnc ..."
  foreach ($userTry in $userCandidates) {
    $cred = New-Object System.Management.Automation.PSCredential($userTry, $secure)
    $result = Try-MapShare -Drive $DriveLetter -Unc $tryUnc -User $userTry -Pass $Password -Cred $cred
    if ($result.ok) {
      $mapped = $true
      $unc = $tryUnc
      $method = $result.method
      break
    }
    if ($result.error) { Write-Step "  net use failed: $($result.error)" }
  }
  if ($mapped) { break }
}

if (-not $mapped) {
  Write-Err ""
  Write-Err "ERROR: Could not map any SMB share on $NasHost"
  Write-Err "SMB is reachable, but login or share access failed."
  Write-Err "Tried shares: $($shareCandidates -join ', ')"
  Write-Err "Download a fresh setup script from the portal and try again."
  Write-Err ""
  Read-Host "Press Enter to close"
  exit 1
}

try {
  $shell = New-Object -ComObject Scripting.Shell
  $shell.NameSpace("${DriveLetter}:").Self.Name = $Label
} catch {}

Write-Host ""
Write-Host "Mapped ${DriveLetter}: -> $unc ($Label) via $method" -ForegroundColor Green
Write-Step "Open File Explorer -> This PC -> ${DriveLetter}:"
Start-Process explorer.exe "${DriveLetter}:\"
Read-Host "Press Enter to close"
