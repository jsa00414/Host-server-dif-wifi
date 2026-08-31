# ServerManager - Map Buffalo NAS in Windows File Explorer via portal public route
# VPS public port forwards to NAS SMB (default portal.vpstruelord.com:1445 -> NAS:445).
param(
  [string]$NasHost = "portal.vpstruelord.com",
  [string]$NasIp = "74.208.76.213",
  [int]$NasPort = 1445,
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

function Get-NasUnc {
  param([string]$Server, [string]$ShareName)
  return "\\$Server\$ShareName"
}

function Test-TcpPort {
  param([string]$HostName, [int]$Port, [int]$TimeoutMs = 5000)
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

function Test-IsAdmin {
  return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Set-SmbClientPort {
  param([int]$Port)
  if ($Port -eq 445) { return $true }
  $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
  if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
  Set-ItemProperty -Path $path -Name 'PortNumber' -Value $Port -Type DWord -Force
  try {
    Restart-Service LanmanWorkstation -Force -ErrorAction Stop
    Start-Sleep -Seconds 2
  } catch {
    throw "LanmanWorkstation restart failed: $($_.Exception.Message)"
  }
  $current = (Get-ItemProperty -Path $path -Name 'PortNumber' -ErrorAction SilentlyContinue).PortNumber
  if ([int]$current -ne [int]$Port) {
    throw "SMB client port is still $current (wanted $Port)."
  }
  return $true
}

function Clear-SmbClientPort {
  $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
  Remove-ItemProperty -Path $path -Name 'PortNumber' -ErrorAction SilentlyContinue
}

function Clear-StaleNasCreds {
  param([string[]]$Servers, [string]$User)
  foreach ($server in ($Servers | Where-Object { $_ } | Select-Object -Unique)) {
    foreach ($target in @($server, "$server\$User", "\\$server")) {
      cmdkey /delete:$target 2>$null | Out-Null
    }
  }
}

function Invoke-NetUseMap {
  param(
    [string]$Drive,
    [string]$Unc,
    [string]$User,
    [string]$Pass
  )
  $args = @(
    'use', "${Drive}:",
    $Unc,
    $Pass,
    "/user:$User",
    '/persistent:yes'
  )
  $outFile = [System.IO.Path]::GetTempFileName()
  $errFile = [System.IO.Path]::GetTempFileName()
  try {
    $proc = Start-Process -FilePath 'net.exe' -ArgumentList $args -Wait -PassThru -NoNewWindow `
      -RedirectStandardOutput $outFile -RedirectStandardError $errFile
    $out = ((Get-Content -LiteralPath $outFile -ErrorAction SilentlyContinue) + (Get-Content -LiteralPath $errFile -ErrorAction SilentlyContinue)) -join ' '
    return @{ ok = ($proc.ExitCode -eq 0); output = $out.Trim() }
  } finally {
    Remove-Item -LiteralPath $outFile,$errFile -ErrorAction SilentlyContinue
  }
}

function Try-MapShare {
  param(
    [string]$Drive,
    [string]$Unc,
    [string]$Server,
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

  $null = Start-Process -FilePath 'cmdkey.exe' -ArgumentList @("/add:$Server", "/user:$User", "/pass:$Pass") -Wait -PassThru -NoNewWindow
  $net = Invoke-NetUseMap -Drive $Drive -Unc $Unc -User $User -Pass $Pass
  if ($net.ok) {
    return @{ ok = $true; method = 'net use' }
  }
  return @{ ok = $false; error = $net.output }
}

Write-Step "ServerManager NAS -> ${DriveLetter}: ($Label)"
Write-Step "Public route: ${NasHost}:${NasPort} -> \\${NasHost}\${Share}"
Write-Step "User: $Username"
Write-Step ""

if ($Password -eq '@@NAS_PASSWORD@@' -or -not $Password) {
  Write-Err "ERROR: No password in script. Download again from the portal while logged in."
  Read-Host "Press Enter to close"
  exit 3
}

if (-not (Test-TcpPort -HostName $NasHost -Port $NasPort) -and -not (Test-TcpPort -HostName $NasIp -Port $NasPort)) {
  Write-Err ""
  Write-Err "ERROR: Cannot reach ${NasHost} or ${NasIp} on TCP port ${NasPort}."
  Write-Err "The portal public NAS route may still be starting. Wait a minute and try again."
  Write-Err ""
  Read-Host "Press Enter to close"
  exit 2
}

if ($NasPort -ne 445 -and -not (Test-IsAdmin)) {
  Write-Err ""
  Write-Err "ERROR: Administrator rights are required to map SMB on port $NasPort."
  Write-Err "Right-click Setup-ServerManagerNas.cmd and choose Run as administrator."
  Write-Err "Do not run the .ps1 directly unless you started PowerShell as admin."
  Write-Err ""
  Read-Host "Press Enter to close"
  exit 4
}

$hadPort = $false
if ($NasPort -ne 445) {
  try {
    Write-Step "Setting Windows SMB client port to $NasPort ..."
    $hadPort = Set-SmbClientPort -Port $NasPort
    Write-Step "SMB client port $NasPort is active."
  } catch {
    Write-Err ""
    Write-Err "ERROR: Could not configure Windows SMB port $NasPort."
    Write-Err $_.Exception.Message
    Write-Err "Run Setup-ServerManagerNas.cmd as administrator and try again."
    Write-Err ""
    Read-Host "Press Enter to close"
    exit 5
  }
}

$serverCandidates = @($NasHost, $NasIp) | Where-Object { $_ } | Select-Object -Unique
$shareCandidates = @($Share, "share") | Where-Object { $_ } | Select-Object -Unique
$userCandidates = @($Username, ".\$Username") | Select-Object -Unique
$secure = ConvertTo-SecureString $Password -AsPlainText -Force
$mapped = $false
$unc = ""
$method = ""

try {
  Clear-StaleNasCreds -Servers $serverCandidates -User $Username
  foreach ($server in $serverCandidates) {
    foreach ($candidate in $shareCandidates) {
      $tryUnc = Get-NasUnc -Server $server -ShareName $candidate
      Write-Step "Trying $tryUnc ..."
      foreach ($userTry in $userCandidates) {
        $cred = New-Object System.Management.Automation.PSCredential($userTry, $secure)
        $result = Try-MapShare -Drive $DriveLetter -Unc $tryUnc -Server $server -User $userTry -Pass $Password -Cred $cred
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
    if ($mapped) { break }
  }
} finally {
  if ($hadPort -and -not $mapped) { Clear-SmbClientPort }
}

if (-not $mapped) {
  Write-Err ""
  Write-Err "ERROR: Could not map any SMB share on $NasHost"
  Write-Err "Public route is reachable, but login or share access failed."
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
if ($hadPort) {
  Write-Warn "SMB client port $NasPort is enabled for reconnects to the portal public route."
}
Write-Step "Open File Explorer -> This PC -> ${DriveLetter}:"
Start-Process explorer.exe "${DriveLetter}:\"
Read-Host "Press Enter to close"
