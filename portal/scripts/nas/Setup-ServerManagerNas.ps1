# ServerManager - Map Buffalo NAS in Windows File Explorer via portal public route
# Uses a local port proxy (127.0.0.1) -> portal public SMB port -> NAS :445.
param(
  [string]$NasHost = "portal.vpstruelord.com",
  [string]$NasIp = "74.208.76.213",
  [int]$NasPort = 1445,
  [int]$LocalSmbPort = 14450,
  [string]$Share = "share",
  [string]$Username = "admin",
  [string]$Password = '@@NAS_PASSWORD@@',
  [string]$DriveLetter = "Z",
  [string]$Label = "ServerManager NAS"
)

$ErrorActionPreference = "Continue"
$DriveLetter = ($DriveLetter -replace '[^A-Za-z]', '').Substring(0, 1).ToUpper()

function Test-IsAdmin {
  return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
  if ((-not $Password -or $Password -eq '@@NAS_PASSWORD@@') -and $env:SM_NAS_PASSWORD_B64) {
    try {
      $Password = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:SM_NAS_PASSWORD_B64))
    } catch {}
  }
  $elevateArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
  if ($Password -and $Password -ne '@@NAS_PASSWORD@@') {
    $elevateArgs += '-Password'
    $elevateArgs += $Password
  }
  Start-Process powershell.exe -Verb RunAs -ArgumentList $elevateArgs -Wait
  exit $LASTEXITCODE
}

if ((-not $Password -or $Password -eq '@@NAS_PASSWORD@@') -and $env:SM_NAS_PASSWORD_B64) {
  try {
    $Password = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:SM_NAS_PASSWORD_B64))
  } catch {}
}

$LogFile = Join-Path $env:TEMP "ServerManagerNas-setup.log"
$MapServer = "127.0.0.1"
$script:AddedPortProxy = $false
$script:ChangedSmbPort = $false

function Write-Log($msg) {
  $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $msg"
  try { Add-Content -LiteralPath $LogFile -Value $line -Encoding UTF8 } catch {}
}

function Write-Step($msg) { Write-Host $msg; Write-Log $msg }
function Write-Warn($msg) { Write-Host $msg -ForegroundColor Yellow; Write-Log "WARN: $msg" }
function Write-Err($msg) { Write-Host $msg -ForegroundColor Red; Write-Log "ERROR: $msg" }

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

function Ensure-IpHelperService {
  $svc = Get-Service iphlpsvc -ErrorAction SilentlyContinue
  if (-not $svc) { return }
  if ($svc.StartType -eq 'Disabled') {
    Set-Service iphlpsvc -StartupType Manual
  }
  if ($svc.Status -ne 'Running') {
    Start-Service iphlpsvc
    Start-Sleep -Seconds 1
  }
}

function Enable-NasPortProxy {
  param([string]$ConnectHost, [int]$ConnectPort, [int]$ListenPort)
  Ensure-IpHelperService
  & netsh interface portproxy delete v4tov4 listenport=$ListenPort listenaddress=127.0.0.1 | Out-Null
  $output = & netsh interface portproxy add v4tov4 listenport=$ListenPort listenaddress=127.0.0.1 connectport=$ConnectPort connectaddress=$ConnectHost 2>&1
  if ($LASTEXITCODE -ne 0) {
    throw "portproxy add failed: $output"
  }
  $script:AddedPortProxy = $true
  if (-not (Test-TcpPort -HostName '127.0.0.1' -Port $ListenPort -TimeoutMs 8000)) {
    throw "Local SMB proxy 127.0.0.1:$ListenPort did not open."
  }
}

function Disable-NasPortProxy {
  param([int]$ListenPort)
  & netsh interface portproxy delete v4tov4 listenport=$ListenPort listenaddress=127.0.0.1 | Out-Null
  $script:AddedPortProxy = $false
}

function Set-SmbClientPort {
  param([int]$Port)
  $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
  if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
  Set-ItemProperty -Path $path -Name 'PortNumber' -Value $Port -Type DWord -Force
  Restart-Service LanmanWorkstation -Force -ErrorAction Stop
  Start-Sleep -Seconds 2
  $current = (Get-ItemProperty -Path $path -Name 'PortNumber' -ErrorAction SilentlyContinue).PortNumber
  if ([int]$current -ne [int]$Port) {
    throw "SMB client port is still $current (wanted $Port)."
  }
  $script:ChangedSmbPort = $true
}

function Clear-SmbClientPort {
  $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
  Remove-ItemProperty -Path $path -Name 'PortNumber' -ErrorAction SilentlyContinue
  $script:ChangedSmbPort = $false
}

function Clear-StaleNasCreds {
  param([string]$Server, [string]$User)
  foreach ($target in @($Server, "$Server\$User", "\\$Server")) {
    cmdkey /delete:$target 2>$null | Out-Null
  }
}

function Invoke-NetUseMap {
  param([string]$Drive, [string]$Unc, [string]$User, [string]$Pass)
  $args = @('use', "${Drive}:", $Unc, $Pass, "/user:$User", '/persistent:yes')
  $outFile = [System.IO.Path]::GetTempFileName()
  $errFile = [System.IO.Path]::GetTempFileName()
  try {
    $proc = Start-Process -FilePath 'net.exe' -ArgumentList $args -Wait -PassThru -NoNewWindow `
      -RedirectStandardOutput $outFile -RedirectStandardError $errFile
    $out = ((Get-Content -LiteralPath $outFile -ErrorAction SilentlyContinue) + (Get-Content -LiteralPath $errFile -ErrorAction SilentlyContinue)) -join ' '
    return @{ ok = ($proc.ExitCode -eq 0); output = $out.Trim() }
  } finally {
    Remove-Item -LiteralPath $outFile, $errFile -ErrorAction SilentlyContinue
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

  Clear-StaleNasCreds -Server $Server -User $User
  $null = Start-Process -FilePath 'cmdkey.exe' -ArgumentList @("/add:$Server", "/user:$User", "/pass:$Pass") -Wait -PassThru -NoNewWindow

  $net = Invoke-NetUseMap -Drive $Drive -Unc $Unc -User $User -Pass $Pass
  if ($net.ok) {
    return @{ ok = $true; method = 'net use' }
  }
  Write-Step "  net use failed: $($net.output)"

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

  return @{ ok = $false; error = $net.output }
}

function Cleanup-Setup {
  if ($script:ChangedSmbPort) { Clear-SmbClientPort }
  if ($script:AddedPortProxy) { Disable-NasPortProxy -ListenPort $LocalSmbPort }
}

Write-Log "=== ServerManager NAS setup start ==="
Write-Step "ServerManager NAS -> ${DriveLetter}: ($Label)"
Write-Step "Public route: ${NasIp}:${NasPort} -> \\${MapServer}\${Share} (local proxy on ${LocalSmbPort})"
Write-Step "User: $Username"
Write-Step "Log file: $LogFile"
Write-Step ""

if ($Password -eq '@@NAS_PASSWORD@@' -or -not $Password) {
  Write-Err "ERROR: No password in script."
  Write-Err "Download a fresh Setup-ServerManagerNas.cmd from the portal while logged in,"
  Write-Err "or run the .cmd file (it passes the password automatically)."
  Read-Host "Press Enter to close"
  exit 3
}

if (-not (Test-IsAdmin)) {
  Write-Err ""
  Write-Err "ERROR: Administrator rights are required."
  Write-Err "Right-click Setup-ServerManagerNas.cmd and choose Run as administrator."
  Write-Err ""
  Read-Host "Press Enter to close"
  exit 4
}

$remoteOk = $false
foreach ($target in @($NasIp, $NasHost)) {
  if ($target -and (Test-TcpPort -HostName $target -Port $NasPort)) {
    $remoteOk = $true
    if ($target -match '^\d+\.') { $NasIp = $target }
    break
  }
}
if (-not $remoteOk) {
  Write-Err ""
  Write-Err "ERROR: Cannot reach ${NasHost} or ${NasIp} on TCP port ${NasPort}."
  Write-Err "The portal public NAS route may still be starting. Wait a minute and try again."
  Write-Err ""
  Read-Host "Press Enter to close"
  exit 2
}

$mapped = $false
$unc = "\\$MapServer\$Share"
$method = ""

try {
  Write-Step "Creating local SMB proxy 127.0.0.1:${LocalSmbPort} -> ${NasIp}:${NasPort} ..."
  Enable-NasPortProxy -ConnectHost $NasIp -ConnectPort $NasPort -ListenPort $LocalSmbPort
  Write-Step "Setting Windows SMB client port to $LocalSmbPort ..."
  Set-SmbClientPort -Port $LocalSmbPort
  Write-Step "Mapping $unc ..."
  $secure = ConvertTo-SecureString $Password -AsPlainText -Force
  $cred = New-Object System.Management.Automation.PSCredential($Username, $secure)
  $result = Try-MapShare -Drive $DriveLetter -Unc $unc -Server $MapServer -User $Username -Pass $Password -Cred $cred
  if ($result.ok) {
    $mapped = $true
    $method = $result.method
  } elseif ($result.error) {
    Write-Step "  $($result.error)"
  }
} catch {
  Write-Err $_.Exception.Message
} finally {
  if (-not $mapped) { Cleanup-Setup }
}

if (-not $mapped) {
  Write-Err ""
  Write-Err "ERROR: Could not map any SMB share on $NasHost"
  Write-Err "Public route is reachable, but login or share access failed."
  Write-Err "See log: $LogFile"
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
Write-Warn "Keep this PC's local NAS proxy enabled. Re-run the setup script after reboot if Z: stops working."
Write-Step "Open File Explorer -> This PC -> ${DriveLetter}:"
Start-Process explorer.exe "${DriveLetter}:\"
Read-Host "Press Enter to close"
