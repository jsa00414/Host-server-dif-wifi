# ServerManager - Map Buffalo NAS in Windows File Explorer via portal public route
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
$LogFile = Join-Path $env:TEMP "ServerManagerNas-setup.log"
$script:ChangedSmbPort = $false
$script:AddedPortProxy = $false

function Write-Log($msg) {
  $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $msg"
  try { Add-Content -LiteralPath $LogFile -Value $line -Encoding UTF8 } catch {}
}

function Write-Step($msg) { Write-Host $msg; Write-Log $msg }
function Write-Warn($msg) { Write-Host $msg -ForegroundColor Yellow; Write-Log "WARN: $msg" }
function Write-Err($msg) { Write-Host $msg -ForegroundColor Red; Write-Log "ERROR: $msg" }

function Test-IsAdmin {
  return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Import-NasPassword {
  param([string]$ScriptPath, [string]$Current)
  if ($Current -and $Current -ne '@@NAS_PASSWORD@@') { return $Current }
  $dir = Split-Path -Parent $ScriptPath
  $pwFile = Join-Path $dir 'Setup-ServerManagerNas.pw'
  if (Test-Path -LiteralPath $pwFile) {
    return (Get-Content -LiteralPath $pwFile -Raw).TrimEnd("`r", "`n")
  }
  if ($env:SM_NAS_PASSWORD_B64) {
    try {
      return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:SM_NAS_PASSWORD_B64))
    } catch {}
  }
  return $Current
}

if (-not (Test-IsAdmin)) {
  Start-Process powershell.exe -Verb RunAs -ArgumentList @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath
  ) -Wait
  exit $LASTEXITCODE
}

$Password = Import-NasPassword -ScriptPath $PSCommandPath -Current $Password

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
  if ($svc.StartType -eq 'Disabled') { Set-Service iphlpsvc -StartupType Manual }
  if ($svc.Status -ne 'Running') { Start-Service iphlpsvc; Start-Sleep -Seconds 1 }
}

function Enable-NasPortProxy {
  param([string]$ConnectHost, [int]$ConnectPort, [int]$ListenPort)
  Ensure-IpHelperService
  & netsh interface portproxy delete v4tov4 listenport=$ListenPort listenaddress=127.0.0.1 | Out-Null
  $output = & netsh interface portproxy add v4tov4 listenport=$ListenPort listenaddress=127.0.0.1 connectport=$ConnectPort connectaddress=$ConnectHost 2>&1
  if ($LASTEXITCODE -ne 0) { throw "portproxy add failed: $output" }
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
  if ($Port -eq 445) { return }
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
    [string]$Pass
  )

  try { net use "${Drive}:" /delete /y 2>$null | Out-Null } catch {}
  try { Remove-PSDrive -Name $Drive -Force -ErrorAction SilentlyContinue } catch {}
  try {
    if (Get-Command Remove-SmbMapping -ErrorAction SilentlyContinue) {
      Remove-SmbMapping -LocalPath "${Drive}:" -Force -ErrorAction SilentlyContinue | Out-Null
    }
  } catch {}

  Clear-StaleNasCreds -Server $Server -User $User
  $secure = ConvertTo-SecureString $Pass -AsPlainText -Force
  $cred = New-Object System.Management.Automation.PSCredential($User, $secure)

  $net = Invoke-NetUseMap -Drive $Drive -Unc $Unc -User $User -Pass $Pass
  if ($net.ok) {
    return @{ ok = $true; method = 'net use' }
  }
  Write-Step "  net use failed: $($net.output)"

  if (Get-Command New-SmbMapping -ErrorAction SilentlyContinue) {
    try {
      $null = New-SmbMapping -RemotePath $Unc -LocalPath "${Drive}:" -Credential $cred -Persistent $true -ErrorAction Stop
      return @{ ok = $true; method = 'New-SmbMapping' }
    } catch {
      Write-Step "  New-SmbMapping failed: $($_.Exception.Message)"
    }
  }

  return @{ ok = $false; error = $net.output }
}

function Cleanup-Setup {
  if ($script:ChangedSmbPort) { Clear-SmbClientPort }
  if ($script:AddedPortProxy) { Disable-NasPortProxy -ListenPort $LocalSmbPort }
}

function Build-MapAttempts {
  param([string]$Ip, [string]$HostName, [int]$Port, [int]$LocalPort, [string]$ShareName)
  $list = New-Object System.Collections.Generic.List[object]
  foreach ($server in @($Ip, $HostName)) {
    if (-not $server) { continue }
    $list.Add([pscustomobject]@{
      Name = 'alt-port UNC'
      Unc = "\\${server}@${Port}\$ShareName"
      Server = "${server}@${Port}"
      Setup = { }
    })
  }
  $list.Add([pscustomobject]@{
    Name = 'local proxy'
    Unc = "\\127.0.0.1\$ShareName"
    Server = '127.0.0.1'
    Setup = {
      Write-Step "Creating local SMB proxy 127.0.0.1:${LocalSmbPort} -> ${NasIp}:${NasPort} ..."
      Enable-NasPortProxy -ConnectHost $NasIp -ConnectPort $NasPort -ListenPort $LocalSmbPort
      Write-Step "Setting Windows SMB client port to $LocalSmbPort ..."
      Set-SmbClientPort -Port $LocalSmbPort
    }
  })
  foreach ($server in @($Ip, $HostName)) {
    if (-not $server) { continue }
    $list.Add([pscustomobject]@{
      Name = 'registry port'
      Unc = "\\$server\$ShareName"
      Server = $server
      Setup = {
        Write-Step "Setting Windows SMB client port to $NasPort ..."
        Set-SmbClientPort -Port $NasPort
      }
    })
  }
  return $list
}

Write-Log "=== ServerManager NAS setup start ==="
Write-Step "ServerManager NAS -> ${DriveLetter}: ($Label)"
Write-Step "Public route: ${NasIp}:${NasPort} -> \\server\${Share}"
Write-Step "User: $Username"
Write-Step "Log file: $LogFile"
Write-Step ""

if ($Password -eq '@@NAS_PASSWORD@@' -or -not $Password) {
  Write-Err "ERROR: No password in script."
  Write-Err "Download a fresh Setup-ServerManagerNas.cmd from the portal while logged in."
  Read-Host "Press Enter to close"
  exit 3
}

Write-Step "Password loaded (length $($Password.Length))."

if (-not (Test-TcpPort -HostName $NasIp -Port $NasPort) -and -not (Test-TcpPort -HostName $NasHost -Port $NasPort)) {
  Write-Err ""
  Write-Err "ERROR: Cannot reach ${NasHost} or ${NasIp} on TCP port ${NasPort}."
  Write-Err ""
  Read-Host "Press Enter to close"
  exit 2
}

$mapped = $false
$unc = ""
$method = ""
$attempts = Build-MapAttempts -Ip $NasIp -HostName $NasHost -Port $NasPort -LocalPort $LocalSmbPort -ShareName $Share

try {
  foreach ($attempt in $attempts) {
  Cleanup-Setup
  try {
    & $attempt.Setup
  } catch {
    Write-Step "  setup failed ($($attempt.Name)): $($_.Exception.Message)"
    continue
  }
  Write-Step "Trying $($attempt.Name): $($attempt.Unc) ..."
  $result = Try-MapShare -Drive $DriveLetter -Unc $attempt.Unc -Server $attempt.Server -User $Username -Pass $Password
  if ($result.ok) {
    $mapped = $true
    $unc = $attempt.Unc
    $method = "$($result.method) ($($attempt.Name))"
    break
  }
  if ($result.error) { Write-Step "  $($result.error)" }
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
if ($script:ChangedSmbPort -or $script:AddedPortProxy) {
  Write-Warn "Keep this setup PC configured for the portal public NAS route."
}
Write-Step "Open File Explorer -> This PC -> ${DriveLetter}:"
Start-Process explorer.exe "${DriveLetter}:\"
Read-Host "Press Enter to close"
