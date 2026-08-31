# ServerManager - Map Buffalo NAS in Windows File Explorer via portal public route
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
$LogFile = Join-Path $env:TEMP "ServerManagerNas-setup.log"
$script:ChangedSmbPort = $false

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

  if (Get-Command New-SmbMapping -ErrorAction SilentlyContinue) {
    try {
      $null = New-SmbMapping -RemotePath $Unc -LocalPath "${Drive}:" -Credential $cred -Persistent $true -ErrorAction Stop
      return @{ ok = $true; method = 'New-SmbMapping' }
    } catch {
      Write-Step "  New-SmbMapping failed: $($_.Exception.Message)"
    }
  }

  try {
    $null = New-PSDrive -Name $Drive -PSProvider FileSystem -Root $Unc -Credential $cred -Persist -ErrorAction Stop
    return @{ ok = $true; method = 'New-PSDrive' }
  } catch {
    Write-Step "  New-PSDrive failed: $($_.Exception.Message)"
  }

  $net = Invoke-NetUseMap -Drive $Drive -Unc $Unc -User $User -Pass $Pass
  if ($net.ok) {
    return @{ ok = $true; method = 'net use' }
  }
  return @{ ok = $false; error = $net.output }
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

try {
  Write-Step "Setting Windows SMB client port to $NasPort ..."
  Set-SmbClientPort -Port $NasPort
  foreach ($server in @($NasIp, $NasHost)) {
    if (-not $server) { continue }
    $tryUnc = "\\$server\$Share"
    Write-Step "Mapping $tryUnc ..."
    $result = Try-MapShare -Drive $DriveLetter -Unc $tryUnc -Server $server -User $Username -Pass $Password
    if ($result.ok) {
      $mapped = $true
      $unc = $tryUnc
      $method = $result.method
      break
    }
    if ($result.error) { Write-Step "  net use failed: $($result.error)" }
  }
} catch {
  Write-Err $_.Exception.Message
} finally {
  if (-not $mapped) { Clear-SmbClientPort }
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
Write-Warn "SMB client port $NasPort stays enabled for reconnects to the portal public route."
Write-Step "Open File Explorer -> This PC -> ${DriveLetter}:"
Start-Process explorer.exe "${DriveLetter}:\"
Read-Host "Press Enter to close"
