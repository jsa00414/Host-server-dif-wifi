# ServerManager - Map Buffalo NAS in Windows File Explorer via portal public route
# VPS public port forwards to NAS SMB (default portal.vpstruelord.com:1445 -> NAS:445).
param(
  [string]$NasHost = "portal.vpstruelord.com",
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

function Get-SmbServerName {
  param([string]$HostName, [int]$Port)
  if ($Port -eq 445) { return $HostName }
  return "${HostName}@${Port}"
}

function Get-NasUnc {
  param([string]$HostName, [int]$Port, [string]$ShareName)
  $server = Get-SmbServerName -HostName $HostName -Port $Port
  return "\\$server\$ShareName"
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

function Set-SmbClientPort {
  param([int]$Port)
  if ($Port -eq 445) { return $false }
  $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
  if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
  Set-ItemProperty -Path $path -Name 'PortNumber' -Value $Port -Type DWord -Force
  try {
    Restart-Service LanmanWorkstation -Force -ErrorAction Stop
  } catch {
    Write-Warn "SMB port set to $Port but LanmanWorkstation could not restart: $($_.Exception.Message)"
  }
  return $true
}

function Clear-SmbClientPort {
  $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
  Remove-ItemProperty -Path $path -Name 'PortNumber' -ErrorAction SilentlyContinue
}

function Clear-StaleNasCreds {
  param([string]$SmbServer, [string]$HostName, [string]$User)
  foreach ($target in @($SmbServer, $HostName, "$HostName\$User", "\\$HostName", "\\$SmbServer")) {
    cmdkey /delete:$target 2>$null | Out-Null
  }
}

function Try-MapShare {
  param(
    [string]$Drive,
    [string]$Unc,
    [string]$SmbServer,
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

  Clear-StaleNasCreds -SmbServer $SmbServer -HostName $NasHost -User $User
  $null = cmdkey /add:$SmbServer /user:$User /pass:$Pass
  $out = net use "${Drive}:" $Unc $Pass /user:$User /persistent:yes 2>&1
  if ($LASTEXITCODE -eq 0) {
    return @{ ok = $true; method = 'net use' }
  }
  Write-Step "  net use failed: $out"

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

  return @{ ok = $false; error = "$out" }
}

$SmbServer = Get-SmbServerName -HostName $NasHost -Port $NasPort
Write-Step "ServerManager NAS -> ${DriveLetter}: ($Label)"
Write-Step "Public route: ${NasHost}:${NasPort} -> $(Get-NasUnc -HostName $NasHost -Port $NasPort -ShareName $Share)"
Write-Step "User: $Username"
Write-Step ""

if (-not $Password) {
  Write-Err "ERROR: No password in script. Download again from the portal while logged in."
  Read-Host "Press Enter to close"
  exit 3
}

if (-not (Test-TcpPort -HostName $NasHost -Port $NasPort)) {
  Write-Err ""
  Write-Err "ERROR: Cannot reach ${NasHost} on TCP port ${NasPort}."
  Write-Err "The portal public NAS route may still be starting. Wait a minute and try again."
  Write-Err ""
  Read-Host "Press Enter to close"
  exit 2
}

$hadPort = $false
$shareCandidates = @($Share, "share") | Where-Object { $_ } | Select-Object -Unique
$userCandidates = @($Username, ".\$Username", "$NasHost\$Username") | Select-Object -Unique
$secure = ConvertTo-SecureString $Password -AsPlainText -Force
$mapped = $false
$unc = ""
$method = ""

try {
  foreach ($candidate in $shareCandidates) {
    $tryUnc = Get-NasUnc -HostName $NasHost -Port $NasPort -ShareName $candidate
    Write-Step "Trying $tryUnc ..."
    foreach ($userTry in $userCandidates) {
      $cred = New-Object System.Management.Automation.PSCredential($userTry, $secure)
      $result = Try-MapShare -Drive $DriveLetter -Unc $tryUnc -SmbServer $SmbServer -User $userTry -Pass $Password -Cred $cred
      if ($result.ok) {
        $mapped = $true
        $unc = $tryUnc
        $method = $result.method
        break
      }
      if ($result.error) { Write-Step "  $($result.error)" }
    }
    if ($mapped) { break }
  }

  if (-not $mapped -and $NasPort -ne 445) {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
      [Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
      Write-Step "Retrying with global SMB port $NasPort (admin fallback) ..."
      try {
        $hadPort = Set-SmbClientPort -Port $NasPort
        Start-Sleep -Milliseconds 400
        foreach ($candidate in $shareCandidates) {
          $tryUnc = "\\$NasHost\$candidate"
          Write-Step "Trying $tryUnc ..."
          foreach ($userTry in $userCandidates) {
            $cred = New-Object System.Management.Automation.PSCredential($userTry, $secure)
            $result = Try-MapShare -Drive $DriveLetter -Unc $tryUnc -SmbServer $NasHost -User $userTry -Pass $Password -Cred $cred
            if ($result.ok) {
              $mapped = $true
              $unc = $tryUnc
              $method = "$($result.method) (registry port)"
              break
            }
          }
          if ($mapped) { break }
        }
      } catch {
        Write-Warn "Registry SMB port fallback failed: $($_.Exception.Message)"
      }
    }
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
if ($hadPort -and $mapped) {
  Write-Warn "SMB client port $NasPort is enabled for reconnects to the portal public route."
}
Write-Step "Open File Explorer -> This PC -> ${DriveLetter}:"
Start-Process explorer.exe "${DriveLetter}:\"
Read-Host "Press Enter to close"
