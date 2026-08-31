# ServerManager - Map Buffalo NAS in Windows File Explorer via portal public route
param(
  [string]$NasHost = "portal.vpstruelord.com",
  [string]$NasIp = "74.208.76.213",
  [int]$NasPort = 1445,
  [string]$LocalListenIp = "10.255.255.1",
  [int]$LocalSmbPort = 445,
  [string]$MapAlias = "sm-nas.vpstruelord.com",
  [string]$Share = "share",
  [string]$NasNetbiosName = "741HOMECLOUDNET",
  [string]$Username = "admin",
  [string]$Password = '@@NAS_PASSWORD@@',
  [string]$DriveLetter = "Z",
  [string]$Label = "ServerManager NAS"
)

$ErrorActionPreference = "Continue"
$DriveLetter = ($DriveLetter -replace '[^A-Za-z]', '').Substring(0, 1).ToUpper()
$LogFile = Join-Path $env:TEMP "ServerManagerNas-setup.log"
$HostsMark = "# servermanager-nas-route"
$script:ChangedSmbPort = $false
$script:AddedPortProxy = $false
$script:AddedHostsEntry = $false
$script:AddedListenIp = $false

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
  param([string]$ScriptPath)
  $dir = Split-Path -Parent $ScriptPath
  $pwFile = Join-Path $dir 'Setup-ServerManagerNas.pw'
  if (Test-Path -LiteralPath $pwFile) {
    return (Get-Content -LiteralPath $pwFile -Raw -Encoding UTF8).TrimEnd("`r", "`n")
  }
  if ($env:SM_NAS_PASSWORD_B64) {
    try {
      return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:SM_NAS_PASSWORD_B64))
    } catch {}
  }
  if ($Password -and $Password -ne '@@NAS_PASSWORD@@') { return $Password }
  return ""
}

function Read-NasPasswordPrompt {
  Write-Warn "Automatic password failed. Enter the NAS password from the portal (Settings -> Download Setup page)."
  $secure = Read-Host "NAS password" -AsSecureString
  $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
  try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
  finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

if (-not (Test-IsAdmin)) {
  Start-Process powershell.exe -Verb RunAs -ArgumentList @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath
  ) -Wait
  exit $LASTEXITCODE
}

$Password = Import-NasPassword -ScriptPath $PSCommandPath

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

function Enable-LocalListenIp {
  param([string]$ListenIp)
  $existing = Get-NetIPAddress -IPAddress $ListenIp -ErrorAction SilentlyContinue
  if ($existing) { return }
  $ifAlias = 'Loopback Pseudo-Interface 1'
  $output = & netsh interface ipv4 add address "$ifAlias" $ListenIp store=persistent 2>&1
  if ($LASTEXITCODE -ne 0 -and "$output" -notmatch 'already exists|Object already exists') {
    throw "Could not add local listen IP ${ListenIp}: $output"
  }
  $script:AddedListenIp = $true
}

function Enable-NasPortProxy {
  param([string]$ListenIp, [string]$ConnectHost, [int]$ConnectPort, [int]$ListenPort)
  Ensure-IpHelperService
  & netsh interface portproxy delete v4tov4 listenport=$ListenPort listenaddress=$ListenIp | Out-Null
  $output = & netsh interface portproxy add v4tov4 listenport=$ListenPort listenaddress=$ListenIp connectport=$ConnectPort connectaddress=$ConnectHost 2>&1
  if ($LASTEXITCODE -ne 0) { throw "portproxy add failed: $output" }
  $script:AddedPortProxy = $true
  if (-not (Test-TcpPort -HostName $ListenIp -Port $ListenPort -TimeoutMs 8000)) {
    throw "Local SMB proxy ${ListenIp}:$ListenPort did not open."
  }
}

function Disable-NasPortProxy {
  param([string]$ListenIp, [int]$ListenPort)
  & netsh interface portproxy delete v4tov4 listenport=$ListenPort listenaddress=$ListenIp | Out-Null
  $script:AddedPortProxy = $false
}

function Get-HostsFilePath {
  Join-Path $env:Windir 'System32\drivers\etc\hosts'
}

function Test-HostsHasAlias {
  param([string]$Alias, [string]$ListenIp)
  $hostsFile = Get-HostsFilePath
  $content = @(Get-Content -LiteralPath $hostsFile -ErrorAction SilentlyContinue)
  foreach ($line in $content) {
    $trim = $line.Trim()
    if (-not $trim -or $trim.StartsWith('#')) { continue }
    if ($trim -match ('^\s*' + [regex]::Escape($ListenIp) + '\s+' + [regex]::Escape($Alias) + '(\s|$)')) {
      return $true
    }
  }
  return $false
}

function Write-HostsLines {
  param([string[]]$Lines)
  $hostsFile = Get-HostsFilePath
  if (-not (Test-Path -LiteralPath $hostsFile)) {
    throw "Hosts file not found: $hostsFile"
  }

  cmd.exe /c "attrib -r `"$hostsFile`"" | Out-Null
  $tmp = Join-Path $env:TEMP ("hosts-sm-nas-" + [Guid]::NewGuid().ToString("n") + ".tmp")
  $lastErr = $null
  try {
    [System.IO.File]::WriteAllLines($tmp, $Lines, [System.Text.Encoding]::ASCII)
    for ($i = 1; $i -le 10; $i++) {
      try {
        Copy-Item -LiteralPath $tmp -Destination $hostsFile -Force -ErrorAction Stop
        return
      } catch {
        $lastErr = $_
        Start-Sleep -Milliseconds (300 * $i)
      }
    }
    $copyOut = cmd.exe /c "copy /Y `"$tmp`" `"$hostsFile`"" 2>&1
    if ($LASTEXITCODE -eq 0) { return }
    throw "Could not update hosts file (another program may be locking it): $lastErr"
  } finally {
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
  }
}

function Enable-NasHostsAlias {
  param([string]$Alias, [string]$ListenIp)
  if (Test-HostsHasAlias -Alias $Alias -ListenIp $ListenIp) {
    Write-Step "Hosts entry already set: $ListenIp $Alias"
    $script:AddedHostsEntry = $true
    return
  }
  $hostsFile = Get-HostsFilePath
  $content = @(Get-Content -LiteralPath $hostsFile -ErrorAction SilentlyContinue)
  $filtered = New-Object System.Collections.Generic.List[string]
  $skip = $false
  foreach ($line in $content) {
    if ($line -eq $HostsMark) { $skip = $true; continue }
    if ($skip) {
      if ($line -match [regex]::Escape($Alias)) { $skip = $false; continue }
      $skip = $false
    }
    if ($line -match [regex]::Escape($Alias)) { continue }
    $filtered.Add($line)
  }
  $filtered.Add($HostsMark)
  $filtered.Add("$ListenIp $Alias")
  try {
    Write-HostsLines -Lines $filtered
    $script:AddedHostsEntry = $true
  } catch {
    Write-Warn $_.Exception.Message
    Write-Warn "Add this line manually in Notepad (Run as administrator): $hostsFile"
    Write-Warn "$ListenIp $Alias"
    if (-not (Test-HostsHasAlias -Alias $Alias -ListenIp $ListenIp)) {
      throw "Hosts file is locked. Close VPN/DNS tools, add the line above manually, then run setup again."
    }
    $script:AddedHostsEntry = $true
  }
}

function Disable-NasHostsAlias {
  param([string]$Alias)
  $hostsFile = Get-HostsFilePath
  if (-not (Test-Path -LiteralPath $hostsFile)) { return }
  $lines = Get-Content -LiteralPath $hostsFile -ErrorAction SilentlyContinue
  $out = New-Object System.Collections.Generic.List[string]
  $skip = $false
  foreach ($line in $lines) {
    if ($line -eq $HostsMark) { $skip = $true; continue }
    if ($skip) {
      if ($line -match [regex]::Escape($Alias)) { $skip = $false; continue }
      $skip = $false
    }
    if ($line -match [regex]::Escape($Alias)) { continue }
    $out.Add($line)
  }
  try {
    Write-HostsLines -Lines $out
  } catch {}
  $script:AddedHostsEntry = $false
}

function Clear-SmbClientPort {
  $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
  Remove-ItemProperty -Path $path -Name 'PortNumber' -ErrorAction SilentlyContinue
  $script:ChangedSmbPort = $false
}

function Remove-LegacyNasRoute {
  param([string]$Alias)
  & netsh interface portproxy delete v4tov4 listenport=14450 listenaddress=127.0.0.1 | Out-Null
  Clear-SmbClientPort
  $hostsFile = Get-HostsFilePath
  if (-not (Test-Path -LiteralPath $hostsFile)) { return }
  $lines = Get-Content -LiteralPath $hostsFile -ErrorAction SilentlyContinue
  $out = New-Object System.Collections.Generic.List[string]
  $changed = $false
  foreach ($line in $lines) {
    if ($line -match '127\.0\.0\.1\s+' + [regex]::Escape($Alias)) { $changed = $true; continue }
    $out.Add($line)
  }
  if (-not $changed) { return }
  try {
    Write-HostsLines -Lines $out
  } catch {
    Write-Warn "Could not remove legacy 127.0.0.1 hosts entry automatically. Delete this line manually: 127.0.0.1 $Alias"
  }
}

function Clear-StaleNasCreds {
  param([string[]]$Servers, [string]$User)
  foreach ($server in ($Servers | Where-Object { $_ } | Select-Object -Unique)) {
    foreach ($target in @($server, "$server\$User", "\\$server", "TERMSRV/$server", "TERMSRV/$server/$User")) {
      cmdkey /delete:$target 2>$null | Out-Null
    }
  }
}

function Enable-SmbClientCompat {
  $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
  if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
  foreach ($pair in @(
    @{ Name = 'AllowInsecureGuestAuth'; Value = 1 },
    @{ Name = 'EnablePlainTextPasswd'; Value = 1 },
    @{ Name = 'EnableSecuritySignature'; Value = 0 },
    @{ Name = 'RequireSecuritySignature'; Value = 0 }
  )) {
    try {
      Set-ItemProperty -Path $path -Name $pair.Name -Value $pair.Value -Type DWord -Force -ErrorAction SilentlyContinue | Out-Null
    } catch {}
  }
  if (Get-Command Set-SmbClientConfiguration -ErrorAction SilentlyContinue) {
    try {
      Set-SmbClientConfiguration -RequireSecuritySignature $false -EnableSecuritySignature $false -Force -ErrorAction SilentlyContinue | Out-Null
    } catch {}
  }
}

function Add-NasCredential {
  param([string]$Target, [string]$User, [string]$Pass)
  cmdkey /delete:$Target 2>$null | Out-Null
  $outFile = [System.IO.Path]::GetTempFileName()
  $errFile = [System.IO.Path]::GetTempFileName()
  try {
    $proc = Start-Process -FilePath 'cmdkey.exe' -ArgumentList @("/add:$Target", "/user:$User", "/pass:$Pass") `
      -Wait -PassThru -NoNewWindow -RedirectStandardOutput $outFile -RedirectStandardError $errFile
    $out = ((Get-Content -LiteralPath $outFile -ErrorAction SilentlyContinue) + (Get-Content -LiteralPath $errFile -ErrorAction SilentlyContinue)) -join ' '
    return @{ ok = ($proc.ExitCode -eq 0); output = $out.Trim() }
  } finally {
    Remove-Item -LiteralPath $outFile, $errFile -ErrorAction SilentlyContinue
  }
}

function Invoke-TimedProcess {
  param(
    [string]$FilePath,
    [string[]]$ArgumentList,
    [int]$TimeoutMs = 25000
  )
  $outFile = [System.IO.Path]::GetTempFileName()
  $errFile = [System.IO.Path]::GetTempFileName()
  try {
    $proc = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -PassThru -NoNewWindow `
      -RedirectStandardOutput $outFile -RedirectStandardError $errFile
    if (-not $proc.WaitForExit($TimeoutMs)) {
      try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch {}
      return @{ ok = $false; output = "timed out after $([int]($TimeoutMs / 1000))s" }
    }
    $out = ((Get-Content -LiteralPath $outFile -ErrorAction SilentlyContinue) + (Get-Content -LiteralPath $errFile -ErrorAction SilentlyContinue)) -join ' '
    return @{ ok = ($proc.ExitCode -eq 0); output = $out.Trim() }
  } finally {
    Remove-Item -LiteralPath $outFile, $errFile -ErrorAction SilentlyContinue
  }
}

function Stop-StuckNetProcesses {
  Get-Process -Name 'net' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

function Invoke-NetUseMap {
  param([string]$Drive, [string]$Unc, [string]$User = "", [string]$Pass = "", [int]$TimeoutMs = 25000)
  $args = @('use', "${Drive}:", $Unc)
  if ($User) { $args += "/user:$User" }
  if ($Pass) { $args += $Pass }
  $args += '/persistent:yes'
  return Invoke-TimedProcess -FilePath 'net.exe' -ArgumentList $args -TimeoutMs $TimeoutMs
}

function Try-MapShare {
  param(
    [string]$Drive,
    [string]$Unc,
    [string[]]$Servers,
    [string[]]$Users,
    [string]$Pass
  )

  Stop-StuckNetProcesses
  try { net use "${Drive}:" /delete /y 2>$null | Out-Null } catch {}
  try { Remove-PSDrive -Name $Drive -Force -ErrorAction SilentlyContinue } catch {}
  try {
    if (Get-Command Remove-SmbMapping -ErrorAction SilentlyContinue) {
      Remove-SmbMapping -LocalPath "${Drive}:" -Force -ErrorAction SilentlyContinue | Out-Null
    }
  } catch {}

  Clear-StaleNasCreds -Servers $Servers -User ($Users | Select-Object -First 1)

  foreach ($userTry in $Users) {
    Write-Step "  Trying net use as $userTry with stored password (20s timeout) ..."
    $netDirect = Invoke-NetUseMap -Drive $Drive -Unc $Unc -User $userTry -Pass $Pass -TimeoutMs 20000
    if ($netDirect.ok) {
      return @{ ok = $true; method = "net use direct ($userTry)" }
    }
    Write-Step "  net use direct ($userTry) failed: $($netDirect.output)"
    Stop-StuckNetProcesses

    Write-Step "  Storing credentials for $userTry ..."
    $cred = Add-NasCredential -Target $MapAlias -User $userTry -Pass $Pass
    if (-not $cred.ok) {
      Write-Step "  cmdkey ($MapAlias / $userTry) failed: $($cred.output)"
    }

    Write-Step "  Trying net use with cmdkey as $userTry (20s timeout) ..."
    $net = Invoke-NetUseMap -Drive $Drive -Unc $Unc -TimeoutMs 20000
    if ($net.ok) {
      return @{ ok = $true; method = "net use + cmdkey ($userTry)" }
    }
    Write-Step "  net use + cmdkey ($userTry) failed: $($net.output)"
    Stop-StuckNetProcesses
  }

  return @{ ok = $false; error = "all user formats failed" }
}

Write-Log "=== ServerManager NAS setup start ==="
Write-Step "ServerManager NAS -> ${DriveLetter}: ($Label)"
Write-Step "Public route: ${NasIp}:${NasPort} -> \\${MapAlias}\${Share} via ${LocalListenIp}:${LocalSmbPort}"
Write-Step "User: $Username"
Write-Step "Log file: $LogFile"
Write-Step ""

if (-not $Password) {
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

$userCandidates = @(
  $Username,
  "$NasNetbiosName\$Username",
  "$MapAlias\$Username"
) | Select-Object -Unique
$mapped = $false
$unc = ""
$method = ""

try {
  Write-Step "Removing legacy 127.0.0.1 route (if present) ..."
  Remove-LegacyNasRoute -Alias $MapAlias
  Write-Step "Configuring local SMB route via $MapAlias -> $LocalListenIp ..."
  Enable-LocalListenIp -ListenIp $LocalListenIp
  Enable-NasHostsAlias -Alias $MapAlias -ListenIp $LocalListenIp
  Enable-NasPortProxy -ListenIp $LocalListenIp -ConnectHost $NasIp -ConnectPort $NasPort -ListenPort $LocalSmbPort
  Enable-SmbClientCompat
  Write-Step "Local proxy ready on ${LocalListenIp}:${LocalSmbPort}"

  $tryUnc = "\\$MapAlias\$Share"
  Write-Step "Mapping $tryUnc (proxy ${NasIp}:${NasPort}) ..."
  $result = Try-MapShare -Drive $DriveLetter -Unc $tryUnc -Servers @($MapAlias, $LocalListenIp) -Users $userCandidates -Pass $Password
  if ($result.ok) {
    $mapped = $true
    $unc = $tryUnc
    $method = $result.method
  } elseif ($result.error) {
    Write-Step "  $($result.error)"
  }

  if (-not $mapped) {
    $manual = Read-NasPasswordPrompt
    if ($manual) {
      Write-Step "Retrying with manually entered password ..."
      $result = Try-MapShare -Drive $DriveLetter -Unc $tryUnc -Servers @($MapAlias, $LocalListenIp) -Users $userCandidates -Pass $manual
      if ($result.ok) {
        $mapped = $true
        $unc = $tryUnc
        $method = $result.method
      } elseif ($result.error) {
        Write-Step "  $($result.error)"
      }
    }
  }
} catch {
  Write-Err $_.Exception.Message
}

if (-not $mapped) {
  Write-Err ""
  Write-Err "ERROR: Could not map any SMB share on $NasHost"
  Write-Err "Public route is reachable, but login or share access failed."
  Write-Err "Download a fresh Setup-ServerManagerNas.cmd from the portal, or copy the password from NAS -> Settings."
  Write-Err "The local SMB route was left in place for manual retry in File Explorer."
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
Write-Warn "Keep this PC configured for the portal NAS route (hosts alias + local proxy)."
Write-Step "Open File Explorer -> This PC -> ${DriveLetter}:"
Start-Process explorer.exe "${DriveLetter}:\"
Read-Host "Press Enter to close"
