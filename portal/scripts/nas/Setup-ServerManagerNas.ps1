# ServerManager - Map Buffalo NAS in Windows File Explorer via portal public route
param(
  [string]$NasHost = "portal.vpstruelord.com",
  [string]$NasIp = "74.208.76.213",
  [int]$NasPort = 1445,
  [int]$LocalSmbPort = 14450,
  [string]$MapAlias = "sm-nas.vpstruelord.com",
  [string]$Share = "share",
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

function Enable-NasHostsAlias {
  param([string]$Alias)
  $hostsFile = Join-Path $env:Windir 'System32\drivers\etc\hosts'
  $content = Get-Content -LiteralPath $hostsFile -ErrorAction SilentlyContinue
  if ($content -match [regex]::Escape($Alias)) { return }
  Add-Content -LiteralPath $hostsFile -Value "`r`n$HostsMark`r`n127.0.0.1 $Alias" -Encoding ASCII
  $script:AddedHostsEntry = $true
}

function Disable-NasHostsAlias {
  param([string]$Alias)
  $hostsFile = Join-Path $env:Windir 'System32\drivers\etc\hosts'
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
  Set-Content -LiteralPath $hostsFile -Value $out -Encoding ASCII
  $script:AddedHostsEntry = $false
}

function Set-SmbClientPort {
  param([int]$Port)
  if ($Port -eq 445) { return }
  $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
  if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
  Set-ItemProperty -Path $path -Name 'PortNumber' -Value $Port -Type DWord -Force
  Restart-Service LanmanWorkstation -Force -ErrorAction Stop
  Start-Sleep -Seconds 3
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

function Enable-LoopbackAuth {
  param([string]$Alias)
  # Windows blocks SMB auth to hostnames that resolve to 127.0.0.1 (loopback check).
  # That surfaces as "password is not correct" even when the NAS password is right.
  $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
  if (-not (Test-Path $lsa)) { New-Item -Path $lsa -Force | Out-Null }
  Set-ItemProperty -Path $lsa -Name 'DisableLoopbackCheck' -Value 1 -Type DWord -Force

  $msv = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
  if (-not (Test-Path $msv)) { New-Item -Path $msv -Force | Out-Null }
  $existing = @()
  try {
    $existing = @(Get-ItemProperty -Path $msv -Name 'BackConnectionHostNames' -ErrorAction SilentlyContinue).BackConnectionHostNames
  } catch {}
  if (-not $existing) { $existing = @() }
  $merged = @($existing + @($Alias) | Where-Object { $_ } | Select-Object -Unique)
  New-ItemProperty -Path $msv -Name 'BackConnectionHostNames' -PropertyType MultiString -Value $merged -Force | Out-Null
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

function Invoke-NetUseMap {
  param([string]$Drive, [string]$Unc, [string]$User = "", [string]$Pass = "")
  $args = @('use', "${Drive}:", $Unc)
  if ($User) { $args += "/user:$User" }
  if ($Pass) { $args += $Pass }
  $args += '/persistent:yes'
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

function Invoke-WNetMap {
  param([string]$Drive, [string]$Unc, [string]$User, [string]$Pass)
  if (-not ("WNetAddConnection2" -as [type])) {
    $signature = @'
[StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
public class NetResource {
  public int Scope;
  public int Type;
  public int DisplayType;
  public int Usage;
  public string LocalName;
  public string RemoteName;
  public string Comment;
  public string Provider;
}
[DllImport("Mpr.dll", CharSet=CharSet.Unicode)]
public static extern int WNetAddConnection2(NetResource netResource, string password, string username, int flags);
'@
    Add-Type -Namespace ServerManagerNas -Name WNet -MemberDefinition $signature -ErrorAction Stop | Out-Null
  }
  $resource = New-Object ServerManagerNas.WNet+NetResource
  $resource.Type = 1
  $resource.LocalName = "${Drive}:"
  $resource.RemoteName = $Unc
  $result = [ServerManagerNas.WNet]::WNetAddConnection2($resource, $Pass, $User, 0)
  if ($result -eq 0) {
    return @{ ok = $true; output = "WNetAddConnection2 ok" }
  }
  return @{ ok = $false; output = "WNetAddConnection2 error $result" }
}

function Try-MapShare {
  param(
    [string]$Drive,
    [string]$Unc,
    [string[]]$Servers,
    [string[]]$Users,
    [string]$Pass
  )

  try { net use "${Drive}:" /delete /y 2>$null | Out-Null } catch {}
  try { Remove-PSDrive -Name $Drive -Force -ErrorAction SilentlyContinue } catch {}
  try {
    if (Get-Command Remove-SmbMapping -ErrorAction SilentlyContinue) {
      Remove-SmbMapping -LocalPath "${Drive}:" -Force -ErrorAction SilentlyContinue | Out-Null
    }
  } catch {}

  Clear-StaleNasCreds -Servers $Servers -User ($Users | Select-Object -First 1)

  foreach ($userTry in $Users) {
    foreach ($target in ($Servers | Where-Object { $_ } | Select-Object -Unique)) {
      $cred = Add-NasCredential -Target $target -User $userTry -Pass $Pass
      if (-not $cred.ok) {
        Write-Step "  cmdkey ($target / $userTry) failed: $($cred.output)"
      }
    }

    $net = Invoke-NetUseMap -Drive $Drive -Unc $Unc
    if ($net.ok) {
      return @{ ok = $true; method = "net use + cmdkey ($userTry)" }
    }
    Write-Step "  net use + cmdkey ($userTry) failed: $($net.output)"

    $wnet = Invoke-WNetMap -Drive $Drive -Unc $Unc -User $userTry -Pass $Pass
    if ($wnet.ok) {
      return @{ ok = $true; method = "WNetAddConnection2 ($userTry)" }
    }
    Write-Step "  WNetAddConnection2 ($userTry) failed: $($wnet.output)"

    $secure = ConvertTo-SecureString $Pass -AsPlainText -Force
    $psCred = New-Object System.Management.Automation.PSCredential($userTry, $secure)
    if (Get-Command New-SmbMapping -ErrorAction SilentlyContinue) {
      try {
        $null = New-SmbMapping -RemotePath $Unc -LocalPath "${Drive}:" -Credential $psCred -Persistent $true -ErrorAction Stop
        return @{ ok = $true; method = "New-SmbMapping ($userTry)" }
      } catch {
        Write-Step "  New-SmbMapping ($userTry) failed: $($_.Exception.Message)"
      }
    }

    $netDirect = Invoke-NetUseMap -Drive $Drive -Unc $Unc -User $userTry -Pass $Pass
    if ($netDirect.ok) {
      return @{ ok = $true; method = "net use direct ($userTry)" }
    }
    Write-Step "  net use direct ($userTry) failed: $($netDirect.output)"
  }

  return @{ ok = $false; error = "all user formats failed" }
}

function Cleanup-Setup {
  if ($script:ChangedSmbPort) { Clear-SmbClientPort }
  if ($script:AddedPortProxy) { Disable-NasPortProxy -ListenPort $LocalSmbPort }
  if ($script:AddedHostsEntry) { Disable-NasHostsAlias -Alias $MapAlias }
}

Write-Log "=== ServerManager NAS setup start ==="
Write-Step "ServerManager NAS -> ${DriveLetter}: ($Label)"
Write-Step "Public route: ${NasIp}:${NasPort} -> \\${MapAlias}\${Share}"
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
  "WORKGROUP\$Username",
  "$MapAlias\$Username",
  ".\$Username"
) | Select-Object -Unique
$mapped = $false
$unc = ""
$method = ""
$passwordAttempts = @($Password)

try {
  Write-Step "Configuring local SMB route via $MapAlias ..."
  Enable-NasHostsAlias -Alias $MapAlias
  Enable-NasPortProxy -ConnectHost $NasIp -ConnectPort $NasPort -ListenPort $LocalSmbPort
  Set-SmbClientPort -Port $LocalSmbPort
  Enable-SmbClientCompat
  Enable-LoopbackAuth -Alias $MapAlias
  Write-Step "Enabled Windows loopback SMB auth for $MapAlias"

  $tryUnc = "\\$MapAlias\$Share"
  Write-Step "Mapping $tryUnc (proxy ${NasIp}:${NasPort}) ..."
  foreach ($passTry in $passwordAttempts) {
    if (-not $passTry) { continue }
    $result = Try-MapShare -Drive $DriveLetter -Unc $tryUnc -Servers @($MapAlias, '127.0.0.1', $NasIp) -Users $userCandidates -Pass $passTry
    if ($result.ok) {
      $mapped = $true
      $unc = $tryUnc
      $method = $result.method
      break
    }
    if ($result.error) {
      Write-Step "  $($result.error)"
    }
  }

  if (-not $mapped) {
    $manual = Read-NasPasswordPrompt
    if ($manual) {
      Write-Step "Retrying with manually entered password ..."
      $result = Try-MapShare -Drive $DriveLetter -Unc $tryUnc -Servers @($MapAlias, '127.0.0.1', $NasIp) -Users $userCandidates -Pass $manual
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
