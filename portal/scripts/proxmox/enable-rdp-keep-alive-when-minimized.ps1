# Keep Remote Desktop fully active when minimized (webcam / audio / apps).
# Run this ON THE RDP CLIENT (James-Gaming-PC / VM 100), not on win11-rdp.
#
# Default RDP behavior sets RemoteDesktop_SuppressWhenMinimized so a minimized
# mstsc window freezes/throttles the remote session. Value 2 disables that.
#
# Usage (PowerShell as the signed-in user, elevated optional but HKLM needs Admin):
#   powershell -ExecutionPolicy Bypass -File enable-rdp-keep-alive-when-minimized.ps1

$ErrorActionPreference = "Stop"

$paths = @(
  "HKCU:\Software\Microsoft\Terminal Server Client",
  "HKLM:\SOFTWARE\Microsoft\Terminal Server Client"
)

foreach ($p in $paths) {
  if (-not (Test-Path $p)) {
    New-Item -Path $p -Force | Out-Null
  }
  try {
    New-ItemProperty -Path $p -Name "RemoteDesktop_SuppressWhenMinimized" `
      -PropertyType DWord -Value 2 -Force | Out-Null
    Write-Host "Set $p\RemoteDesktop_SuppressWhenMinimized = 2"
  } catch {
    if ($p -like "HKLM:*") {
      Write-Warning "Could not write HKLM (run as Administrator): $_"
    } else {
      throw
    }
  }
}

Write-Host ""
Write-Host "Done. Close all Remote Desktop windows, then reconnect to win11-rdp."
Write-Host "Minimizing mstsc should no longer pause the webcam on the remote VM."
