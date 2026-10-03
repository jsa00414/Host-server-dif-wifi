# ServerManager Authenticator (Windows)

Native Windows app that opens the portal Authenticator PWA in a dedicated
WebView2 window (`auth-app.html`). Same enroll / approve / pending circle UI
as the phone apps.

## Requirements

- Windows 10/11 x64
- [Microsoft Edge WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/)
  (usually already installed with Edge)

## Install

1. In the portal **Security** tab, download **Windows Authenticator**
   (`ServerManagerAuthenticator.exe`), or open:
   `https://portal.vpstruelord.com/download/ServerManagerAuthenticator.exe`
2. Save and run the `.exe` (no installer). SmartScreen may warn on first run —
   choose **More info → Run anyway** for a private build.
3. Use **Enter secret** only while Security has **New authenticator devices** unlocked.

## Rebuild

```bash
bash portal/scripts/auth-app-windows/build.sh
```

Override the portal URL at runtime:

```text
set SERVERMANAGER_PORTAL_URL=https://portal.vpstruelord.com
ServerManagerAuthenticator.exe
```
