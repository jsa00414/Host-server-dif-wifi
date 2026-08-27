# Windows built-in VPN (IKEv2)

ServerManager runs **strongSwan IKEv2** with an **RSA server certificate** and a private CA (Windows built-in VPN rejects Let's Encrypt ECDSA for IKEv2).

## Setup / refresh on the VPS

```bash
bash /opt/ikev2/setup-ikev2.sh
```

## Connect from Windows

1. Portal → **Windows VPN**
2. Download `Setup-ServerManagerVpn.ps1`
3. Run it in **PowerShell as Administrator** (installs the CA into Trusted Root + creates the VPN profile)
4. Connect with the shown username/password

## Details

| Item | Value |
|------|--------|
| Protocol | IKEv2 + EAP-MSCHAPv2 |
| Ports | UDP 500, 4500 |
| Pool | `10.10.0.0/24` |
| DNS | `10.9.0.1` → AdGuard → Pi-hole |
| Server cert | RSA 2048 (ServerManager CA) |
