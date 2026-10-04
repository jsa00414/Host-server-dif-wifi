# NAS SFTP gateway

VPN/LAN SFTP front door on the VPS (`rclone serve sftp` → Buffalo FTP backend).

| | |
|---|---|
| Host | `portal.vpstruelord.com` (or VPS IP) |
| Port | **2123** (`NAS_SFTP_PUBLIC_PORT`) |
| User | `admin` (same as FTP / NAS) |
| Password | Buffalo admin (portal NAS credentials) |
| Allow | VPN + home LAN only (UFW) |

Install / refresh:

```bash
bash /opt/wireguard/port-forward-ui/scripts/nas/install-nas-sftp-gateway.sh
```

Clients: WinSCP, FileZilla (SFTP), macOS `sftp`, Cyberduck, rclone.
