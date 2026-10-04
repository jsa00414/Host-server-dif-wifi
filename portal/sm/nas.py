"""NAS gateway helpers — FTP retired in favor of SFTP / WebDAV."""
from __future__ import annotations

import os


def ftp_retired() -> bool:
    """Public FTP gateway is retired unless explicitly re-enabled."""
    raw = str(os.environ.get("NAS_FTP_RETIRED", "1")).strip().lower()
    return raw not in ("0", "false", "no", "off")


def preferred_nas_protocols() -> list[str]:
    if ftp_retired():
        return ["sftp", "webdav", "smb"]
    return ["sftp", "webdav", "smb", "ftp"]


def nas_ui_copy() -> dict:
    retired = ftp_retired()
    return {
        "ftp_retired": retired,
        "preferred": preferred_nas_protocols(),
        "headline": (
            "Use SFTP or WebDAV over VPN / home Wi‑Fi (FTP gateway retired)."
            if retired
            else "Map NAS over VPN / home Wi‑Fi."
        ),
        "ftp_message": (
            "FTP on :2121 is retired. Prefer SFTP (:2123) or WebDAV (/dav)."
            if retired
            else ""
        ),
    }
