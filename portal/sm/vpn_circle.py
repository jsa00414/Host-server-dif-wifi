"""VPN trust-circle drift detection (sticky vs allowlist vs Caddy ACL)."""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Callable


STICKY_PATH = Path(
    os.environ.get(
        "STICKY_VPN_IPS_FILE",
        "/opt/servermanager/panel/caddy-sticky-vpn-ips.txt",
    )
)
ALLOWLIST_PATH = Path(
    os.environ.get(
        "VPN_ALLOWLIST_FILE",
        "/opt/servermanager/panel/vpn-allowlist.json",
    )
)
CADDYFILE_PATH = Path(
    os.environ.get("CADDYFILE_PATH", "/opt/truemail/Caddyfile")
)
METRICS_PATH = Path(
    os.environ.get(
        "CIRCLE_DRIFT_METRICS_PATH",
        "/var/lib/node_exporter/textfile_collector/circle_drift.prom",
    )
)


def _normalize_ip(raw: str) -> str:
    ip = str(raw or "").strip()
    if "/" in ip:
        ip = ip.split("/", 1)[0].strip()
    return ip


def _read_sticky_ips() -> set[str]:
    out: set[str] = set()
    if not STICKY_PATH.is_file():
        return out
    try:
        for line in STICKY_PATH.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            ip = _normalize_ip(line)
            if ip:
                out.add(ip)
    except OSError:
        pass
    return out


def _read_allowlist_keybound_ips() -> set[str]:
    out: set[str] = set()
    if not ALLOWLIST_PATH.is_file():
        return out
    try:
        data = json.loads(ALLOWLIST_PATH.read_text(encoding="utf-8"))
    except Exception:
        return out
    for row in data.get("allowed") or []:
        if not isinstance(row, dict):
            continue
        ip = _normalize_ip(str(row.get("ip") or ""))
        if not ip:
            continue
        sealed = bool(row.get("sealed"))
        has_key = bool(str(row.get("pubkey") or "").strip())
        if sealed or has_key:
            out.add(ip)
    return out


def _read_caddy_vpn_client_ips() -> set[str]:
    """Extract /32 host entries from @vpn_clients client_ip lines (ignore broad CIDRs)."""
    out: set[str] = set()
    if not CADDYFILE_PATH.is_file():
        return out
    try:
        text = CADDYFILE_PATH.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for match in re.finditer(r"@vpn_clients\s+client_ip\s+([^\n]+)", text):
        for tok in match.group(1).split():
            tok = tok.strip()
            if not tok:
                continue
            if tok.endswith("/32"):
                out.add(tok[:-3])
            elif "/" not in tok and re.match(r"^\d+\.\d+\.\d+\.\d+$", tok):
                out.add(tok)
    return out


def compute_circle_drift() -> dict:
    sticky = _read_sticky_ips()
    allow = _read_allowlist_keybound_ips()
    caddy = _read_caddy_vpn_client_ips()

    sticky_not_allow = sorted(sticky - allow)
    allow_not_sticky = sorted(allow - sticky)
    # Caddy sticky /32s should match sticky file; pools are ignored above.
    sticky_not_caddy = sorted(sticky - caddy) if caddy else []
    caddy_not_sticky = sorted(caddy - sticky) if caddy else []

    drifted = bool(
        sticky_not_allow
        or allow_not_sticky
        or sticky_not_caddy
        or caddy_not_sticky
    )
    return {
        "ok": not drifted,
        "drifted": drifted,
        "checked_at": int(time.time()),
        "counts": {
            "sticky": len(sticky),
            "allowlist_keybound": len(allow),
            "caddy_host32": len(caddy),
        },
        "sticky_not_in_allowlist": sticky_not_allow,
        "allowlist_not_in_sticky": allow_not_sticky,
        "sticky_not_in_caddy": sticky_not_caddy,
        "caddy_not_in_sticky": caddy_not_sticky,
        "paths": {
            "sticky": str(STICKY_PATH),
            "allowlist": str(ALLOWLIST_PATH),
            "caddy": str(CADDYFILE_PATH),
        },
    }


def write_drift_metrics(report: dict) -> None:
    METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
    drifted = 1 if report.get("drifted") else 0
    counts = report.get("counts") or {}
    body = (
        "# HELP sm_circle_drift Trust-circle sticky/allowlist/Caddy disagreement.\n"
        "# TYPE sm_circle_drift gauge\n"
        f"sm_circle_drift {drifted}\n"
        "# HELP sm_circle_sticky_ips Sticky /32 count.\n"
        "# TYPE sm_circle_sticky_ips gauge\n"
        f"sm_circle_sticky_ips {int(counts.get('sticky') or 0)}\n"
        "# HELP sm_circle_allowlist_keybound_ips Key-bound/sealed allowlist count.\n"
        "# TYPE sm_circle_allowlist_keybound_ips gauge\n"
        f"sm_circle_allowlist_keybound_ips {int(counts.get('allowlist_keybound') or 0)}\n"
        "# HELP sm_circle_caddy_host32_ips Caddy @vpn_clients /32 count.\n"
        "# TYPE sm_circle_caddy_host32_ips gauge\n"
        f"sm_circle_caddy_host32_ips {int(counts.get('caddy_host32') or 0)}\n"
    )
    tmp = METRICS_PATH.with_suffix(".tmp")
    tmp.write_text(body, encoding="utf-8")
    tmp.replace(METRICS_PATH)


def send_drift_email(
    report: dict,
    *,
    smtp_send: Callable[..., None],
    to_addr: str,
) -> None:
    if not report.get("drifted") or not to_addr:
        return
    subject = "ServerManager trust-circle drift detected"
    lines = [
        "Sticky / allowlist / Caddy ACL disagreement:",
        f"sticky={report['counts'].get('sticky')} "
        f"allowlist_keybound={report['counts'].get('allowlist_keybound')} "
        f"caddy_host32={report['counts'].get('caddy_host32')}",
        "",
        f"sticky not in allowlist: {', '.join(report.get('sticky_not_in_allowlist') or []) or '(none)'}",
        f"allowlist not in sticky: {', '.join(report.get('allowlist_not_in_sticky') or []) or '(none)'}",
        f"sticky not in caddy: {', '.join(report.get('sticky_not_in_caddy') or []) or '(none)'}",
        f"caddy not in sticky: {', '.join(report.get('caddy_not_in_sticky') or []) or '(none)'}",
    ]
    body = "\n".join(lines) + "\n"
    smtp_send(to_addr=to_addr, subject=subject, body=body, html=None)


def run_circle_drift_check(
    *,
    smtp_send: Callable[..., None] | None = None,
    email_to: str = "",
    email_on_drift: bool = True,
) -> dict:
    report = compute_circle_drift()
    try:
        write_drift_metrics(report)
        report["metrics_path"] = str(METRICS_PATH)
    except Exception as exc:
        report["metrics_error"] = str(exc)
    if email_on_drift and report.get("drifted") and smtp_send and email_to:
        try:
            send_drift_email(report, smtp_send=smtp_send, to_addr=email_to)
            report["email_sent"] = True
        except Exception as exc:
            report["email_error"] = str(exc)
    return report
