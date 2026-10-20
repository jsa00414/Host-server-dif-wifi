"""Twilio SMS helpers for Truemailor / portal OTP delivery.

Credentials are read from the process environment, with a fallback to
``/opt/truemail/.env`` (same pattern as portal SMTP for Truemailor).
"""
from __future__ import annotations

import base64
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

TRUEMAIL_ENV_PATHS = (
    Path(os.environ.get("TRUEMAIL_ENV", "/opt/truemail/.env")),
    Path(__file__).resolve().parent.parent.parent / "truemail" / ".env",
)

_ENV_CACHE: dict[str, str] | None = None


def _load_truemail_env() -> dict[str, str]:
    global _ENV_CACHE
    if _ENV_CACHE is not None:
        return _ENV_CACHE
    out: dict[str, str] = {}
    for path in TRUEMAIL_ENV_PATHS:
        if not path.is_file():
            continue
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                raw = line.strip()
                if not raw or raw.startswith("#") or "=" not in raw:
                    continue
                key, val = raw.split("=", 1)
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if key and key not in out:
                    out[key] = val
        except OSError:
            continue
    _ENV_CACHE = out
    return out


def _env(name: str, default: str = "") -> str:
    direct = (os.environ.get(name) or "").strip()
    if direct:
        return direct
    return (_load_truemail_env().get(name) or default).strip()


def account_sid() -> str:
    return _env("TWILIO_ACCOUNT_SID")


def auth_token() -> str:
    return _env("TWILIO_AUTH_TOKEN")


def from_number() -> str:
    return _env("TWILIO_FROM_NUMBER") or _env("TWILIO_PHONE_NUMBER")


def messaging_service_sid() -> str:
    return _env("TWILIO_MESSAGING_SERVICE_SID")


def to_number() -> str:
    return _env("SMS_CODE_TO") or _env("TWILIO_TO_NUMBER")


def configured() -> bool:
    sender_ok = bool(messaging_service_sid() or from_number())
    return bool(account_sid() and auth_token() and sender_ok and to_number())


def normalize_e164(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if raw.startswith("+"):
        digits = re.sub(r"\D+", "", raw)
        return f"+{digits}" if digits else ""
    digits = re.sub(r"\D+", "", raw)
    if len(digits) == 10:
        return f"+1{digits}"
    if len(digits) == 11 and digits.startswith("1"):
        return f"+{digits}"
    return f"+{digits}" if digits else ""


def mask_e164(value: str) -> str:
    e164 = normalize_e164(value)
    if len(e164) < 6:
        return "••••"
    return f"{e164[:3]}••••{e164[-2:]}"


def send_sms(body: str, *, to: str | None = None) -> dict[str, Any]:
    """Send one SMS via Twilio Messages API. Raises RuntimeError on failure."""
    sid = account_sid()
    token = auth_token()
    sender = normalize_e164(from_number())
    service = messaging_service_sid()
    dest = normalize_e164(to or to_number())
    if not (sid and token and dest and (service or sender)):
        raise RuntimeError(
            "Twilio SMS not configured "
            "(set TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, SMS_CODE_TO, and "
            "TWILIO_MESSAGING_SERVICE_SID or TWILIO_FROM_NUMBER in the portal "
            "env or /opt/truemail/.env)"
        )
    text = str(body or "").strip()
    if not text:
        raise ValueError("SMS body is empty")

    url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
    fields: dict[str, str] = {"To": dest, "Body": text}
    # Prefer Messaging Service (A2P / campaign routing) when configured.
    if service:
        fields["MessagingServiceSid"] = service
    else:
        fields["From"] = sender
    form = urllib.parse.urlencode(fields).encode("utf-8")
    req = urllib.request.Request(url, data=form, method="POST")
    basic = base64.b64encode(f"{sid}:{token}".encode("utf-8")).decode("ascii")
    req.add_header("Authorization", f"Basic {basic}")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            status = int(getattr(resp, "status", 200) or 200)
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8", errors="replace")[:300]
        except Exception:
            detail = str(exc.reason or exc)
        raise RuntimeError(f"Twilio SMS failed ({exc.code}): {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Twilio SMS unreachable: {exc.reason}") from exc

    message_sid = ""
    try:
        import json

        data = json.loads(raw) if raw else {}
        if isinstance(data, dict):
            message_sid = str(data.get("sid") or "")
    except Exception:
        data = {}
    if status >= 400:
        raise RuntimeError(f"Twilio SMS failed ({status}): {raw[:300]}")
    return {
        "ok": True,
        "sid": message_sid,
        "to": dest,
        "from": sender,
        "messaging_service_sid": service,
        "status": status,
    }
