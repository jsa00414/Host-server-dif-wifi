"""Portal auth helpers: login notify, encrypted enroll secrets, WebAuthn passkeys."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any, Callable

from cryptography.fernet import Fernet, InvalidToken

PANEL_DIR = Path(
    os.environ.get("SERVERMANAGER_PANEL_DIR", "/opt/servermanager/panel")
)
ENROLL_VAULT_PATH = Path(
    os.environ.get(
        "ENROLL_SECRETS_VAULT_PATH",
        str(PANEL_DIR / "enroll-secrets.enc"),
    )
)
ENROLL_VAULT_KEY_PATH = Path(
    os.environ.get(
        "ENROLL_SECRETS_KEY_PATH",
        str(PANEL_DIR / "enroll-vault.key"),
    )
)
WEBAUTHN_CREDS_PATH = Path(
    os.environ.get(
        "WEBAUTHN_CREDENTIALS_PATH",
        str(PANEL_DIR / "webauthn-credentials.json"),
    )
)
LOGIN_NOTIFY_TO = os.environ.get(
    "PORTAL_LOGIN_NOTIFY_TO",
    os.environ.get("EMAIL_CODE_TO", "portalvpsserver@truemailor.com"),
).strip()
RP_ID = os.environ.get("WEBAUTHN_RP_ID", "portal.vpstruelord.com").strip() or "portal.vpstruelord.com"
RP_NAME = os.environ.get("WEBAUTHN_RP_NAME", "ServerManager").strip() or "ServerManager"
ORIGIN = os.environ.get(
    "WEBAUTHN_ORIGIN", f"https://{RP_ID}"
).strip() or f"https://{RP_ID}"

_vault_lock = threading.Lock()
_webauthn_lock = threading.Lock()
_webauthn_challenges: dict[str, dict] = {}


def _b32_encode_secret(raw: bytes) -> str:
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def _ensure_panel_dir() -> None:
    PANEL_DIR.mkdir(parents=True, exist_ok=True)


def _load_or_create_vault_key() -> bytes:
    _ensure_panel_dir()
    if ENROLL_VAULT_KEY_PATH.is_file():
        key = ENROLL_VAULT_KEY_PATH.read_bytes().strip()
        if key:
            return key
    key = Fernet.generate_key()
    ENROLL_VAULT_KEY_PATH.write_bytes(key + b"\n")
    try:
        os.chmod(ENROLL_VAULT_KEY_PATH, 0o600)
    except Exception:
        pass
    return key


def _fernet() -> Fernet:
    return Fernet(_load_or_create_vault_key())


def _empty_vault() -> dict:
    return {"version": 1, "secrets": [], "updated_at": int(time.time())}


def read_enroll_vault() -> dict:
    """Decrypt and return the enroll-secrets vault (never log contents)."""
    with _vault_lock:
        if not ENROLL_VAULT_PATH.is_file():
            return _empty_vault()
        try:
            raw = ENROLL_VAULT_PATH.read_bytes()
            plain = _fernet().decrypt(raw)
            data = json.loads(plain.decode("utf-8"))
            if not isinstance(data, dict):
                return _empty_vault()
            secrets_list = data.get("secrets")
            if not isinstance(secrets_list, list):
                data["secrets"] = []
            return data
        except (InvalidToken, json.JSONDecodeError, OSError, ValueError):
            return _empty_vault()


def write_enroll_vault(data: dict) -> None:
    payload = {
        "version": 1,
        "secrets": list(data.get("secrets") or []),
        "updated_at": int(time.time()),
    }
    blob = _fernet().encrypt(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    _ensure_panel_dir()
    tmp = ENROLL_VAULT_PATH.with_suffix(".tmp")
    with _vault_lock:
        tmp.write_bytes(blob)
        try:
            os.chmod(tmp, 0o600)
        except Exception:
            pass
        tmp.replace(ENROLL_VAULT_PATH)
        try:
            os.chmod(ENROLL_VAULT_PATH, 0o600)
        except Exception:
            pass


def ensure_legacy_secret_in_vault(legacy_secret: str, *, label: str = "primary") -> dict:
    """Import the current panel TOTP secret into the encrypted vault if missing."""
    secret = str(legacy_secret or "").strip().upper().replace(" ", "")
    vault = read_enroll_vault()
    if not secret:
        return vault
    for row in vault.get("secrets") or []:
        if not isinstance(row, dict):
            continue
        if str(row.get("secret") or "").strip().upper().replace(" ", "") == secret:
            return vault
    vault.setdefault("secrets", []).append(
        {
            "id": f"s_{secrets.token_hex(6)}",
            "secret": secret,
            "label": label,
            "status": "enrolled",
            "created_at": int(time.time()),
            "enroll_for_ip": "",
            "enrolled_device_ip": "",
            "enrolled_at": int(time.time()),
        }
    )
    write_enroll_vault(vault)
    return vault


def generate_enroll_secret(
    *,
    for_ip: str = "",
    label: str = "",
    ttl_seconds: int = 900,
) -> dict:
    """Create a new random TOTP secret for a pending enroll; keep existing rows.

    Pending secrets expire with ``expires_at`` so abandoned QR enrolls cannot
    mint portal sessions forever.
    """
    vault = read_enroll_vault()
    # Drop expired pending before adding a new one.
    purge_expired_pending_secrets(vault=vault, persist=False)
    secret = _b32_encode_secret(secrets.token_bytes(20))
    now = int(time.time())
    ttl = max(60, int(ttl_seconds or 900))
    row = {
        "id": f"s_{secrets.token_hex(6)}",
        "secret": secret,
        "label": (label or f"enroll-{time.strftime('%Y%m%d-%H%M%S')}").strip()[:80],
        "status": "pending",
        "created_at": now,
        "expires_at": now + ttl,
        "enroll_for_ip": str(for_ip or "").strip(),
        "enrolled_device_ip": "",
        "enrolled_at": 0,
    }
    vault.setdefault("secrets", []).append(row)
    # Cap growth; keep enrolled/active + newest pending.
    kept: list[dict] = []
    for item in vault["secrets"]:
        if not isinstance(item, dict):
            continue
        st = str(item.get("status") or "")
        if st in ("enrolled", "active", "pending"):
            kept.append(item)
    vault["secrets"] = kept[-40:]
    write_enroll_vault(vault)
    return row


def purge_expired_pending_secrets(
    *,
    vault: dict | None = None,
    persist: bool = True,
    now: int | None = None,
) -> int:
    """Revoke pending enroll secrets past expires_at. Returns count revoked."""
    data = vault if isinstance(vault, dict) else read_enroll_vault()
    ts = int(time.time() if now is None else now)
    changed = 0
    for row in data.get("secrets") or []:
        if not isinstance(row, dict):
            continue
        if str(row.get("status") or "") != "pending":
            continue
        exp = int(row.get("expires_at") or 0)
        # Legacy pending without expires_at: treat as already expired.
        if exp <= 0 or exp <= ts:
            row["status"] = "expired"
            row["expired_at"] = ts
            changed += 1
    if changed and persist:
        write_enroll_vault(data)
    return changed


def revoke_all_pending_secrets() -> int:
    """Force-revoke every pending enroll secret (unlock window closed)."""
    vault = read_enroll_vault()
    ts = int(time.time())
    changed = 0
    for row in vault.get("secrets") or []:
        if not isinstance(row, dict):
            continue
        if str(row.get("status") or "") != "pending":
            continue
        row["status"] = "expired"
        row["expired_at"] = ts
        changed += 1
    if changed:
        write_enroll_vault(vault)
    return changed


def mark_enroll_secret_enrolled(*, secret: str = "", for_ip: str = "", device_ip: str = "") -> bool:
    """Mark a pending vault secret as fully enrolled (keeps ciphertext list intact)."""
    want_secret = str(secret or "").strip().upper().replace(" ", "")
    want_ip = str(for_ip or device_ip or "").strip()
    vault = read_enroll_vault()
    changed = False
    now = int(time.time())
    for row in vault.get("secrets") or []:
        if not isinstance(row, dict):
            continue
        sec = str(row.get("secret") or "").strip().upper().replace(" ", "")
        if want_secret and sec != want_secret:
            continue
        if want_ip and str(row.get("enroll_for_ip") or "").strip() not in ("", want_ip):
            if str(row.get("enroll_for_ip") or "").strip() != want_ip:
                continue
        if str(row.get("status") or "") == "pending" or want_secret:
            row["status"] = "enrolled"
            row["enrolled_at"] = now
            row["enrolled_device_ip"] = str(device_ip or want_ip or row.get("enrolled_device_ip") or "")
            changed = True
            if want_secret:
                break
    if changed:
        write_enroll_vault(vault)
    return changed


def list_verifiable_totp_secrets(
    legacy_secret: str = "",
    *,
    include_pending: bool = False,
) -> list[str]:
    """Secrets that may satisfy TOTP checks (legacy + vault).

    Pending enroll secrets are excluded by default — they must not unlock
    portal login. Pass ``include_pending=True`` only during an active enroll
    unlock window (auth-app APIs).
    """
    purge_expired_pending_secrets()
    out: list[str] = []
    legacy = str(legacy_secret or "").strip().upper().replace(" ", "")
    if legacy:
        out.append(legacy)
    allowed = ("enrolled", "active", "pending") if include_pending else ("enrolled", "active")
    now = int(time.time())
    for row in read_enroll_vault().get("secrets") or []:
        if not isinstance(row, dict):
            continue
        st = str(row.get("status") or "")
        if st not in allowed:
            continue
        if st == "pending":
            exp = int(row.get("expires_at") or 0)
            if exp <= 0 or exp <= now:
                continue
        sec = str(row.get("secret") or "").strip().upper().replace(" ", "")
        if sec and sec not in out:
            out.append(sec)
    return out


def vault_public_summary() -> dict:
    """Safe metadata for Security UI (no raw secrets)."""
    rows = []
    for row in read_enroll_vault().get("secrets") or []:
        if not isinstance(row, dict):
            continue
        rows.append(
            {
                "id": str(row.get("id") or ""),
                "label": str(row.get("label") or ""),
                "status": str(row.get("status") or ""),
                "created_at": int(row.get("created_at") or 0),
                "enroll_for_ip": str(row.get("enroll_for_ip") or ""),
                "enrolled_device_ip": str(row.get("enrolled_device_ip") or ""),
                "enrolled_at": int(row.get("enrolled_at") or 0),
            }
        )
    return {
        "count": len(rows),
        "enrolled": sum(1 for r in rows if r["status"] == "enrolled"),
        "pending": sum(1 for r in rows if r["status"] == "pending"),
        "encrypted": ENROLL_VAULT_PATH.is_file(),
        "secrets": rows,
    }


def send_portal_login_email(
    *,
    client_ip: str,
    user: str,
    method: str,
    smtp_send: Callable[..., None],
    to_addr: str | None = None,
) -> None:
    """Notify operator mailbox that someone signed into the portal."""
    to = (to_addr or LOGIN_NOTIFY_TO).strip()
    if not to:
        return
    when = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    ip = str(client_ip or "unknown").strip() or "unknown"
    meth = str(method or "unknown")
    subject = f"ServerManager portal login from {ip}"
    body = (
        f"Portal sign-in succeeded.\n\n"
        f"User: {user}\n"
        f"IP: {ip}\n"
        f"2FA method: {meth}\n"
        f"Time: {when}\n\n"
        f"If this was not you, lock the panel and rotate credentials.\n"
    )
    html = (
        f"<p><strong>Portal sign-in succeeded</strong></p>"
        f"<ul><li>User: {user}</li><li>IP: {ip}</li>"
        f"<li>2FA: {meth}</li><li>Time: {when}</li></ul>"
        f"<p>If this was not you, lock the panel and rotate credentials.</p>"
    )
    smtp_send(to_addr=to, subject=subject, body=body, html=html)


# --- WebAuthn / passkeys -------------------------------------------------


def _read_webauthn_store() -> dict:
    if not WEBAUTHN_CREDS_PATH.is_file():
        return {"credentials": []}
    try:
        data = json.loads(WEBAUTHN_CREDS_PATH.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("credentials"), list):
            return data
    except Exception:
        pass
    return {"credentials": []}


def _write_webauthn_store(data: dict) -> None:
    _ensure_panel_dir()
    payload = {"credentials": list(data.get("credentials") or []), "updated_at": int(time.time())}
    WEBAUTHN_CREDS_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    try:
        os.chmod(WEBAUTHN_CREDS_PATH, 0o600)
    except Exception:
        pass


def webauthn_status() -> dict:
    store = _read_webauthn_store()
    creds = [c for c in store.get("credentials") or [] if isinstance(c, dict)]
    return {
        "enabled": True,
        "rp_id": RP_ID,
        "origin": ORIGIN,
        "credential_count": len(creds),
        "credentials": [
            {
                "id": str(c.get("id") or "")[:32],
                "name": str(c.get("name") or "passkey"),
                "created_at": int(c.get("created_at") or 0),
            }
            for c in creds
        ],
    }


def begin_webauthn_registration(*, user_id: str, user_name: str) -> dict:
    from webauthn import generate_registration_options, options_to_json
    from webauthn.helpers.structs import (
        AuthenticatorSelectionCriteria,
        ResidentKeyRequirement,
        UserVerificationRequirement,
    )

    opts = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=user_id.encode("utf-8")[:32],
        user_name=user_name,
        user_display_name=user_name,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )
    challenge_b64 = base64.urlsafe_b64encode(opts.challenge).decode("ascii").rstrip("=")
    with _webauthn_lock:
        _webauthn_challenges[challenge_b64] = {
            "type": "reg",
            "exp": time.time() + 300,
            "challenge": opts.challenge,
            "user_id": user_id,
        }
    return json.loads(options_to_json(opts))


def finish_webauthn_registration(*, credential: dict, name: str = "") -> dict:
    from webauthn import verify_registration_response
    from webauthn.helpers import base64url_to_bytes

    if not isinstance(credential, dict):
        raise ValueError("Invalid passkey credential")
    resp = credential.get("response") if isinstance(credential.get("response"), dict) else {}
    client_data = base64url_to_bytes(str(resp.get("clientDataJSON") or ""))
    # Parse challenge from clientDataJSON
    client = json.loads(client_data.decode("utf-8"))
    challenge_b64 = str(client.get("challenge") or "").rstrip("=")
    with _webauthn_lock:
        pending = _webauthn_challenges.pop(challenge_b64, None)
    if not pending or pending.get("type") != "reg" or float(pending.get("exp") or 0) < time.time():
        raise ValueError("Passkey registration challenge expired")
    verification = verify_registration_response(
        credential=credential,
        expected_challenge=pending["challenge"],
        expected_rp_id=RP_ID,
        expected_origin=ORIGIN,
    )
    cred_id = base64.urlsafe_b64encode(verification.credential_id).decode("ascii").rstrip("=")
    store = _read_webauthn_store()
    store.setdefault("credentials", [])
    # Replace same id if re-registered
    store["credentials"] = [
        c for c in store["credentials"] if isinstance(c, dict) and str(c.get("id")) != cred_id
    ]
    store["credentials"].append(
        {
            "id": cred_id,
            "name": (name or "passkey").strip()[:80] or "passkey",
            "public_key": base64.urlsafe_b64encode(verification.credential_public_key).decode("ascii"),
            "sign_count": int(verification.sign_count or 0),
            "created_at": int(time.time()),
        }
    )
    _write_webauthn_store(store)
    return {"ok": True, "id": cred_id, "message": "Passkey registered.", **webauthn_status()}


def begin_webauthn_authentication() -> dict:
    from webauthn import generate_authentication_options, options_to_json
    from webauthn.helpers.structs import UserVerificationRequirement

    store = _read_webauthn_store()
    if not store.get("credentials"):
        raise ValueError("No passkeys registered")
    allow = []
    from webauthn.helpers.structs import PublicKeyCredentialDescriptor
    from webauthn.helpers import base64url_to_bytes

    for c in store["credentials"]:
        if not isinstance(c, dict) or not c.get("id"):
            continue
        allow.append(
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(str(c["id"])))
        )
    opts = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=allow or None,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    challenge_b64 = base64.urlsafe_b64encode(opts.challenge).decode("ascii").rstrip("=")
    with _webauthn_lock:
        _webauthn_challenges[challenge_b64] = {
            "type": "auth",
            "exp": time.time() + 300,
            "challenge": opts.challenge,
        }
    return json.loads(options_to_json(opts))


def finish_webauthn_authentication(*, credential: dict) -> dict:
    from webauthn import verify_authentication_response
    from webauthn.helpers import base64url_to_bytes

    if not isinstance(credential, dict):
        raise ValueError("Invalid passkey assertion")
    resp = credential.get("response") if isinstance(credential.get("response"), dict) else {}
    client = json.loads(base64url_to_bytes(str(resp.get("clientDataJSON") or "")).decode("utf-8"))
    challenge_b64 = str(client.get("challenge") or "").rstrip("=")
    with _webauthn_lock:
        pending = _webauthn_challenges.pop(challenge_b64, None)
    if not pending or pending.get("type") != "auth" or float(pending.get("exp") or 0) < time.time():
        raise ValueError("Passkey challenge expired")
    cred_id = str(credential.get("id") or "").rstrip("=")
    store = _read_webauthn_store()
    match = None
    for c in store.get("credentials") or []:
        if isinstance(c, dict) and str(c.get("id") or "").rstrip("=") == cred_id:
            match = c
            break
    if not match:
        raise ValueError("Unknown passkey")
    verification = verify_authentication_response(
        credential=credential,
        expected_challenge=pending["challenge"],
        expected_rp_id=RP_ID,
        expected_origin=ORIGIN,
        credential_public_key=base64url_to_bytes(str(match["public_key"])),
        credential_current_sign_count=int(match.get("sign_count") or 0),
    )
    match["sign_count"] = int(verification.new_sign_count or 0)
    _write_webauthn_store(store)
    return {"ok": True, "credential_id": cred_id}


def remove_webauthn_credential(cred_id: str) -> dict:
    want = str(cred_id or "").strip().rstrip("=")
    store = _read_webauthn_store()
    before = len(store.get("credentials") or [])
    store["credentials"] = [
        c
        for c in (store.get("credentials") or [])
        if not (isinstance(c, dict) and str(c.get("id") or "").rstrip("=") == want)
    ]
    if len(store["credentials"]) == before:
        raise ValueError("Passkey not found")
    _write_webauthn_store(store)
    return {"ok": True, "message": "Passkey removed.", **webauthn_status()}
