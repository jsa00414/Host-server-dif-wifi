#!/usr/bin/env python3
"""Pending enroll secrets must not unlock portal; burns persist."""
from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

import server
from sm import auth as sm_auth


class TestPendingTotpNotForLogin(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        root = Path(self._tmpdir.name)
        sm_auth.PANEL_DIR = root
        sm_auth.ENROLL_VAULT_PATH = root / "enroll-secrets.enc"
        sm_auth.ENROLL_VAULT_KEY_PATH = root / "enroll-vault.key"
        with server._totp_used_lock:
            server._totp_used.clear()

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_pending_excluded_from_login_secrets(self) -> None:
        row = sm_auth.generate_enroll_secret(for_ip="192.168.8.50", ttl_seconds=900)
        secrets = sm_auth.list_verifiable_totp_secrets(include_pending=False)
        self.assertNotIn(
            row["secret"].upper().replace(" ", ""),
            [s.upper().replace(" ", "") for s in secrets],
        )

    def test_pending_included_when_requested_and_fresh(self) -> None:
        row = sm_auth.generate_enroll_secret(for_ip="192.168.8.50", ttl_seconds=900)
        secrets = sm_auth.list_verifiable_totp_secrets(include_pending=True)
        self.assertIn(
            row["secret"].upper().replace(" ", ""),
            [s.upper().replace(" ", "") for s in secrets],
        )

    def test_expired_pending_revoked(self) -> None:
        row = sm_auth.generate_enroll_secret(for_ip="192.168.8.50", ttl_seconds=900)
        vault = sm_auth.read_enroll_vault()
        for r in vault["secrets"]:
            if r.get("id") == row["id"]:
                r["expires_at"] = int(time.time()) - 10
        sm_auth.write_enroll_vault(vault)
        n = sm_auth.purge_expired_pending_secrets()
        self.assertGreaterEqual(n, 1)
        secrets = sm_auth.list_verifiable_totp_secrets(include_pending=True)
        self.assertNotIn(
            row["secret"].upper().replace(" ", ""),
            [s.upper().replace(" ", "") for s in secrets],
        )


class TestLoginStep2IpBind(unittest.TestCase):
    def setUp(self) -> None:
        with server._pending_logins_lock:
            server._pending_logins.clear()
        with server._totp_used_lock:
            server._totp_used.clear()

    def test_complete_rejects_ip_change(self) -> None:
        token = "tok-test-ip"
        now = time.time()
        with server._pending_logins_lock:
            server._pending_logins[token] = {
                "exp": now + 300,
                "user": "admin",
                "ip": "192.168.8.243",
                "method": "email",
                "passkey_ok": False,
            }
        with self.assertRaises(PermissionError):
            server.complete_portal_login(
                login_token=token,
                code="123456",
                client_ip="10.9.0.5",
                circle_lease_ok=True,
            )


class TestTotpBurnPersist(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        server.TOTP_USED_PATH = Path(self._tmpdir.name) / "totp-used.json"
        with server._totp_used_lock:
            server._totp_used.clear()

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_burn_written_to_disk(self) -> None:
        secret = "JBSWY3DPEHPK3PXP"
        code = server._totp_at(secret, time.time())
        self.assertTrue(
            server.verify_and_consume_totp(secret, code, purpose="portal-login")
        )
        self.assertTrue(server.TOTP_USED_PATH.is_file())
        data = json.loads(server.TOTP_USED_PATH.read_text())
        self.assertTrue(data.get("used"))


if __name__ == "__main__":
    unittest.main()
