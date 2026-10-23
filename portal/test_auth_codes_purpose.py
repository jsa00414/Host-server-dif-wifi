#!/usr/bin/env python3
"""Purpose-scoped auth codes: one TOTP cannot unlock login and Settings."""
from __future__ import annotations

import time
import unittest

import server


class TestTotpPurposeConsume(unittest.TestCase):
    def setUp(self) -> None:
        with server._totp_used_lock:
            server._totp_used.clear()

    def test_same_code_cannot_cross_login_and_settings(self) -> None:
        # Fixed Base32 secret (RFC 6238 test vector family).
        secret = "JBSWY3DPEHPK3PXP"
        code = server._totp_at(secret, time.time())
        self.assertTrue(
            server.verify_and_consume_totp(secret, code, purpose="portal-login")
        )
        self.assertFalse(
            server.verify_and_consume_totp(secret, code, purpose="ssh-unlock"),
            "Settings unlock must reject a code already used for portal login",
        )

    def test_same_code_cannot_reuse_same_purpose(self) -> None:
        secret = "JBSWY3DPEHPK3PXP"
        code = server._totp_at(secret, time.time())
        self.assertTrue(
            server.verify_and_consume_totp(secret, code, purpose="ssh-unlock")
        )
        self.assertFalse(
            server.verify_and_consume_totp(secret, code, purpose="ssh-unlock")
        )

    def test_wrong_code_rejected(self) -> None:
        secret = "JBSWY3DPEHPK3PXP"
        self.assertFalse(
            server.verify_and_consume_totp(secret, "000000", purpose="portal-login")
        )

    def test_requires_purpose(self) -> None:
        secret = "JBSWY3DPEHPK3PXP"
        code = server._totp_at(secret, time.time())
        self.assertFalse(server.verify_and_consume_totp(secret, code, purpose=""))


class TestEmailPurposeBinding(unittest.TestCase):
    def setUp(self) -> None:
        with server._email_codes_lock:
            server._email_codes.clear()
            server._email_code_last_send.clear()

    def test_login_code_not_valid_for_settings(self) -> None:
        login_key = "portal-login:tok-a"
        unlock_key = "ssh-unlock:tok-b"
        code = "123456"
        now = time.time()
        with server._email_codes_lock:
            server._email_codes[login_key] = {
                "hash": __import__("hashlib").sha256(code.encode()).hexdigest(),
                "expires": now + 600,
                "attempts": 0,
                "purpose": "portal-login",
            }
        with self.assertRaises(ValueError):
            server.verify_email_test_code(
                "1.2.3.4", code, key=unlock_key, purpose="ssh-unlock"
            )
        ok = server.verify_email_test_code(
            "1.2.3.4", code, key=login_key, purpose="portal-login"
        )
        self.assertTrue(ok.get("ok"))

    def test_purpose_mismatch_on_entry(self) -> None:
        key = "portal-login:tok-c"
        code = "654321"
        now = time.time()
        with server._email_codes_lock:
            server._email_codes[key] = {
                "hash": __import__("hashlib").sha256(code.encode()).hexdigest(),
                "expires": now + 600,
                "attempts": 0,
                "purpose": "ssh-unlock",  # wrong purpose stored
            }
        with self.assertRaises(ValueError):
            server.verify_email_test_code(
                "1.2.3.4", code, key=key, purpose="portal-login"
            )

    def test_email_test_key_is_purpose_prefixed(self) -> None:
        # Simulate store write path without SMTP by calling store logic via
        # verifying unknown purpose is rejected.
        with self.assertRaises(ValueError):
            server.send_email_test_code("9.9.9.9", purpose="not-a-real-purpose")


class TestSmsPurposeBinding(unittest.TestCase):
    def setUp(self) -> None:
        with server._sms_codes_lock:
            server._sms_codes.clear()
            server._sms_code_last_send.clear()

    def test_login_sms_not_valid_for_settings(self) -> None:
        login_key = "portal-login:tok-sms-a"
        unlock_key = "ssh-unlock:tok-sms-b"
        code = "112233"
        now = time.time()
        with server._sms_codes_lock:
            server._sms_codes[login_key] = {
                "hash": __import__("hashlib").sha256(code.encode()).hexdigest(),
                "expires": now + 600,
                "attempts": 0,
                "purpose": "portal-login",
            }
        with self.assertRaises(ValueError):
            server.verify_sms_test_code(
                "1.2.3.4", code, key=unlock_key, purpose="ssh-unlock"
            )
        ok = server.verify_sms_test_code(
            "1.2.3.4", code, key=login_key, purpose="portal-login"
        )
        self.assertTrue(ok.get("ok"))

    def test_sms_unknown_purpose_rejected(self) -> None:
        with self.assertRaises(ValueError):
            server.send_sms_test_code("9.9.9.9", purpose="not-a-real-purpose")

    def test_two_factor_code_field(self) -> None:
        self.assertEqual(server._two_factor_code_field("app"), "app_code")
        self.assertEqual(server._two_factor_code_field("sms"), "sms_code")
        self.assertEqual(server._two_factor_code_field("email"), "email_code")


class TestTwilioHelpers(unittest.TestCase):
    def test_normalize_and_mask_e164(self) -> None:
        from sm import twilio_sms as tw

        self.assertEqual(tw.normalize_e164("5551234567"), "+15551234567")
        self.assertEqual(tw.normalize_e164("+1 (555) 123-4567"), "+15551234567")
        masked = tw.mask_e164("+15551234567")
        self.assertTrue(masked.startswith("+15"))
        self.assertIn("••••", masked)
        self.assertTrue(masked.endswith("67"))


if __name__ == "__main__":
    unittest.main()
