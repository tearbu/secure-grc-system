"""Tests for the Secure GRC System.

Covers password hashing, login success and failure, role based access
control in both directions (allowed and denied), audit log writes, audit log
immutability, input validation, and SQL injection safety.

Run with:  python -m unittest discover -s tests -v
"""

import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from grc import auth, db as db_module
from grc.rbac import PermissionDenied
from grc.service import GRCService


class ServiceTestCase(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(prefix="secure-grc-test-",
                                         suffix=".db")
        os.close(fd)
        self.conn = db_module.connect(self.path)
        db_module.init_db(self.conn)
        self.service = GRCService(self.conn)
        self.service.create_user(None, "admin", "admin-test-pass", "Admin")
        self.admin = self.service.login("admin", "admin-test-pass")
        self.service.create_user(self.admin, "analyst", "analyst-test-pass",
                                 "GRC Analyst")
        self.service.create_user(self.admin, "viewer", "viewer-test-pass",
                                 "Viewer")
        self.analyst = self.service.login("analyst", "analyst-test-pass")
        self.viewer = self.service.login("viewer", "viewer-test-pass")

    def tearDown(self):
        self.conn.close()
        os.unlink(self.path)

    def make_risk(self, user=None, title="Test risk"):
        return self.service.create_risk(
            user or self.analyst, title, "desc", "analyst", "Open", "High")


class PasswordHashingTests(unittest.TestCase):
    def test_hash_is_not_plaintext_and_verifies(self):
        stored = auth.hash_password("correct horse battery")
        self.assertNotIn("correct horse", stored)
        self.assertTrue(stored.startswith("scrypt$"))
        self.assertTrue(auth.verify_password("correct horse battery", stored))

    def test_wrong_password_fails_verification(self):
        stored = auth.hash_password("correct horse battery")
        self.assertFalse(auth.verify_password("wrong password", stored))

    def test_same_password_hashes_differently_each_time(self):
        first = auth.hash_password("repeated password")
        second = auth.hash_password("repeated password")
        self.assertNotEqual(first, second)

    def test_short_password_rejected(self):
        with self.assertRaises(ValueError):
            auth.hash_password("short")


class LoginTests(ServiceTestCase):
    def test_login_success_returns_user_with_role(self):
        user = self.service.login("analyst", "analyst-test-pass")
        self.assertIsNotNone(user)
        self.assertEqual(user["role"], "GRC Analyst")

    def test_login_wrong_password_returns_none(self):
        self.assertIsNone(self.service.login("analyst", "not-the-password"))

    def test_login_unknown_user_returns_none(self):
        self.assertIsNone(self.service.login("ghost", "whatever-pass"))

    def test_failed_login_is_audited(self):
        self.service.login("analyst", "not-the-password")
        entries = self.service.get_audit_log(self.admin)
        failures = [e for e in entries
                    if e["action"] == "login" and e["outcome"] == "failure"]
        self.assertTrue(failures)


class RBACTests(ServiceTestCase):
    def test_viewer_can_read(self):
        self.make_risk()
        self.assertEqual(len(self.service.list_risks(self.viewer)), 1)

    def test_viewer_cannot_create(self):
        with self.assertRaises(PermissionDenied):
            self.service.create_risk(self.viewer, "Nope", "", "viewer",
                                     "Open", "Low")

    def test_viewer_cannot_edit(self):
        record_id = self.make_risk()
        with self.assertRaises(PermissionDenied):
            self.service.update_risk(self.viewer, record_id, status="Closed")

    def test_viewer_cannot_read_audit_log(self):
        with self.assertRaises(PermissionDenied):
            self.service.get_audit_log(self.viewer)

    def test_analyst_can_create_and_edit(self):
        record_id = self.make_risk()
        self.service.update_risk(self.analyst, record_id, status="Closed")
        risks = self.service.list_risks(self.analyst)
        self.assertEqual(risks[0]["status"], "Closed")

    def test_analyst_cannot_manage_users(self):
        with self.assertRaises(PermissionDenied):
            self.service.create_user(self.analyst, "extra", "extra-pass-123",
                                     "Viewer")

    def test_admin_can_manage_users(self):
        self.service.create_user(self.admin, "extra", "extra-pass-123",
                                 "Viewer")
        self.assertIsNotNone(self.service.login("extra", "extra-pass-123"))

    def test_denial_is_written_to_audit_log(self):
        try:
            self.service.create_risk(self.viewer, "Nope", "", "viewer",
                                     "Open", "Low")
        except PermissionDenied:
            pass
        entries = self.service.get_audit_log(self.admin)
        denials = [e for e in entries if e["outcome"] == "denied"]
        self.assertTrue(denials)


class AuditLogTests(ServiceTestCase):
    def test_create_writes_audit_entry(self):
        self.make_risk()
        entries = self.service.get_audit_log(self.admin)
        creates = [e for e in entries
                   if e["action"] == "create" and e["entity"] == "risks"]
        self.assertEqual(len(creates), 1)
        self.assertEqual(creates[0]["username"], "analyst")

    def test_audit_log_cannot_be_updated(self):
        self.make_risk()
        with self.assertRaises(sqlite3.Error):
            self.conn.execute(
                "UPDATE audit_log SET outcome = 'hidden' WHERE id = 1")
            self.conn.commit()

    def test_audit_log_cannot_be_deleted(self):
        self.make_risk()
        with self.assertRaises(sqlite3.Error):
            self.conn.execute("DELETE FROM audit_log WHERE id = 1")
            self.conn.commit()


class ValidationAndInjectionTests(ServiceTestCase):
    def test_invalid_severity_rejected(self):
        with self.assertRaises(ValueError):
            self.service.create_risk(self.analyst, "Bad", "", "analyst",
                                     "Open", "Severe-ish")

    def test_empty_title_rejected(self):
        with self.assertRaises(ValueError):
            self.service.create_risk(self.analyst, "   ", "", "analyst",
                                     "Open", "Low")

    def test_injection_string_is_stored_as_inert_data(self):
        payload = "x'); DROP TABLE risks;--"
        self.service.create_risk(self.analyst, payload, "", "analyst",
                                 "Open", "Low")
        risks = self.service.list_risks(self.analyst)
        self.assertEqual(len(risks), 1)
        self.assertEqual(risks[0]["title"], payload)
        count = self.conn.execute(
            "SELECT COUNT(*) AS n FROM risks").fetchone()["n"]
        self.assertEqual(count, 1)

    def test_injection_in_login_does_not_authenticate(self):
        self.assertIsNone(
            self.service.login("analyst' OR '1'='1", "analyst-test-pass"))


if __name__ == "__main__":
    unittest.main()
