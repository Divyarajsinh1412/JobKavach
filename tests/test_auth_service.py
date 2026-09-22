"""
Unit Tests for JobKavach Authentication Service and Identity Persistence.
Validates PBKDF2-HMAC-SHA256 password hashing, salt uniqueness, timing-safe verification,
zero-trust registration rules, and session login.
"""

import os
import unittest

from src.database.db_manager import DatabaseManager
from src.services.auth_service import (
    AuthService,
    DEFAULT_DEMO_EMAIL,
    DEFAULT_DEMO_PASSWORD,
)


class TestAuthService(unittest.TestCase):
    """Test suite for JobKavach AuthService and user management."""

    def setUp(self):
        self.test_db_path = "test_auth_db.db"
        self.db = DatabaseManager(db_path=self.test_db_path)

    def tearDown(self):
        # Clear users table
        try:
            with self.db._get_connection() as conn:
                conn.execute("DELETE FROM users;")
                conn.commit()
        except Exception:
            pass

    def test_hash_and_salt_uniqueness(self):
        """Validates that hashing the same password produces unique cryptographically random salts."""
        password = "SecurePassword123!"
        hash1, salt1 = AuthService.hash_password(password)
        hash2, salt2 = AuthService.hash_password(password)

        self.assertNotEqual(salt1, salt2)
        self.assertNotEqual(hash1, hash2)
        self.assertEqual(len(salt1), 64)  # 32 bytes in hex

    def test_password_verification(self):
        """Validates constant-time password verification."""
        password = "MyComplexPassword@2026"
        pwd_hash, salt = AuthService.hash_password(password)

        # Correct password
        self.assertTrue(AuthService.verify_password(password, salt, pwd_hash))

        # Incorrect password
        self.assertFalse(AuthService.verify_password("WrongPassword@2026", salt, pwd_hash))

    def test_user_registration_success(self):
        """Validates successful user registration and database persistence."""
        success, msg, user = AuthService.register(
            db=self.db,
            email="analyst.test@jobkavach.sec",
            full_name="Sarah Connor",
            password="CyberDefense@99",
            role="Lead Security Analyst"
        )

        self.assertTrue(success)
        self.assertIsNotNone(user)
        self.assertEqual(user.email, "analyst.test@jobkavach.sec")
        self.assertEqual(user.full_name, "Sarah Connor")
        self.assertEqual(user.role, "Lead Security Analyst")

        # Verify record in DB
        db_user = self.db.get_user_by_email("analyst.test@jobkavach.sec")
        self.assertIsNotNone(db_user)
        self.assertEqual(db_user["full_name"], "Sarah Connor")

    def test_registration_validation_rules(self):
        """Validates email format, password length, and duplicate email constraints."""
        # Invalid email
        ok, msg, _ = AuthService.register(self.db, "notanemail", "Name", "Password123", "Analyst")
        self.assertFalse(ok)
        self.assertIn("email", msg.lower())

        # Password too short
        ok, msg, _ = AuthService.register(self.db, "valid@test.com", "Name", "short", "Analyst")
        self.assertFalse(ok)
        self.assertIn("8 characters", msg)

        # Full name too short
        ok, msg, _ = AuthService.register(self.db, "valid@test.com", "A", "Password123", "Analyst")
        self.assertFalse(ok)
        self.assertIn("2 characters", msg)

        # Duplicate email
        AuthService.register(self.db, "dup@test.com", "Original User", "Password123", "Analyst")
        ok, msg, _ = AuthService.register(self.db, "dup@test.com", "Duplicate User", "Password123", "Analyst")
        self.assertFalse(ok)
        self.assertIn("already exists", msg)

    def test_login_success_and_failure(self):
        """Validates authentication flow for valid and invalid credentials."""
        email = "bob.analyst@jobkavach.sec"
        password = "AnalystSecretKey#1"
        AuthService.register(self.db, email, "Bob Vance", password, "SOC Security Analyst")

        # Successful Login
        ok, msg, user = AuthService.login(self.db, email, password)
        self.assertTrue(ok)
        self.assertIsNotNone(user)
        self.assertEqual(user.email, email)

        # Failed Login: Bad password
        ok, msg, user = AuthService.login(self.db, email, "WrongPassword!")
        self.assertFalse(ok)
        self.assertIsNone(user)

        # Failed Login: Non-existent email
        ok, msg, user = AuthService.login(self.db, "nonexistent@jobkavach.sec", password)
        self.assertFalse(ok)
        self.assertIsNone(user)

    def test_bootstrap_demo_analyst(self):
        """Validates bootstrapping of the default evaluation analyst account."""
        AuthService.bootstrap_demo_analyst(self.db)

        # Should be able to log in with default credentials
        ok, msg, user = AuthService.login(self.db, DEFAULT_DEMO_EMAIL, DEFAULT_DEMO_PASSWORD)
        self.assertTrue(ok)
        self.assertIsNotNone(user)
        self.assertEqual(user.email, DEFAULT_DEMO_EMAIL)


if __name__ == "__main__":
    unittest.main()
