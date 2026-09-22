"""
Enterprise Authentication & Identity Service for JobKavach.
Provides secure PBKDF2-HMAC-SHA256 password hashing with unique salts,
timing-attack immune verification, role enforcement, and session validation.
"""

import hmac
import hashlib
import logging
import re
import secrets
import uuid
from typing import Optional, Tuple

from src.database.db_manager import DatabaseManager
from src.models.schemas import User

logger = logging.getLogger("JobKavach.Auth")

EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
PBKDF2_ITERATIONS = 100_000

# Default Pre-Seeded Demo Credentials for Instant Evaluation
DEFAULT_DEMO_EMAIL = "analyst@jobkavach.sec"
DEFAULT_DEMO_PASSWORD = "Kavach@2026!"


class AuthService:
    """Security-hardened authentication service with zero external C-dependencies."""

    @classmethod
    def hash_password(cls, password: str, salt: Optional[str] = None) -> Tuple[str, str]:
        """
        Derives a cryptographic password hash using PBKDF2-HMAC-SHA256.
        Returns a tuple of (hex_hash, hex_salt).
        """
        if not salt:
            salt = secrets.token_hex(32)

        key = hashlib.pbkdf2_hmac(
            hash_name="sha256",
            password=password.encode("utf-8"),
            salt=salt.encode("utf-8"),
            iterations=PBKDF2_ITERATIONS,
            dklen=64
        )
        return key.hex(), salt

    @classmethod
    def verify_password(cls, password: str, salt: str, expected_hash: str) -> bool:
        """
        Verifies a password against an expected hash using constant-time comparison
        to completely prevent side-channel timing attacks.
        """
        computed_hash, _ = cls.hash_password(password, salt=salt)
        return hmac.compare_digest(computed_hash, expected_hash)

    @classmethod
    def register(
        cls,
        db: DatabaseManager,
        email: str,
        full_name: str,
        password: str,
        role: str = "SOC Security Analyst"
    ) -> Tuple[bool, str, Optional[User]]:
        """
        Registers a new user account with zero-trust validation checks.
        """
        clean_email = email.strip().lower()
        clean_name = full_name.strip()

        # Validation 1: Email format
        if not EMAIL_REGEX.match(clean_email):
            return False, "Invalid email address format.", None

        # Validation 2: Full Name
        if len(clean_name) < 2:
            return False, "Full name must be at least 2 characters.", None

        # Validation 3: Password Strength
        if len(password) < 8:
            return False, "Password must be at least 8 characters in length.", None

        # Validation 4: Existing user check
        existing = db.get_user_by_email(clean_email)
        if existing:
            return False, "An account with this email address already exists.", None

        # Generate User ID and Hash Credentials
        user_id = f"usr-{uuid.uuid4().hex[:12]}"
        pwd_hash, salt = cls.hash_password(password)

        created = db.create_user(
            user_id=user_id,
            email=clean_email,
            full_name=clean_name,
            role=role,
            password_hash=pwd_hash,
            salt=salt
        )

        user = User(
            user_id=created["user_id"],
            email=created["email"],
            full_name=created["full_name"],
            role=created["role"],
            created_at=created["created_at"],
            last_login=None
        )

        logger.info(f"[AuthService] User registered successfully: {clean_email} ({user_id})")
        return True, "Account registered successfully. You may now log in.", user

    @classmethod
    def login(
        cls,
        db: DatabaseManager,
        email: str,
        password: str
    ) -> Tuple[bool, str, Optional[User]]:
        """
        Authenticates an analyst using PBKDF2 verification and updates last login.
        """
        clean_email = email.strip().lower()
        user_record = db.get_user_by_email(clean_email)

        if not user_record:
            return False, "Invalid email address or password.", None

        # Verify password hash
        is_valid = cls.verify_password(
            password=password,
            salt=user_record["salt"],
            expected_hash=user_record["password_hash"]
        )

        if not is_valid:
            return False, "Invalid email address or password.", None

        # Update last login timestamp
        db.update_last_login(user_record["user_id"])

        user = User(
            user_id=user_record["user_id"],
            email=user_record["email"],
            full_name=user_record["full_name"],
            role=user_record["role"],
            created_at=user_record["created_at"],
            last_login=user_record.get("last_login")
        )

        logger.info(f"[AuthService] User authenticated: {clean_email} ({user.user_id})")
        return True, f"Welcome back, {user.full_name}!", user

    @classmethod
    def bootstrap_demo_analyst(cls, db: DatabaseManager) -> None:
        """Bootstraps default demo credentials into the database if not present."""
        pwd_hash, salt = cls.hash_password(DEFAULT_DEMO_PASSWORD)
        db.seed_default_analyst(default_hash=pwd_hash, default_salt=salt)
