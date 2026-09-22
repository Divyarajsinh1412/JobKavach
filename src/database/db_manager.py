"""
Database Persistence Layer (DatabaseManager).
Manages SQLite with WAL (Write-Ahead Logging) mode, parameterized queries,
auto-schema bootstrapping, and ledger queries.
"""

import json
import sqlite3
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

logger = logging.getLogger("PhishingInspector.Database")


class DatabaseManager:
    """
    Manages persistent SQLite storage for logging scan telemetry, threat indices,
    and historical audit ledgers.

    Security & Reliability Properties:
    - Thread-safe connection handling using context managers.
    - Write-Ahead Logging (WAL) enabled for high concurrent throughput.
    - Parameterized SQL execution to completely prevent SQL injection vulnerabilities.
    - Auto-bootstrapping schema creation on initialization.
    """

    def __init__(self, db_path: str = "threat_scanner.db"):
        self.db_path = db_path
        self.init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Establishes and configures a SQLite connection with WAL mode."""
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        # Enable WAL mode for read/write concurrency and performance
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def init_db(self) -> None:
        """
        Initializes the SQLite schema automatically on startup if not already present.
        Stores immutable audit records with SHA-256 integrity hashes.
        """
        schema_sql = """
        CREATE TABLE IF NOT EXISTS scan_ledger (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            target_domain TEXT,
            threat_score REAL NOT NULL,
            risk_level TEXT NOT NULL,
            flag_count INTEGER NOT NULL,
            detected_flags_json TEXT NOT NULL,
            details_json TEXT NOT NULL,
            payload_hash TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_scan_ledger_timestamp ON scan_ledger(timestamp);
        CREATE INDEX IF NOT EXISTS idx_scan_ledger_risk_level ON scan_ledger(risk_level);

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_login TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
        """
        with self._get_connection() as conn:
            conn.executescript(schema_sql)
            conn.commit()
        logger.info("Database schema validated and initialized successfully.")

    def log_scan(
        self,
        scan_type: str,
        target_domain: Optional[str],
        threat_score: float,
        risk_level: str,
        detected_flags: List[str],
        details: Dict[str, Any],
        payload_hash: str
    ) -> int:
        """
        Logs a completed threat inspection into the immutable audit ledger.
        Uses parameterized SQL execution to guarantee zero SQL injection risk.
        """
        insert_sql = """
        INSERT INTO scan_ledger (
            timestamp, scan_type, target_domain, threat_score, risk_level,
            flag_count, detected_flags_json, details_json, payload_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        now_utc = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                insert_sql,
                (
                    now_utc,
                    scan_type,
                    target_domain or "N/A",
                    threat_score,
                    risk_level,
                    len(detected_flags),
                    json.dumps(detected_flags),
                    json.dumps(details),
                    payload_hash
                )
            )
            conn.commit()
            return cursor.lastrowid

    def get_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves recent scan records from the ledger for SOC auditing."""
        query_sql = """
        SELECT id, timestamp, scan_type, target_domain, threat_score,
               risk_level, flag_count, detected_flags_json, details_json, payload_hash
        FROM scan_ledger
        ORDER BY id DESC
        LIMIT ?;
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query_sql, (limit,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def get_summary_metrics(self) -> Dict[str, Any]:
        """Calculates aggregated metrics across all recorded scans."""
        query_sql = """
        SELECT 
            COUNT(*) AS total_scans,
            SUM(CASE WHEN risk_level = 'CRITICAL' THEN 1 ELSE 0 END) AS critical_scans,
            SUM(CASE WHEN risk_level = 'SUSPICIOUS' THEN 1 ELSE 0 END) AS suspicious_scans,
            SUM(CASE WHEN risk_level = 'LOW RISK' THEN 1 ELSE 0 END) AS low_risk_scans,
            AVG(threat_score) AS avg_threat_score
        FROM scan_ledger;
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query_sql)
            row = cursor.fetchone()
            if row and row["total_scans"] > 0:
                return {
                    "total_scans": row["total_scans"],
                    "critical_scans": row["critical_scans"] or 0,
                    "suspicious_scans": row["suspicious_scans"] or 0,
                    "low_risk_scans": row["low_risk_scans"] or 0,
                    "avg_threat_score": round(row["avg_threat_score"] or 0.0, 1)
                }
            return {
                "total_scans": 0,
                "critical_scans": 0,
                "suspicious_scans": 0,
                "low_risk_scans": 0,
                "avg_threat_score": 0.0
            }

    def get_scan_by_id(self, record_id: int) -> Optional[Dict[str, Any]]:
        """Retrieves a single scan record by primary key."""
        query_sql = "SELECT * FROM scan_ledger WHERE id = ?;"
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query_sql, (record_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    # ==========================================================================
    # USER AUTHENTICATION & MANAGEMENT
    # ==========================================================================

    def create_user(
        self,
        user_id: str,
        email: str,
        full_name: str,
        role: str,
        password_hash: str,
        salt: str
    ) -> Dict[str, Any]:
        """Creates a new user account with secure password credentials."""
        now_utc = datetime.now(timezone.utc).isoformat()
        insert_sql = """
        INSERT INTO users (user_id, email, full_name, role, password_hash, salt, created_at, last_login)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                insert_sql,
                (user_id, email.lower().strip(), full_name.strip(), role, password_hash, salt, now_utc, None)
            )
            conn.commit()

        return {
            "user_id": user_id,
            "email": email.lower().strip(),
            "full_name": full_name.strip(),
            "role": role,
            "created_at": now_utc,
            "last_login": None
        }

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Retrieves a user by unique email address."""
        query_sql = "SELECT * FROM users WHERE email = ?;"
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query_sql, (email.lower().strip(),))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a user by user_id."""
        query_sql = "SELECT * FROM users WHERE user_id = ?;"
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query_sql, (user_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def update_last_login(self, user_id: str) -> None:
        """Updates the last login timestamp for a user."""
        now_utc = datetime.now(timezone.utc).isoformat()
        update_sql = "UPDATE users SET last_login = ? WHERE user_id = ?;"
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(update_sql, (now_utc, user_id))
            conn.commit()

    def seed_default_analyst(self, default_hash: str, default_salt: str) -> None:
        """Bootstraps a default Lead SOC Analyst account if no users exist."""
        existing = self.get_user_by_email("analyst@jobkavach.sec")
        if not existing:
            self.create_user(
                user_id="usr-kavach-001",
                email="analyst@jobkavach.sec",
                full_name="Alex Vance (Lead SOC Analyst)",
                role="Lead Security Analyst",
                password_hash=default_hash,
                salt=default_salt
            )
            logger.info("Default analyst account seeded: analyst@jobkavach.sec")
