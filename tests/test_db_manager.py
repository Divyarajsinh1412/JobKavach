"""
Unit Tests for DatabaseManager Persistence Layer.
Validates SQLite WAL mode, schema initialization, parameterized logging,
audit ledger queries, and summary metrics calculation.
"""

import os
import sys
import unittest

# Ensure workspace root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.database.db_manager import DatabaseManager


class TestDatabaseManager(unittest.TestCase):
    """Test suite for DatabaseManager persistence and audit ledger operations."""

    TEST_DB_PATH = "test_unit_scan_ledger.db"

    def setUp(self):
        """Set up a fresh test database and clear any existing records."""
        self.db = DatabaseManager(db_path=self.TEST_DB_PATH)
        with self.db._get_connection() as conn:
            conn.execute("DELETE FROM scan_ledger;")
            conn.commit()

    def tearDown(self):
        """Clean up records in the test database."""
        with self.db._get_connection() as conn:
            conn.execute("DELETE FROM scan_ledger;")
            conn.commit()

    def test_wal_mode_enabled(self):
        """Validates that SQLite connection operates in WAL (Write-Ahead Logging) mode."""
        with self.db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode;")
            mode = cursor.fetchone()[0]
            self.assertEqual(mode.lower(), "wal")

    def test_log_scan_and_history(self):
        """Validates logging a scan and retrieving it from the audit ledger."""
        row_id = self.db.log_scan(
            scan_type="Full Inspection",
            target_domain="suspicious-recruiting.xyz",
            threat_score=85.0,
            risk_level="CRITICAL",
            detected_flags=["Newly registered domain", "Wire transfer keyword"],
            details={"notes": "Automated unit test record"},
            payload_hash="a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
        )
        self.assertIsNotNone(row_id)
        self.assertGreater(row_id, 0)

        history = self.db.get_history(limit=10)
        self.assertEqual(len(history), 1)
        record = history[0]
        self.assertEqual(record["id"], row_id)
        self.assertEqual(record["target_domain"], "suspicious-recruiting.xyz")
        self.assertEqual(record["threat_score"], 85.0)
        self.assertEqual(record["risk_level"], "CRITICAL")
        self.assertEqual(record["flag_count"], 2)

    def test_summary_metrics(self):
        """Validates aggregation of summary metrics across multiple scan records."""
        self.db.log_scan(
            scan_type="Full Inspection",
            target_domain="critical-domain.xyz",
            threat_score=90.0,
            risk_level="CRITICAL",
            detected_flags=["Flag1"],
            details={},
            payload_hash="hash1"
        )
        self.db.log_scan(
            scan_type="Text Only",
            target_domain=None,
            threat_score=50.0,
            risk_level="SUSPICIOUS",
            detected_flags=["Flag2"],
            details={},
            payload_hash="hash2"
        )
        self.db.log_scan(
            scan_type="Domain Only",
            target_domain="clean-domain.com",
            threat_score=10.0,
            risk_level="LOW RISK",
            detected_flags=[],
            details={},
            payload_hash="hash3"
        )

        metrics = self.db.get_summary_metrics()
        self.assertEqual(metrics["total_scans"], 3)
        self.assertEqual(metrics["critical_scans"], 1)
        self.assertEqual(metrics["suspicious_scans"], 1)
        self.assertEqual(metrics["low_risk_scans"], 1)
        self.assertEqual(metrics["avg_threat_score"], 50.0)

    def test_get_scan_by_id(self):
        """Validates retrieval of a specific record by primary key."""
        row_id = self.db.log_scan(
            scan_type="Text Only",
            target_domain=None,
            threat_score=25.0,
            risk_level="LOW RISK",
            detected_flags=["Low urgency"],
            details={"candidate": "Jane Doe"},
            payload_hash="testhash999"
        )
        record = self.db.get_scan_by_id(row_id)
        self.assertIsNotNone(record)
        self.assertEqual(record["id"], row_id)
        self.assertEqual(record["threat_score"], 25.0)
        self.assertEqual(record["risk_level"], "LOW RISK")


if __name__ == "__main__":
    unittest.main()
