"""
Unit Tests for TextParser Service.
Validates detection across 5 fraud taxonomies, O(N) linear time complexity,
and ReDoS immunity under pathological load.
"""

import os
import sys
import time
import unittest

# Ensure workspace root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.services.text_parser import TextParser


class TestTextParser(unittest.TestCase):
    """Test suite for TextParser linguistic fraud extraction."""

    def setUp(self):
        self.parser = TextParser()

    def test_equipment_scam_detection(self):
        """Validates detection of pay-for-equipment phishing patterns."""
        text = (
            "Congratulations on your new position. We will send you a reimbursement check "
            "for equipment to buy home office hardware from our approved vendor."
        )
        result = self.parser.analyze_text(text)
        self.assertGreater(len(result.equipment_flags), 0)
        self.assertTrue(any("approved" in f.lower() or "check" in f.lower() for f in result.equipment_flags))

    def test_advance_fee_detection(self):
        """Validates detection of upfront security deposits and screening fees."""
        text = (
            "To complete onboarding, please remit a refundable security deposit "
            "of $250 for your background check fee and training materials."
        )
        result = self.parser.analyze_text(text)
        self.assertGreater(len(result.deposit_flags), 0)
        self.assertTrue(any("security deposit" in f.lower() or "background check" in f.lower() for f in result.deposit_flags))

    def test_financial_keywords_detection(self):
        """Validates exact detection of high-risk payment channels."""
        text = "Please send funds via wire transfer, western union, bitcoin, or zelle immediately."
        result = self.parser.analyze_text(text)
        self.assertIn("wire transfer", result.financial_keywords_found)
        self.assertIn("western union", result.financial_keywords_found)
        self.assertIn("bitcoin", result.financial_keywords_found)
        self.assertIn("zelle", result.financial_keywords_found)
        self.assertEqual(result.financial_keyword_count, 4)

    def test_urgency_and_coercion_detection(self):
        """Validates detection of artificial deadlines and pressure tactics."""
        text = "Immediate action required within 24 hours or offer void. Strictly confidential."
        result = self.parser.analyze_text(text)
        self.assertGreater(len(result.urgency_flags), 0)

    def test_webmail_recruiter_detection(self):
        """Validates detection of free webmail recruiter address impersonation."""
        text = "Send your signed acceptance to hr.department.google@gmail.com and recruit@yahoo.com."
        result = self.parser.analyze_text(text)
        self.assertIn("gmail", result.webmail_flags)
        self.assertIn("yahoo", result.webmail_flags)
        self.assertEqual(len(result.webmail_flags), 2)

    def test_redos_immunity_and_linear_performance(self):
        """
        Validates O(N) linear time complexity and ReDoS immunity under pathological load.
        Processes 150,000+ characters of repeating deceptive phrasing in under 0.5s.
        """
        pathological_block = (
            "approved vendor will deliver upon payment check to buy home office laptop "
            "reimbursement check for equipment refundable security deposit "
        )
        large_text = pathological_block * 1500  # ~165,000 characters
        self.assertGreater(len(large_text), 150000)

        start_time = time.perf_counter()
        result = self.parser.analyze_text(large_text)
        elapsed = time.perf_counter() - start_time

        # Must execute in under 0.5 seconds on any standard CPU
        self.assertLess(
            elapsed,
            0.5,
            f"Possible ReDoS vulnerability detected! Parsing took {elapsed:.4f}s"
        )
        self.assertGreater(len(result.equipment_flags), 0)
        self.assertGreater(len(result.deposit_flags), 0)


if __name__ == "__main__":
    unittest.main()
