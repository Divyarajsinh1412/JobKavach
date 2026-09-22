"""
Unit Tests for ThreatScoringEngine Service.
Validates exact mathematical weights, clamping boundaries, and severity classifications.
"""

import os
import sys
import unittest

# Ensure workspace root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.models.schemas import TextAnalysisResult, DomainAnalysisResult
from src.services.scoring_engine import ThreatScoringEngine


class TestThreatScoringEngine(unittest.TestCase):
    """Test suite for ThreatScoringEngine mathematical risk calculation."""

    def test_baseline_clean_offer(self):
        """Validates that empty/benign input produces 0% score and LOW RISK."""
        text_res = TextAnalysisResult()
        eval_res = ThreatScoringEngine.evaluate(text_res)
        self.assertEqual(eval_res.score, 0.0)
        self.assertEqual(eval_res.risk_level, "LOW RISK")

    def test_domain_age_weight(self):
        """Validates domain age < 180 days adds exactly +40%."""
        text_res = TextAnalysisResult()
        dom_res = DomainAnalysisResult(domain="new-portal.xyz", is_new_domain=True, domain_age_days=14)
        eval_res = ThreatScoringEngine.evaluate(text_res, dom_res)
        self.assertEqual(eval_res.score, 40.0)
        self.assertEqual(eval_res.risk_level, "SUSPICIOUS")  # 30-69% is SUSPICIOUS

    def test_masked_whois_weight(self):
        """Validates masked WHOIS privacy proxy adds exactly +20%."""
        text_res = TextAnalysisResult()
        dom_res = DomainAnalysisResult(domain="masked.xyz", is_masked=True)
        eval_res = ThreatScoringEngine.evaluate(text_res, dom_res)
        self.assertEqual(eval_res.score, 20.0)
        self.assertEqual(eval_res.risk_level, "LOW RISK")

    def test_financial_keywords_weights(self):
        """Validates each specific financial keyword adds exactly +20%."""
        text_res = TextAnalysisResult(
            financial_keywords_found=["wire transfer", "bitcoin", "zelle"],
            financial_keyword_count=3
        )
        eval_res = ThreatScoringEngine.evaluate(text_res)
        self.assertEqual(eval_res.score, 60.0)  # 20 * 3
        self.assertEqual(eval_res.risk_level, "SUSPICIOUS")

    def test_equipment_advance_fee_weight(self):
        """Validates equipment scam or advance fee patterns add +20%."""
        text_res = TextAnalysisResult(equipment_flags=["check to buy equipment"])
        eval_res = ThreatScoringEngine.evaluate(text_res)
        self.assertEqual(eval_res.score, 20.0)

    def test_webmail_recruiter_weight(self):
        """Validates recruiter webmail impersonation adds exactly +25%."""
        text_res = TextAnalysisResult(webmail_flags=["recruiter@gmail.com"])
        eval_res = ThreatScoringEngine.evaluate(text_res)
        self.assertEqual(eval_res.score, 25.0)

    def test_urgency_demand_weight(self):
        """Validates urgent payment / coercion demands add exactly +15%."""
        text_res = TextAnalysisResult(urgency_flags=["immediate action within 24 hours"])
        eval_res = ThreatScoringEngine.evaluate(text_res)
        self.assertEqual(eval_res.score, 15.0)

    def test_critical_threshold_and_clamping(self):
        """
        Validates compound indicators triggering CRITICAL tier (>=70%)
        and strict capping at 100.0%.
        """
        # 40 (new domain) + 20 (masked) + 40 (2 keywords) + 20 (equipment) + 15 (urgency) = 135% -> Clamped to 100%
        text_res = TextAnalysisResult(
            equipment_flags=["check to buy equipment"],
            financial_keywords_found=["wire transfer", "cashier's check"],
            financial_keyword_count=2,
            urgency_flags=["immediate payment"]
        )
        dom_res = DomainAnalysisResult(
            domain="fake-careers.xyz",
            is_new_domain=True,
            domain_age_days=5,
            is_masked=True
        )
        eval_res = ThreatScoringEngine.evaluate(text_res, dom_res)
        self.assertEqual(eval_res.score, 100.0)
        self.assertEqual(eval_res.risk_level, "CRITICAL")
        self.assertTrue(any("CRITICAL THREAT" in rec for rec in eval_res.recommendations))


if __name__ == "__main__":
    unittest.main()
