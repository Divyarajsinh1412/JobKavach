"""
Unit Tests for ExplainabilityEngine (XAI Service).
Validates SHAP-style feature attributions, algorithmic decision confidence,
counterfactual 'what-if' reasoning, forensic narrative generation, and XSS sanitization.
"""

import os
import sys
import unittest

# Ensure workspace root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.models.schemas import (
    TextAnalysisResult,
    DomainAnalysisResult,
    ThreatEvaluation,
)
from src.services.xai_engine import ExplainabilityEngine


class TestExplainabilityEngine(unittest.TestCase):
    """Test suite for ExplainabilityEngine XAI calculations and safety."""

    def test_feature_attribution_computation(self):
        """Validates that individual signal contributions and percentage impacts are calculated accurately."""
        text_res = TextAnalysisResult(
            financial_keywords_found=["wire transfer", "bitcoin"],
            equipment_flags=["check to buy equipment"],
            webmail_flags=["recruiter@gmail.com"],
            urgency_flags=["urgent payment within 24 hours"]
        )
        dom_res = DomainAnalysisResult(
            domain="scam-portal.xyz",
            is_new_domain=True,
            domain_age_days=10,
            is_masked=True
        )
        eval_res = ThreatEvaluation(
            score=100.0,
            risk_level="CRITICAL",
            all_flags=["Domain <180d", "Masked WHOIS", "Wire transfer", "Bitcoin", "Equipment trap", "Webmail", "Urgency"]
        )

        attributions = ExplainabilityEngine.compute_attributions(eval_res, text_res, dom_res)
        self.assertGreater(len(attributions), 0)

        # Verify specific feature weights
        names = [a.feature_name for a in attributions]
        self.assertTrue(any("Newly Registered Domain" in n for n in names))
        self.assertTrue(any("Concealed WHOIS" in n for n in names))
        self.assertTrue(any("wire transfer" in n for n in names))
        self.assertTrue(any("bitcoin" in n for n in names))
        self.assertTrue(any("Equipment Scam" in n for n in names))
        self.assertTrue(any("Recruiter Webmail" in n for n in names))
        self.assertTrue(any("Coercive Urgency" in n for n in names))

        # Check that percentage impacts sum to 100% (+/- 1.0% due to rounding)
        total_pct = sum(a.percentage_impact for a in attributions)
        self.assertAlmostEqual(total_pct, 100.0, delta=1.5)

    def test_decision_confidence_calculation(self):
        """Validates algorithmic decision confidence scaling."""
        # 1. High-risk multi-vector convergence case
        text_res = TextAnalysisResult(
            financial_keywords_found=["wire transfer"],
            equipment_flags=["check to buy equipment"]
        )
        dom_res = DomainAnalysisResult(
            domain="fake-domain.xyz",
            lookup_successful=True,
            is_new_domain=True,
            is_masked=True
        )
        eval_res = ThreatEvaluation(score=80.0, risk_level="CRITICAL")
        attributions = ExplainabilityEngine.compute_attributions(eval_res, text_res, dom_res)

        confidence_high = ExplainabilityEngine.compute_decision_confidence(eval_res, attributions, dom_res)
        self.assertGreaterEqual(confidence_high, 80.0)
        self.assertLessEqual(confidence_high, 100.0)

        # 2. Clean benign case
        text_clean = TextAnalysisResult()
        dom_clean = DomainAnalysisResult(domain="cisco.com", lookup_successful=True, is_new_domain=False)
        eval_clean = ThreatEvaluation(score=0.0, risk_level="LOW RISK")
        attributions_clean = ExplainabilityEngine.compute_attributions(eval_clean, text_clean, dom_clean)

        confidence_clean = ExplainabilityEngine.compute_decision_confidence(eval_clean, attributions_clean, dom_clean)
        self.assertGreaterEqual(confidence_clean, 90.0)

    def test_counterfactual_what_if_reasoning(self):
        """Validates counterfactual scenario generation for reducing high threat to LOW RISK (<30%)."""
        eval_res = ThreatEvaluation(score=80.0, risk_level="CRITICAL")
        text_res = TextAnalysisResult(
            financial_keywords_found=["wire transfer"],
            equipment_flags=["check to buy equipment"]
        )
        dom_res = DomainAnalysisResult(domain="scam.xyz", is_new_domain=True, domain_age_days=12)

        attributions = ExplainabilityEngine.compute_attributions(eval_res, text_res, dom_res)
        counterfactuals = ExplainabilityEngine.generate_counterfactuals(eval_res, attributions)

        self.assertEqual(len(counterfactuals), 1)
        scenario = counterfactuals[0]
        self.assertLess(scenario.target_score, 30.0)
        self.assertEqual(scenario.target_risk_tier, "LOW RISK")
        self.assertIn("Threat Index would drop from 80% to", scenario.narrative)
        self.assertGreater(len(scenario.factors_to_change), 0)

    def test_counterfactual_already_low_risk(self):
        """Validates counterfactual for an offer already at LOW RISK."""
        eval_res = ThreatEvaluation(score=15.0, risk_level="LOW RISK")
        counterfactuals = ExplainabilityEngine.generate_counterfactuals(eval_res, [])
        self.assertEqual(len(counterfactuals), 1)
        self.assertEqual(counterfactuals[0].target_risk_tier, "LOW RISK")
        self.assertIn("already classified as LOW RISK", counterfactuals[0].narrative)

    def test_forensic_summary_generation(self):
        """Validates generation of Primary Driver, Corroborating Evidence, and Evasion Signals."""
        text_res = TextAnalysisResult(
            financial_keywords_found=["wire transfer"],
            urgency_flags=["urgent payment"]
        )
        dom_res = DomainAnalysisResult(domain="fake.xyz", is_new_domain=True, is_masked=True)
        eval_res = ThreatEvaluation(score=75.0, risk_level="CRITICAL")

        attributions = ExplainabilityEngine.compute_attributions(eval_res, text_res, dom_res)
        primary_driver, corroborating, evasion_signals, narrative = ExplainabilityEngine.generate_forensic_summary(
            eval_res, attributions
        )

        self.assertIsNotNone(primary_driver)
        self.assertEqual(primary_driver.weight, 40.0)  # Domain age is highest (+40%)
        self.assertGreater(len(corroborating), 0)
        self.assertGreater(len(evasion_signals), 0)
        self.assertIn("PRIMARY DRIVER", narrative)
        self.assertIn("corroborated by secondary indicators", narrative)

    def test_xss_sanitization_in_highlighted_html(self):
        """Validates strict XSS sanitization of candidate text in HTML highlighting."""
        malicious_input = (
            "<script>alert('XSS')</script> Wire transfer $5,000 for equipment check. "
            "<img src='x' onerror='alert(1)'>"
        )
        snippets = [
            {"category": "Financial Channel", "term": "Wire transfer", "snippet": "Wire transfer $5,000"},
            {"category": "Pay-For-Equipment Trap", "term": "equipment check", "snippet": "for equipment check"}
        ]

        html_output = ExplainabilityEngine.generate_highlighted_html(malicious_input, snippets, [])

        # Critical security assertions: unescaped script and img tags must NOT be present as HTML
        self.assertNotIn("<script>", html_output)
        self.assertNotIn("<img", html_output)
        self.assertIn("&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;", html_output)
        self.assertIn("&lt;img src=&#x27;x&#x27;", html_output)

        # Verify safe highlighting marks were injected for valid matched terms
        self.assertIn('<mark class="xai-mark hl-red"', html_output)
        self.assertIn("Wire transfer", html_output)


if __name__ == "__main__":
    unittest.main()
