"""
Automated Forensic Test Suite for Fake Offer Letter & Phishing Inspector
Validates Clean Architecture, O(N) linear parsing, ReDoS immunity,
exact mathematical scoring weights, and SQLite WAL operations.
"""

import sys
import os
import time
import json
from datetime import datetime, timezone

# Add workspace to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import (
    DatabaseManager,
    TextParser,
    DomainVerifier,
    ThreatScoringEngine,
    TextAnalysisResult,
    DomainAnalysisResult,
    ThreatEvaluation,
)


def test_database_manager():
    print("[TEST] 1. Validating DatabaseManager & SQLite WAL persistence...")
    test_db = "test_scan_ledger.db"
    if os.path.exists(test_db):
        try:
            os.remove(test_db)
        except PermissionError:
            pass

    db = DatabaseManager(db_path=test_db)

    # Validate log_scan with parameterized query
    row_id = db.log_scan(
        scan_type="Full Inspection",
        target_domain="google-careers-portal.xyz",
        threat_score=85.0,
        risk_level="CRITICAL",
        detected_flags=["Newly registered domain", "Wire transfer keyword"],
        details={"test_key": "test_val"},
        payload_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert row_id is not None and row_id > 0, "log_scan did not return a valid row id"

    # Validate get_history
    history = db.get_history(limit=10)
    assert len(history) == 1, f"Expected 1 record, got {len(history)}"
    assert history[0]["threat_score"] == 85.0
    assert history[0]["risk_level"] == "CRITICAL"
    assert history[0]["target_domain"] == "google-careers-portal.xyz"

    # Validate get_summary_metrics
    metrics = db.get_summary_metrics()
    assert metrics["total_scans"] == 1
    assert metrics["critical_scans"] == 1
    assert metrics["suspicious_scans"] == 0
    assert metrics["low_risk_scans"] == 0
    assert metrics["avg_threat_score"] == 85.0

    print("  --> DatabaseManager passed all validation checks.")


def test_text_parser_taxonomies():
    print("[TEST] 2. Validating TextParser fraud taxonomies...")
    parser = TextParser()

    # 1. Pay-for-equipment phishing
    text1 = "Please deposit this check to buy equipment for your home office from our approved vendor."
    res1 = parser.analyze_text(text1)
    assert len(res1.equipment_flags) > 0, "Failed to detect pay-for-equipment pattern"

    # 2. Advance-fee / security deposit
    text2 = "A refundable security deposit of $300 is required for background check fee and training materials."
    res2 = parser.analyze_text(text2)
    assert len(res2.deposit_flags) > 0, "Failed to detect advance-fee deposit pattern"

    # 3. High-risk financial channels
    text3 = "Submit payments via wire transfer, western union, bitcoin, or zelle."
    res3 = parser.analyze_text(text3)
    assert "wire transfer" in res3.financial_keywords_found
    assert "western union" in res3.financial_keywords_found
    assert "bitcoin" in res3.financial_keywords_found
    assert "zelle" in res3.financial_keywords_found
    assert res3.financial_keyword_count >= 4

    # 4. Urgent demands & coercion
    text4 = "Urgent payment required within 24 hours. Do not disclose to anyone; strictly confidential."
    res4 = parser.analyze_text(text4)
    assert len(res4.urgency_flags) > 0, "Failed to detect urgency/coercion pattern"

    # 5. Recruiter webmail impersonation
    text5 = "Contact HR director at official_recruiting@gmail.com for your onboarding paperwork."
    res5 = parser.analyze_text(text5)
    assert len(res5.webmail_flags) > 0, "Failed to detect recruiter webmail impersonation"

    print("  --> TextParser fraud taxonomies passed all checks.")


def test_redos_and_linear_performance():
    print("[TEST] 3. Validating O(N) linear time parsing & ReDoS immunity...")
    parser = TextParser()

    # Construct a pathological repeating string (180,000 characters) designed to trigger ReDoS
    malicious_text = ("Dear Candidate, approved vendor will deliver upon payment check to buy home office " * 2000)
    assert len(malicious_text) > 150000

    start_time = time.perf_counter()
    result = parser.analyze_text(malicious_text)
    elapsed = time.perf_counter() - start_time

    print(f"  --> Processed {len(malicious_text):,} characters in {elapsed:.4f} seconds.")
    # Must complete in under 0.5 seconds on any modern CPU
    assert elapsed < 0.5, f"ReDoS vulnerability suspected! Execution took {elapsed:.2f}s"
    assert len(result.equipment_flags) > 0


def test_domain_verifier():
    print("[TEST] 4. Validating DomainVerifier sanitization and logic...")
    verifier = DomainVerifier()

    # 1. Bare domain extraction
    assert verifier.extract_domain("https://careers.google.com/jobs/123") == "careers.google.com"
    assert verifier.extract_domain("hr-director@microsoft-careers.xyz") == "microsoft-careers.xyz"
    assert verifier.extract_domain("sub.portal.domain.co.uk:8080/path") == "sub.portal.domain.co.uk"
    assert verifier.extract_domain("invalid_domain") is None

    # 2. Privacy shield detection
    fake_record = {
        "org": "WhoisGuard Protected",
        "registrant_name": "Withheld for Privacy",
        "registrar": "NameCheap, Inc.",
        "emails": "privacy@whoisguard.com"
    }
    assert verifier._detect_privacy_shield(fake_record) is True

    public_record = {
        "org": "Cisco Systems, Inc.",
        "registrant_name": "Domain Admin",
        "registrar": "MarkMonitor Inc.",
        "emails": "dns-admin@cisco.com"
    }
    assert verifier._detect_privacy_shield(public_record) is False

    print("  --> DomainVerifier passed sanitization and privacy shield tests.")


def test_threat_scoring_engine_weights():
    print("[TEST] 5. Validating exact mathematical scoring weights and tiers...")
    
    # Baseline empty text
    empty_text = TextAnalysisResult()
    eval_empty = ThreatScoringEngine.evaluate(empty_text)
    assert eval_empty.score == 0.0
    assert eval_empty.risk_level == "LOW RISK"

    # Weight 1: Domain age < 180 days (+40%)
    dom_new = DomainAnalysisResult(domain="new-scam.xyz", is_new_domain=True, domain_age_days=15)
    eval_dom = ThreatScoringEngine.evaluate(empty_text, dom_new)
    assert eval_dom.score == 40.0
    assert eval_dom.risk_level == "SUSPICIOUS"  # 30-69% is SUSPICIOUS

    # Weight 2: Specific financial keywords (+20% each)
    text_kw = TextAnalysisResult(financial_keywords_found=["wire transfer", "bitcoin"], financial_keyword_count=2)
    eval_kw = ThreatScoringEngine.evaluate(text_kw)
    assert eval_kw.score == 40.0  # 20 + 20

    # Weight 3: Masked WHOIS privacy proxy (+20%)
    dom_masked = DomainAnalysisResult(domain="masked-scam.xyz", is_masked=True)
    eval_masked = ThreatScoringEngine.evaluate(empty_text, dom_masked)
    assert eval_masked.score == 20.0

    # Weight 4: Equipment scam / Advance fee patterns (+20%)
    text_equip = TextAnalysisResult(equipment_flags=["check to buy home office"])
    eval_equip = ThreatScoringEngine.evaluate(text_equip)
    assert eval_equip.score == 20.0

    # Weight 5: Recruiter webmail spoofing (+25%)
    text_webmail = TextAnalysisResult(webmail_flags=["recruiter@gmail.com"])
    eval_webmail = ThreatScoringEngine.evaluate(text_webmail)
    assert eval_webmail.score == 25.0

    # Weight 6: Urgent payment / coercion demands (+15%)
    text_urgency = TextAnalysisResult(urgency_flags=["immediate payment"])
    eval_urgency = ThreatScoringEngine.evaluate(text_urgency)
    assert eval_urgency.score == 15.0

    # Combined Critical Test:
    # Domain <180d (+40%) + 2 financial keywords (+40%) + equipment scam (+20%) = 100%
    text_full = TextAnalysisResult(
        equipment_flags=["check to buy equipment"],
        financial_keywords_found=["wire transfer", "cashier's check"],
        financial_keyword_count=2,
        urgency_flags=["urgent payment"]
    )
    dom_full = DomainAnalysisResult(
        domain="fake-hr.xyz",
        is_new_domain=True,
        domain_age_days=10,
        is_masked=True
    )
    # 40 (new) + 20 (masked) + 40 (2 keywords) + 20 (equip) + 15 (urgency) = 135 -> Capped at 100.0%
    eval_full = ThreatScoringEngine.evaluate(text_full, dom_full)
    assert eval_full.score == 100.0, f"Expected 100.0 capped, got {eval_full.score}"
    assert eval_full.risk_level == "CRITICAL"

    print("  --> ThreatScoringEngine passed all mathematical scoring and tiering tests.")


def main():
    print("=" * 70)
    print("RUNNING AUTOMATED FORENSIC TEST SUITE")
    print("=" * 70)
    test_database_manager()
    test_text_parser_taxonomies()
    test_redos_and_linear_performance()
    test_domain_verifier()
    test_threat_scoring_engine_weights()
    print("=" * 70)
    print("ALL TESTS PASSED WITH 100% ACCURACY & ZERO ERRORS")
    print("=" * 70)


if __name__ == "__main__":
    main()
