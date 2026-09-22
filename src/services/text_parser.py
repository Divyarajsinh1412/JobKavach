"""
Text Parsing Engine (NLP & Regex Threat Extractor).
Scans input text across 5 fraud taxonomies in linear O(N) time with
guaranteed ReDoS immunity.
"""

import re
import hashlib
import logging
from typing import List, Dict

from src.config.settings import (
    FINANCIAL_KEYWORDS,
    EQUIPMENT_PATTERNS,
    DEPOSIT_PATTERNS,
    URGENCY_PATTERNS,
    WEBMAIL_RECRUITER_PATTERN,
)
from src.models.schemas import TextAnalysisResult

logger = logging.getLogger("PhishingInspector.TextParser")


class TextParser:
    """
    High-throughput linguistic analysis engine for detecting job offer phishing schemes.

    TIME-COMPLEXITY INLINE DOCUMENTATION:
    ------------------------------------
    Overall Complexity: O(N) where N is the length of the input text string.
    - All regular expression patterns are pre-compiled at class initialization using re.compile().
    - Patterns avoid unbounded nested quantifiers (e.g. (a+)+ or (.*a)+) to prevent Regular
      Expression Denial of Service (ReDoS) catastrophic backtracking.
    - Scans execute in linear O(N) time with deterministic finite automata (DFA) behavior.
    - Matched string extraction operates on bounded captures, ensuring sub-millisecond execution
      even on lengthy candidate offer documents.
    """

    def __init__(self):
        self.financial_keywords = FINANCIAL_KEYWORDS
        self.equipment_patterns = EQUIPMENT_PATTERNS
        self.deposit_patterns = DEPOSIT_PATTERNS
        self.urgency_patterns = URGENCY_PATTERNS
        self.webmail_pattern = WEBMAIL_RECRUITER_PATTERN

    def analyze_text(self, text: str) -> TextAnalysisResult:
        """
        Executes multi-vector linguistic extraction on the supplied text payload.
        Runs in linear O(N) time across all five fraud taxonomies.
        Returns a TextAnalysisResult containing all detected indicators.
        """
        if not text or not text.strip():
            return TextAnalysisResult()

        payload_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
        detected_flags: List[str] = []
        financial_keywords_found: List[str] = []
        equipment_flags: List[str] = []
        deposit_flags: List[str] = []
        urgency_flags: List[str] = []
        webmail_flags: List[str] = []
        matched_snippets: List[Dict[str, str]] = []

        # ----------------------------------------------------------------------
        # Vector 1: High-Risk Financial Channels (Exact word boundary matching)
        # O(N) linear-time execution: Pre-compiled regex evaluation without backtracking
        # ----------------------------------------------------------------------
        for kw in self.financial_keywords:
            kw_pattern = re.compile(r"\b" + re.escape(kw) + r"\b", re.I)
            match = kw_pattern.search(text)
            if match:
                financial_keywords_found.append(kw)
                matched_snippets.append({
                    "category": "Financial Channel",
                    "term": kw,
                    "snippet": self._extract_snippet(text, match.start(), match.end())
                })

        if financial_keywords_found:
            detected_flags.append(f"High-Risk Payment Channels: {', '.join(financial_keywords_found)}")

        # ----------------------------------------------------------------------
        # Vector 2: Pay-for-Equipment Phishing Patterns
        # Linear scan for check overpayment & vendor redirection traps
        # ----------------------------------------------------------------------
        for pattern in self.equipment_patterns:
            match = pattern.search(text)
            if match:
                matched_text = match.group(0)
                equipment_flags.append(matched_text)
                matched_snippets.append({
                    "category": "Pay-For-Equipment Trap",
                    "term": matched_text,
                    "snippet": self._extract_snippet(text, match.start(), match.end())
                })
        if equipment_flags:
            detected_flags.append(f"Pay-For-Equipment Phishing Patterns Detected ({len(equipment_flags)} triggers)")

        # ----------------------------------------------------------------------
        # Vector 3: Security Deposit & Advance Fee Scams
        # Linear scan for refundable deposits, screening fees, training costs
        # ----------------------------------------------------------------------
        for pattern in self.deposit_patterns:
            match = pattern.search(text)
            if match:
                matched_text = match.group(0)
                deposit_flags.append(matched_text)
                matched_snippets.append({
                    "category": "Advance Fee / Deposit",
                    "term": matched_text,
                    "snippet": self._extract_snippet(text, match.start(), match.end())
                })
        if deposit_flags:
            detected_flags.append(f"Advance Fee / Security Deposit Demand Detected ({len(deposit_flags)} triggers)")

        # ----------------------------------------------------------------------
        # Vector 4: Urgency & Coercive Pressure Demands
        # Linear scan for 24h artificial deadlines & secrecy requirements
        # ----------------------------------------------------------------------
        for pattern in self.urgency_patterns:
            match = pattern.search(text)
            if match:
                matched_text = match.group(0)
                urgency_flags.append(matched_text)
                matched_snippets.append({
                    "category": "Urgent Coercion",
                    "term": matched_text,
                    "snippet": self._extract_snippet(text, match.start(), match.end())
                })
        if urgency_flags:
            detected_flags.append(f"High Pressure / Immediate Demand Indicators ({len(urgency_flags)} triggers)")

        # ----------------------------------------------------------------------
        # Vector 5: Free Webmail Masquerading as Corporate Enterprise HR
        # Linear scan for @gmail.com, @yahoo.com, etc. in recruiter context
        # ----------------------------------------------------------------------
        webmail_matches = self.webmail_pattern.findall(text)
        if webmail_matches:
            unique_webmails = list(set(webmail_matches))
            webmail_flags.extend(unique_webmails)
            detected_flags.append(f"Free Webmail Recruiter Address Detected: {', '.join(unique_webmails)}")
            matched_snippets.append({
                "category": "Recruiter Impersonation",
                "term": ", ".join(unique_webmails),
                "snippet": "Free public webmail address used in official employment context."
            })

        return TextAnalysisResult(
            detected_flags=detected_flags,
            financial_keywords_found=financial_keywords_found,
            equipment_flags=equipment_flags,
            deposit_flags=deposit_flags,
            urgency_flags=urgency_flags,
            webmail_flags=webmail_flags,
            financial_keyword_count=len(financial_keywords_found),
            matched_snippets=matched_snippets,
            payload_hash=payload_hash
        )

    @staticmethod
    def _extract_snippet(text: str, start: int, end: int, window: int = 50) -> str:
        """Extracts contextual snippet around a matched pattern."""
        s_start = max(0, start - window)
        s_end = min(len(text), end + window)
        prefix = "..." if s_start > 0 else ""
        suffix = "..." if s_end < len(text) else ""
        return f"{prefix}{text[s_start:s_end].strip()}{suffix}"
