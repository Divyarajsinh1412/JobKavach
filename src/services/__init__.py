"""
Services layer for Fake Offer Letter & Phishing Inspector.
Encapsulates text parsing, domain verification, threat scoring, and explainability engines.
"""

from .text_parser import TextParser
from .domain_verifier import DomainVerifier
from .scoring_engine import ThreatScoringEngine
from .xai_engine import ExplainabilityEngine

__all__ = [
    "TextParser",
    "DomainVerifier",
    "ThreatScoringEngine",
    "ExplainabilityEngine",
]
