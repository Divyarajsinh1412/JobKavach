"""
Domain models and schemas for Fake Offer Letter & Phishing Inspector.
"""

from .schemas import (
    TextAnalysisResult,
    DomainAnalysisResult,
    ThreatEvaluation,
    AuditRecord,
    User,
    AttachmentInfo,
    EmailMetadata,
    DocumentAnalysisResult,
    FeatureAttribution,
    CounterfactualScenario,
    XAIExplanation,
)

__all__ = [
    "TextAnalysisResult",
    "DomainAnalysisResult",
    "ThreatEvaluation",
    "AuditRecord",
    "User",
    "AttachmentInfo",
    "EmailMetadata",
    "DocumentAnalysisResult",
    "FeatureAttribution",
    "CounterfactualScenario",
    "XAIExplanation",
]
