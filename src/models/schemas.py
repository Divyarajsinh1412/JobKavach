"""
Strongly typed domain models and schemas for Fake Offer Letter & Phishing Inspector.
Includes core telemetry containers and Explainable AI (XAI) feature attribution schemas.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional, Any


@dataclass
class TextAnalysisResult:
    """Structured data container representing text parsing telemetry and IoCs."""
    detected_flags: List[str] = field(default_factory=list)
    financial_keywords_found: List[str] = field(default_factory=list)
    equipment_flags: List[str] = field(default_factory=list)
    deposit_flags: List[str] = field(default_factory=list)
    urgency_flags: List[str] = field(default_factory=list)
    webmail_flags: List[str] = field(default_factory=list)
    financial_keyword_count: int = 0
    matched_snippets: List[Dict[str, str]] = field(default_factory=list)
    payload_hash: str = ""


@dataclass
class DomainAnalysisResult:
    """Structured data container representing domain intelligence telemetry."""
    domain: str = ""
    is_valid_format: bool = False
    lookup_successful: bool = False
    creation_date: Optional[datetime] = None
    domain_age_days: Optional[int] = None
    is_new_domain: bool = False  # < 180 days per specification
    is_masked: bool = False      # Masked WHOIS / Privacy guard
    registrar: Optional[str] = None
    registrant_org: Optional[str] = None
    raw_summary: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None


@dataclass
class AttachmentInfo:
    """Represents an attachment extracted from an email or container document."""
    filename: str
    file_type: str
    size_bytes: int
    is_suspicious: bool = False
    reason: str = ""


@dataclass
class EmailMetadata:
    """Structured email headers and transport security telemetry."""
    sender: str = ""
    sender_domain: str = ""
    reply_to: str = ""
    reply_to_domain: str = ""
    reply_to_mismatch: bool = False
    subject: str = ""
    date: str = ""
    spf_status: Optional[str] = None
    dkim_status: Optional[str] = None
    attachments: List[AttachmentInfo] = field(default_factory=list)
    extracted_urls: List[str] = field(default_factory=list)


@dataclass
class DocumentAnalysisResult:
    """Structured container for parsed documents and uploaded mail artifacts."""
    filename: str = ""
    file_format: str = ""
    file_size: int = 0
    extracted_text: str = ""
    email_metadata: Optional[EmailMetadata] = None
    embedded_urls: List[str] = field(default_factory=list)
    sha256_hash: str = ""
    parse_warnings: List[str] = field(default_factory=list)


@dataclass
class ThreatEvaluation:
    """Consolidated threat calculation result."""
    score: float = 0.0
    risk_level: str = "LOW RISK"  # 'CRITICAL', 'SUSPICIOUS', 'LOW RISK'
    score_breakdown: List[Dict[str, Any]] = field(default_factory=list)
    all_flags: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    mitre_tags: List[str] = field(default_factory=list)


@dataclass
class AuditRecord:
    """Represents an immutable ledger record stored in SQLite."""
    id: Optional[int] = None
    timestamp: str = ""
    scan_type: str = ""
    target_domain: Optional[str] = None
    threat_score: float = 0.0
    risk_level: str = ""
    flag_count: int = 0
    detected_flags_json: str = "[]"
    details_json: str = "{}"
    payload_hash: str = ""


@dataclass
class User:
    """Represents an authenticated platform analyst or user."""
    user_id: str
    email: str
    full_name: str
    role: str = "SOC Security Analyst"
    created_at: str = ""
    last_login: Optional[str] = None


# ==============================================================================
# EXPLAINABLE AI (XAI) SCHEMAS
# ==============================================================================

@dataclass
class FeatureAttribution:
    """Represents an individual signal's attribution score and directional impact."""
    feature_name: str
    category: str  # "Infrastructure", "Financial Channel", "Linguistic Trap", "Social Engineering", "Identity"
    weight: float  # Absolute weight delta (+40.0, +20.0, -10.0, etc.)
    percentage_impact: float  # Normalized attribution percentage relative to total risk
    direction: str  # "INCREASES_RISK", "DECREASES_RISK", "NEUTRAL"
    evidence: str
    color_hex: str  # Styling token for UI overlay (#ef4444, #f59e0b, #38bdf8)


@dataclass
class CounterfactualScenario:
    """Represents an automated what-if explanation showing steps to reach LOW RISK."""
    factors_to_change: List[str]
    score_reduction: float
    target_score: float
    target_risk_tier: str  # "LOW RISK", "BENIGN"
    narrative: str


@dataclass
class XAIExplanation:
    """Comprehensive explainability report containing attributions, what-if reasoning, and narrative."""
    baseline_risk: float = 0.0
    posterior_score: float = 0.0
    decision_confidence: float = 0.0  # 0.0 - 100.0%
    attributions: List[FeatureAttribution] = field(default_factory=list)
    primary_driver: Optional[FeatureAttribution] = None
    corroborating_evidence: List[FeatureAttribution] = field(default_factory=list)
    evasion_signals: List[FeatureAttribution] = field(default_factory=list)
    forensic_narrative: str = ""
    counterfactuals: List[CounterfactualScenario] = field(default_factory=list)
    highlighted_html: str = ""
