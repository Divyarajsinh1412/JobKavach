"""
Enterprise Settings, Scoring Weights, and Threat Taxonomies.
Centralizes all algorithm parameters, pre-compiled regex definitions,
and MITRE ATT&CK mapping constants.
"""

import re
from typing import List, Dict, Pattern

# ==============================================================================
# 1. MATHEMATICAL THREAT WEIGHTS & THRESHOLDS (PER SPECIFICATION)
# ==============================================================================

# Core Indicator Weights
WEIGHT_DOMAIN_AGE_NEW: float = 40.0         # Domain age < 180 days (+40%)
WEIGHT_FINANCIAL_KEYWORD: float = 20.0      # Specific financial keywords (+20% each)
WEIGHT_WHOIS_MASKED: float = 20.0           # Masked WHOIS privacy proxy (+20%)
WEIGHT_EQUIPMENT_ADVANCE_FEE: float = 20.0  # Equipment scam / Advance fee patterns (+20%)
WEIGHT_WEBMAIL_RECRUITER: float = 25.0      # Recruiter webmail spoofing (+25%)
WEIGHT_URGENCY_COERCION: float = 15.0       # Urgent payment / coercion demands (+15%)
WEIGHT_REPLY_TO_MISMATCH: float = 25.0      # Email Reply-To domain mismatch or webmail redirect (+25%)
WEIGHT_SUSPICIOUS_ATTACHMENT: float = 20.0  # Suspicious executable/script/archive attachment (+20%)
WEIGHT_AUTH_HEADER_FAIL: float = 20.0       # SPF or DKIM validation failure (+20%)

# Score Clamping Boundaries
SCORE_MIN: float = 0.0
SCORE_MAX: float = 100.0

# Risk Classification Severity Tiers
THRESHOLD_CRITICAL: float = 70.0   # CRITICAL: >= 70%
THRESHOLD_SUSPICIOUS: float = 30.0 # SUSPICIOUS: 30% - 69%
                                   # LOW RISK: < 30%

# Domain Age Threshold
DOMAIN_AGE_THRESHOLD_DAYS: int = 180

# ==============================================================================
# 2. FRAUD TAXONOMY INDICATORS & REGEX PATTERNS (O(N) LINEAR DFA)
# ==============================================================================

# Taxonomy 1: High-Risk Financial Channels (+20% each)
FINANCIAL_KEYWORDS: List[str] = [
    "wire transfer",
    "western union",
    "moneygram",
    "crypto",
    "cryptocurrency",
    "bitcoin",
    "btc",
    "usdt",
    "ethereum",
    "cashapp",
    "cash app",
    "zelle",
    "venmo",
    "cashier's check",
    "cashiers check",
    "prepaid card",
    "gift card",
]

# Taxonomy 2: Pay-for-Equipment Phishing Patterns
EQUIPMENT_PATTERNS: List[Pattern[str]] = [
    re.compile(r"\b(?:check|funds|money)\s+to\s+(?:buy|purchase)\s+(?:home\s+office|equipment|hardware|laptop|workstation)", re.I),
    re.compile(r"\b(?:reimbursement|reimburse)\s+(?:check|funds)\s+for\s+(?:equipment|supplies|hardware|office)", re.I),
    re.compile(r"\b(?:approved|certified|our)\s+(?:vendor|merchant|supplier)\s+(?:to\s+order|will\s+deliver|for\s+your\s+laptop)", re.I),
    re.compile(r"\b(?:vendor|courier)\s+will\s+(?:deliver|ship)\s+(?:upon\s+payment|after\s+you\s+pay|equipment)", re.I),
    re.compile(r"\b(?:send|forward)\s+(?:the\s+remaining|excess|balance)\s+(?:funds|money|amount)\s+back", re.I),
]

# Taxonomy 3: Advance-Fee & Security Deposit Traps
DEPOSIT_PATTERNS: List[Pattern[str]] = [
    re.compile(r"\b(?:refundable|security)\s+(?:deposit|fee|payment)\b", re.I),
    re.compile(r"\b(?:background\s+check|screening|verification)\s+(?:fee|cost|charge)\b", re.I),
    re.compile(r"\b(?:training|orientation|certification)\s+(?:fee|materials?\s+deposit|cost)\b", re.I),
    re.compile(r"\b(?:visa|work\s+permit|clearance)\s+(?:processing\s+fee|deposit)\b", re.I),
    re.compile(r"\b(?:pay|send|transfer)\s+(?:in\s+advance|upfront|before\s+starting)\b", re.I),
]

# Taxonomy 4: Coercive Urgency & Pressure Demands
URGENCY_PATTERNS: List[Pattern[str]] = [
    re.compile(r"\b(?:immediate|urgent)\s+(?:payment|transfer|wire|action)\b", re.I),
    re.compile(r"\bwithin\s+(?:24|12|48)\s*hours?\s+(?:or\s+offer\s+void|to\s+secure)\b", re.I),
    re.compile(r"\b(?:strictly\s+confidential|do\s+not\s+disclose\s+to\s+anyone)\b", re.I),
    re.compile(r"\b(?:interview|contact)\s+via\s+(?:telegram|whatsapp|signal)\s+(?:only|immediately)\b", re.I),
]

# Taxonomy 5: Free Webmail Recruiter Address Impersonation
WEBMAIL_RECRUITER_PATTERN: Pattern[str] = re.compile(
    r"\b[A-Za-z0-9._%+-]+@(gmail|yahoo|hotmail|outlook|protonmail|aol|zoho)\.com\b",
    re.I
)

# Privacy Proxy Service Signatures ("Domains By Proxy", "WhoisGuard", "PrivacyProtect", etc.)
PRIVACY_SIGNATURES: List[str] = [
    "privacy",
    "proxy",
    "whoisguard",
    "domains by proxy",
    "withheld for privacy",
    "redacted for privacy",
    "contact privacy inc",
    "super privacy service",
    "private by design",
    "cloudway",
    "identity protection",
    "privacyprotect",
]

# Supported File Upload Formats
SUPPORTED_DOC_EXTENSIONS: List[str] = [
    ".eml", ".msg", ".pdf", ".docx", ".txt", ".rtf", ".html", ".htm"
]

# Suspicious Attachment Extensions
SUSPICIOUS_ATTACHMENT_EXTENSIONS: List[str] = [
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".iso", ".img", ".zip", ".rar", ".7z", ".tar",
    ".gz", ".hta", ".cpl", ".msc", ".jar", ".ps1"
]

# MITRE ATT&CK Mapping Taxonomy
DEFAULT_MITRE_TAGS: List[str] = [
    "T1566 - Phishing",
    "T1566.001 - Spearphishing Attachment",
    "T1566.002 - Spearphishing Link",
    "T1583.001 - Acquire Infrastructure: Domains",
    "T1586.002 - Compromise Accounts: Email Accounts",
    "T1036.005 - Masquerading: Match Legitimate Name or Host",
    "T1204.001 - User Execution: Coercive Social Engineering",
    "T1598 - Phishing for Information: Financial Solicitation",
]

# ==============================================================================
# 3. PRESET EVALUATION SCENARIOS
# ==============================================================================

SAMPLE_EQUIPMENT_SCAM = {
    "text": (
        "Dear Candidate,\n\nFollowing your interview, Google Cloud Team is delighted to offer you the position "
        "of Senior Data Analyst. Your starting salary is $145,000.\n\n"
        "Prior to your official start date, our corporate finance department will send you a cashier's check "
        "of $4,500 for your home office equipment stipend check. Once deposited, you must immediately wire transfer "
        "$3,800 to our approved hardware vendor to purchase your Apple MacBook Pro and secure workstation. "
        "Deduct your share and send the remaining balance back.\n\n"
        "This offer expires today. Immediate response required within 24 hours to secure placement. "
        "Please keep this strictly confidential until fully onboarded."
    ),
    "domain": "http://google-careers-global.xyz",
}

SAMPLE_SECURITY_DEPOSIT_SCAM = {
    "text": (
        "Congratulations! Microsoft Talent Acquisition has selected you for our Remote Cybersecurity Contractor role.\n\n"
        "To proceed, connect with our hiring coordinator on Telegram: @msft_lead_recruiter. All preliminary interviews "
        "will be conducted via Telegram. As part of mandatory onboarding, you must submit a refundable security deposit "
        "of $350 for training materials and background check fee via Bitcoin (crypto) or USDT wallet. "
        "The deposit will be refunded in your first paycheck.\n\n"
        "Respond within 24 hours to claim this offer."
    ),
    "domain": "careers-microsoft-portal.xyz",
}

SAMPLE_LEGITIMATE_OFFER = {
    "text": (
        "Dear Jordan Smith,\n\nWe are pleased to offer you employment at Cisco Systems, Inc. as a Systems Software Engineer. "
        "Your annualized base salary will be $135,000 paid semi-monthly in accordance with standard payroll schedules.\n\n"
        "Cisco will provide all necessary hardware and enterprise laptops directly shipped to your home address via "
        "our global logistics partner at zero expense to you. Your pre-employment background screening will be conducted "
        "through our verified corporate portal.\n\n"
        "Please review the attached formal offer letter on Workday by October 15."
    ),
    "domain": "cisco.com",
}
