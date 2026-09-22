"""
Dynamic Scam Threat Scoring Engine.
Calculates a 0-100% deterministic Threat Index applying exact mathematical weights,
clamping boundaries, and severity classifications.
"""

from typing import Dict, List, Optional, Any

from src.config.settings import (
    WEIGHT_DOMAIN_AGE_NEW,
    WEIGHT_FINANCIAL_KEYWORD,
    WEIGHT_WHOIS_MASKED,
    WEIGHT_EQUIPMENT_ADVANCE_FEE,
    WEIGHT_WEBMAIL_RECRUITER,
    WEIGHT_URGENCY_COERCION,
    WEIGHT_REPLY_TO_MISMATCH,
    WEIGHT_SUSPICIOUS_ATTACHMENT,
    WEIGHT_AUTH_HEADER_FAIL,
    SCORE_MIN,
    SCORE_MAX,
    THRESHOLD_CRITICAL,
    THRESHOLD_SUSPICIOUS,
)
from src.models.schemas import (
    TextAnalysisResult,
    DomainAnalysisResult,
    DocumentAnalysisResult,
    ThreatEvaluation,
)


class ThreatScoringEngine:
    """
    Weighted scoring algorithm calculating a 0-100% Threat Index based on
    enterprise indicators of compromise (IoCs).

    EXACT MATHEMATICAL SCORING WEIGHTS (PER SPECIFICATION):
    ------------------------------------------------------
    - Domain age < 180 days: +40%
    - Specific financial keywords: +20% each
    - Masked WHOIS privacy proxy: +20%
    - Equipment scam / Advance fee patterns: +20%
    - Recruiter webmail spoofing: +25%
    - Urgent payment / coercion demands: +15%

    SCORING BOUNDARIES & TIERS:
    - Floor: 0%, Ceiling: 100%
    - CRITICAL: >= 70%
    - SUSPICIOUS: 30% - 69%
    - LOW RISK: < 30%
    """

    @classmethod
    def evaluate(
        cls,
        text_result: TextAnalysisResult,
        domain_result: Optional[DomainAnalysisResult] = None,
        doc_result: Optional[DocumentAnalysisResult] = None
    ) -> ThreatEvaluation:
        score: float = 0.0
        breakdown: List[Dict[str, Any]] = []
        all_flags: List[str] = list(text_result.detected_flags)
        recommendations: List[str] = []
        mitre_tags: List[str] = ["T1566 - Phishing"]

        # ----------------------------------------------------------------------
        # 1. Domain Age Verification (< 180 days: +40%)
        # ----------------------------------------------------------------------
        if domain_result:
            if domain_result.is_new_domain:
                weight = WEIGHT_DOMAIN_AGE_NEW
                score += weight
                age_str = f"{domain_result.domain_age_days} days" if domain_result.domain_age_days is not None else "<180 days"
                breakdown.append({
                    "factor": "Newly Registered Domain (<180 days)",
                    "weight": f"+{weight:.0f}%",
                    "detail": f"Domain registered {age_str} ago. High risk of disposable phishing infrastructure."
                })
                all_flags.append(f"Domain is only {age_str} old (< 180 days threshold)")
                mitre_tags.append("T1583.001 - Acquire Infrastructure: Domains")

            # ------------------------------------------------------------------
            # 2. Masked WHOIS / Privacy Shield (+20%)
            # ------------------------------------------------------------------
            if domain_result.is_masked:
                weight = WEIGHT_WHOIS_MASKED
                score += weight
                breakdown.append({
                    "factor": "Masked WHOIS / Privacy Proxy",
                    "weight": f"+{weight:.0f}%",
                    "detail": "Registrant identity concealed by privacy guard. Common tactic to obstruct corporate attribution."
                })
                all_flags.append("WHOIS registration records are masked with a privacy proxy")

        # ----------------------------------------------------------------------
        # 3. Specific Financial Keywords (+20% each)
        # ----------------------------------------------------------------------
        if text_result.financial_keywords_found:
            for kw in text_result.financial_keywords_found:
                weight = WEIGHT_FINANCIAL_KEYWORD
                score += weight
                breakdown.append({
                    "factor": f"High-Risk Payment Channel: '{kw}'",
                    "weight": f"+{weight:.0f}%",
                    "detail": f"Unconventional employment payment channel detected ('{kw}'). Legitimate employers do not transact via P2P/crypto/wire."
                })
            mitre_tags.append("T1566.002 - Spearphishing Link / Attachment")

        # ----------------------------------------------------------------------
        # 4. Equipment Scam / Advance-Fee Patterns (+20%)
        # ----------------------------------------------------------------------
        if text_result.equipment_flags or text_result.deposit_flags:
            weight = WEIGHT_EQUIPMENT_ADVANCE_FEE
            score += weight
            detected_items = text_result.equipment_flags + text_result.deposit_flags
            breakdown.append({
                "factor": "Equipment Scam / Advance Fee Patterns",
                "weight": f"+{weight:.0f}%",
                "detail": f"Patterns indicate a check overpayment, mandatory equipment purchase, or upfront deposit/screening fee ({len(detected_items)} trigger(s))."
            })
            if text_result.equipment_flags:
                recommendations.append("NEVER deposit a check from an employer to buy equipment from their 'designated vendor'.")
            if text_result.deposit_flags:
                recommendations.append("Legitimate companies cover all screening, equipment, and onboarding costs. Do not transfer funds.")

        # ----------------------------------------------------------------------
        # 5. Recruiter Free Webmail Impersonation (+25%)
        # ----------------------------------------------------------------------
        if text_result.webmail_flags:
            weight = WEIGHT_WEBMAIL_RECRUITER
            score += weight
            breakdown.append({
                "factor": "Recruiter Webmail Spoofing",
                "weight": f"+{weight:.0f}%",
                "detail": f"Offer correspondence originated from free webmail: {', '.join(text_result.webmail_flags)}"
            })
            recommendations.append("Verify recruiter identity directly through official corporate career portals and LinkedIn.")

        # ----------------------------------------------------------------------
        # 6. Coercive Urgency & Pressure Demands (+15%)
        # ----------------------------------------------------------------------
        if text_result.urgency_flags:
            weight = WEIGHT_URGENCY_COERCION
            score += weight
            breakdown.append({
                "factor": "Coercive Urgency & Pressure",
                "weight": f"+{weight:.0f}%",
                "detail": "Artificial time limits designed to impair rational decision-making and bypass verification."
            })

        # ----------------------------------------------------------------------
        # 7. Document / Email Forensic Telemetry
        # ----------------------------------------------------------------------
        if doc_result and doc_result.email_metadata:
            em = doc_result.email_metadata

            # 7a. Reply-To Domain Mismatch / Webmail Redirection (+25%)
            if em.reply_to_mismatch:
                weight = WEIGHT_REPLY_TO_MISMATCH
                score += weight
                breakdown.append({
                    "factor": "Email Reply-To Mismatch / Webmail Redirection",
                    "weight": f"+{weight:.0f}%",
                    "detail": f"Sender claims to be '{em.sender}' but replies are routed to '{em.reply_to}'. High indicator of recruiter impersonation."
                })
                all_flags.append(f"Reply-To mismatch detected: {em.reply_to} != {em.sender}")
                mitre_tags.append("T1036.005 - Masquerading: Match Legitimate Name or Host")
                recommendations.append("Inspect email header routing: Do not reply directly to suspicious webmail addresses.")

            # 7b. Suspicious Attachment Payloads (+20%)
            suspicious_atts = [att for att in em.attachments if att.is_suspicious]
            if suspicious_atts:
                weight = WEIGHT_SUSPICIOUS_ATTACHMENT
                score += weight
                att_names = ", ".join(a.filename for a in suspicious_atts)
                breakdown.append({
                    "factor": "Suspicious Executable / Archive Attachment",
                    "weight": f"+{weight:.0f}%",
                    "detail": f"High-risk payload attachments detected: {att_names}. Do not execute or decompress."
                })
                all_flags.append(f"Suspicious attachment(s) identified: {att_names}")
                mitre_tags.append("T1566.001 - Spearphishing Attachment")
                recommendations.append("DO NOT download or open email attachments. Submit to sandbox isolation for analysis.")

            # 7c. Email Transport Authentication Failure (SPF/DKIM: FAIL) (+20%)
            if em.spf_status == "FAIL" or em.dkim_status == "FAIL":
                weight = WEIGHT_AUTH_HEADER_FAIL
                score += weight
                breakdown.append({
                    "factor": "Email Transport Authentication Failure",
                    "weight": f"+{weight:.0f}%",
                    "detail": f"Email headers failed cryptographic/sender policy checks (SPF: {em.spf_status or 'N/A'}, DKIM: {em.dkim_status or 'N/A'})."
                })
                all_flags.append(f"Email auth failed (SPF: {em.spf_status}, DKIM: {em.dkim_status})")
                mitre_tags.append("T1586.002 - Compromise Accounts: Email Accounts")
                recommendations.append("Email sender authentication failed. Likely forged headers or unauthorized relay.")

        # Clamping score strictly between 0 and 100%
        final_score = min(SCORE_MAX, max(SCORE_MIN, score))

        # Severity Classification Tiers
        if final_score >= THRESHOLD_CRITICAL:
            risk_level = "CRITICAL"
            recommendations.insert(0, "🚨 CRITICAL THREAT: Cease communication immediately. Do not disclose PII or financial details.")
        elif final_score >= THRESHOLD_SUSPICIOUS:
            risk_level = "SUSPICIOUS"
            recommendations.insert(0, "⚠️ SUSPICIOUS OFFER: Significant anomalies detected. Secondary verification required before proceeding.")
        else:
            risk_level = "LOW RISK"
            recommendations.append("Standard caution advised: Verify official corporate communication channels.")

        return ThreatEvaluation(
            score=final_score,
            risk_level=risk_level,
            score_breakdown=breakdown,
            all_flags=all_flags,
            recommendations=recommendations,
            mitre_tags=list(set(mitre_tags))
        )
