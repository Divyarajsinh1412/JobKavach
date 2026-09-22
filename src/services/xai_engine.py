"""
Explainable AI (XAI) Engine.
Computes SHAP-style feature attributions, algorithmic decision confidence,
counterfactual 'what-if' reasoning, executive forensic narratives, and XSS-safe text highlights.
"""

import html
import re
import logging
from typing import List, Dict, Optional, Tuple, Any

from src.config.settings import (
    THRESHOLD_CRITICAL,
    THRESHOLD_SUSPICIOUS,
    WEIGHT_DOMAIN_AGE_NEW,
    WEIGHT_FINANCIAL_KEYWORD,
    WEIGHT_WHOIS_MASKED,
    WEIGHT_EQUIPMENT_ADVANCE_FEE,
    WEIGHT_WEBMAIL_RECRUITER,
    WEIGHT_URGENCY_COERCION,
    WEIGHT_REPLY_TO_MISMATCH,
    WEIGHT_SUSPICIOUS_ATTACHMENT,
    WEIGHT_AUTH_HEADER_FAIL,
)
from src.models.schemas import (
    ThreatEvaluation,
    TextAnalysisResult,
    DomainAnalysisResult,
    DocumentAnalysisResult,
    FeatureAttribution,
    CounterfactualScenario,
    XAIExplanation,
)

logger = logging.getLogger("PhishingInspector.XAI")


class ExplainabilityEngine:
    """
    Enterprise Explainable AI Engine providing deterministic interpretability,
    counterfactual what-if reasoning, and visual heatmap generation.
    """

    @classmethod
    def explain(
        cls,
        threat_evaluation: ThreatEvaluation,
        text_result: TextAnalysisResult,
        domain_result: Optional[DomainAnalysisResult] = None,
        raw_text: str = "",
        doc_result: Optional[DocumentAnalysisResult] = None
    ) -> XAIExplanation:
        """
        Master method synthesizing all explainability dimensions into a structured XAIExplanation.
        """
        # 1. Feature Attribution
        attributions = cls.compute_attributions(threat_evaluation, text_result, domain_result, doc_result)

        # 2. Algorithmic Decision Confidence
        confidence = cls.compute_decision_confidence(threat_evaluation, attributions, domain_result)

        # 3. Counterfactual What-If Scenarios
        counterfactuals = cls.generate_counterfactuals(threat_evaluation, attributions)

        # 4. Forensic Narrative & Driver Breakdown
        primary_driver, corroborating, evasion_signals, narrative = cls.generate_forensic_summary(
            threat_evaluation, attributions
        )

        # 5. Visual Text Highlighting (XSS-Safe)
        highlighted_html = cls.generate_highlighted_html(
            raw_text, text_result.matched_snippets, attributions, doc_result
        )

        return XAIExplanation(
            baseline_risk=0.0,
            posterior_score=threat_evaluation.score,
            decision_confidence=confidence,
            attributions=attributions,
            primary_driver=primary_driver,
            corroborating_evidence=corroborating,
            evasion_signals=evasion_signals,
            forensic_narrative=narrative,
            counterfactuals=counterfactuals,
            highlighted_html=highlighted_html,
        )

    @classmethod
    def compute_attributions(
        cls,
        threat_evaluation: ThreatEvaluation,
        text_result: TextAnalysisResult,
        domain_result: Optional[DomainAnalysisResult] = None,
        doc_result: Optional[DocumentAnalysisResult] = None
    ) -> List[FeatureAttribution]:
        """
        Computes SHAP-style individual feature contributions (deltas) for all observed signals.
        """
        attributions: List[FeatureAttribution] = []
        total_raw_weight = 0.0

        # 1. Domain Registration Age
        if domain_result and domain_result.is_new_domain:
            w = WEIGHT_DOMAIN_AGE_NEW
            total_raw_weight += w
            age_display = f"{domain_result.domain_age_days}d" if domain_result.domain_age_days is not None else "<180d"
            attributions.append(FeatureAttribution(
                feature_name=f"Newly Registered Domain ({age_display})",
                category="Infrastructure",
                weight=w,
                percentage_impact=0.0,  # Computed below
                direction="INCREASES_RISK",
                evidence=f"Domain '{domain_result.domain}' created recently. Disposable infrastructure indicator.",
                color_hex="#ef4444"
            ))

        # 2. Masked WHOIS Privacy Proxy
        if domain_result and domain_result.is_masked:
            w = WEIGHT_WHOIS_MASKED
            total_raw_weight += w
            attributions.append(FeatureAttribution(
                feature_name="Concealed WHOIS Privacy Shield",
                category="Infrastructure",
                weight=w,
                percentage_impact=0.0,
                direction="INCREASES_RISK",
                evidence="Registrant identity obscured by proxy guard service.",
                color_hex="#f59e0b"
            ))

        # 3. High-Risk Payment Channels (Individual Keyword Deltas)
        if text_result.financial_keywords_found:
            for kw in text_result.financial_keywords_found:
                w = WEIGHT_FINANCIAL_KEYWORD
                total_raw_weight += w
                attributions.append(FeatureAttribution(
                    feature_name=f"Payment Channel: '{kw}'",
                    category="Financial Channel",
                    weight=w,
                    percentage_impact=0.0,
                    direction="INCREASES_RISK",
                    evidence=f"Irreversible or non-standard corporate payment channel detected: '{kw}'.",
                    color_hex="#ef4444"
                ))

        # 4. Equipment Purchase / Advance Fee Traps
        if text_result.equipment_flags or text_result.deposit_flags:
            w = WEIGHT_EQUIPMENT_ADVANCE_FEE
            total_raw_weight += w
            items = text_result.equipment_flags + text_result.deposit_flags
            attributions.append(FeatureAttribution(
                feature_name="Equipment Scam / Advance-Fee Pattern",
                category="Linguistic Trap",
                weight=w,
                percentage_impact=0.0,
                direction="INCREASES_RISK",
                evidence=f"Detected check overpayment, equipment stipend, or mandatory deposit phrasing ({len(items)} match(es)).",
                color_hex="#ef4444"
            ))

        # 5. Recruiter Webmail Impersonation
        if text_result.webmail_flags:
            w = WEIGHT_WEBMAIL_RECRUITER
            total_raw_weight += w
            attributions.append(FeatureAttribution(
                feature_name="Recruiter Webmail Spoofing",
                category="Identity",
                weight=w,
                percentage_impact=0.0,
                direction="INCREASES_RISK",
                evidence=f"Free public webmail ({', '.join(text_result.webmail_flags)}) used in official employment context.",
                color_hex="#38bdf8"
            ))

        # 6. Coercive Urgency & Pressure Demands
        if text_result.urgency_flags:
            w = WEIGHT_URGENCY_COERCION
            total_raw_weight += w
            attributions.append(FeatureAttribution(
                feature_name="Coercive Urgency & Pressure",
                category="Social Engineering",
                weight=w,
                percentage_impact=0.0,
                direction="INCREASES_RISK",
                evidence=f"Artificial deadlines and secrecy demands ({len(text_result.urgency_flags)} trigger(s)).",
                color_hex="#f59e0b"
            ))

        # 7. Document & Email Telemetry Attributions
        if doc_result and doc_result.email_metadata:
            em = doc_result.email_metadata

            # 7a. Reply-To Mismatch (+25%)
            if em.reply_to_mismatch:
                w = WEIGHT_REPLY_TO_MISMATCH
                total_raw_weight += w
                attributions.append(FeatureAttribution(
                    feature_name="Email Reply-To Mismatch",
                    category="Identity & Transport",
                    weight=w,
                    percentage_impact=0.0,
                    direction="INCREASES_RISK",
                    evidence=f"Replies redirected to '{em.reply_to}' instead of sender '{em.sender}'.",
                    color_hex="#ef4444"
                ))

            # 7b. Suspicious Attachments (+20%)
            susp_atts = [a for a in em.attachments if a.is_suspicious]
            if susp_atts:
                w = WEIGHT_SUSPICIOUS_ATTACHMENT
                total_raw_weight += w
                att_names = ", ".join(a.filename for a in susp_atts)
                attributions.append(FeatureAttribution(
                    feature_name="Suspicious Attachment Payload",
                    category="Payload Risk",
                    weight=w,
                    percentage_impact=0.0,
                    direction="INCREASES_RISK",
                    evidence=f"High-risk executable, script, or compressed file attached: {att_names}.",
                    color_hex="#ef4444"
                ))

            # 7c. Email Auth Failures (+20%)
            if em.spf_status == "FAIL" or em.dkim_status == "FAIL":
                w = WEIGHT_AUTH_HEADER_FAIL
                total_raw_weight += w
                attributions.append(FeatureAttribution(
                    feature_name="Email Transport Auth Failure",
                    category="Identity & Transport",
                    weight=w,
                    percentage_impact=0.0,
                    direction="INCREASES_RISK",
                    evidence=f"Transport authentication failed (SPF: {em.spf_status or 'N/A'}, DKIM: {em.dkim_status or 'N/A'}).",
                    color_hex="#f59e0b"
                ))

        # 8. Benign Offsets (Negative Deltas)
        if not attributions and domain_result and domain_result.lookup_successful and not domain_result.is_new_domain:
            # Established corporate domain with clean text
            attributions.append(FeatureAttribution(
                feature_name="Established Corporate Infrastructure",
                category="Trust Factor",
                weight=-10.0,
                percentage_impact=100.0,
                direction="DECREASES_RISK",
                evidence=f"Domain '{domain_result.domain}' age ({domain_result.domain_age_days}d) indicates mature legitimate enterprise profile.",
                color_hex="#10b981"
            ))
            return attributions

        # Calculate normalized percentage impacts
        if total_raw_weight > 0:
            for attr in attributions:
                attr.percentage_impact = round((attr.weight / total_raw_weight) * 100.0, 1)

        return attributions

    @classmethod
    def compute_decision_confidence(
        cls,
        threat_evaluation: ThreatEvaluation,
        attributions: List[FeatureAttribution],
        domain_result: Optional[DomainAnalysisResult] = None
    ) -> float:
        """
        Calculates an algorithmic Decision Confidence Score (0–100%) reflecting signal density,
        multi-vector corroboration, and DNS/WHOIS resolution certainty.
        """
        score = threat_evaluation.score
        if score == 0.0 and (not domain_result or domain_result.lookup_successful):
            return 95.0  # High confidence in clean verdict

        # Base confidence
        confidence = 55.0

        # Multi-vector convergence bonus (infrastructure + linguistic)
        categories = set(a.category for a in attributions)
        if len(categories) >= 3:
            confidence += 25.0
        elif len(categories) == 2:
            confidence += 15.0

        # High signal density bonus
        if len(attributions) >= 4:
            confidence += 12.0
        elif len(attributions) >= 2:
            confidence += 6.0

        # WHOIS resolution confirmation
        if domain_result and domain_result.lookup_successful:
            confidence += 8.0

        # Clamp between 20% and 99%
        return min(99.0, max(20.0, round(confidence, 1)))

    @classmethod
    def generate_counterfactuals(
        cls,
        threat_evaluation: ThreatEvaluation,
        attributions: List[FeatureAttribution]
    ) -> List[CounterfactualScenario]:
        """
        Answers: "What specific factors must change for this offer to be classified as LOW RISK / BENIGN?"
        Calculates the minimal subset of high-impact factors to eliminate to bring score < 30%.
        """
        current_score = threat_evaluation.score
        scenarios: List[CounterfactualScenario] = []

        if current_score < THRESHOLD_SUSPICIOUS:
            scenarios.append(CounterfactualScenario(
                factors_to_change=[],
                score_reduction=0.0,
                target_score=current_score,
                target_risk_tier="LOW RISK",
                narrative="Offer is already classified as LOW RISK. Current telemetry presents no critical fraud vectors."
            ))
            return scenarios

        # Target is strictly below THRESHOLD_SUSPICIOUS (30%)
        target_max_score = THRESHOLD_SUSPICIOUS - 5.0  # 25.0%
        required_reduction = current_score - target_max_score

        # Sort positive attributions by weight descending
        positive_attrs = sorted([a for a in attributions if a.weight > 0], key=lambda a: a.weight, reverse=True)

        accumulated_reduction = 0.0
        factors_selected: List[str] = []

        for attr in positive_attrs:
            factors_selected.append(f"{attr.feature_name} (-{attr.weight:.0f}%)")
            accumulated_reduction += attr.weight
            if current_score - accumulated_reduction <= target_max_score:
                break

        final_projected_score = max(0.0, current_score - accumulated_reduction)
        target_tier = "LOW RISK" if final_projected_score < THRESHOLD_SUSPICIOUS else "SUSPICIOUS"

        narrative_text = (
            f"If {', and '.join(factors_selected)} were resolved or eliminated, "
            f"the Threat Index would drop from {current_score:.0f}% to {final_projected_score:.0f}% ({target_tier})."
        )

        scenarios.append(CounterfactualScenario(
            factors_to_change=factors_selected,
            score_reduction=accumulated_reduction,
            target_score=final_projected_score,
            target_risk_tier=target_tier,
            narrative=narrative_text
        ))

        return scenarios

    @classmethod
    def generate_forensic_summary(
        cls,
        threat_evaluation: ThreatEvaluation,
        attributions: List[FeatureAttribution]
    ) -> Tuple[Optional[FeatureAttribution], List[FeatureAttribution], List[FeatureAttribution], str]:
        """
        Synthesizes an executive-ready, legally defensible audit explanation:
        - Primary Driver: single highest-weighted factor.
        - Corroborating Evidence: secondary signals reinforcing the verdict.
        - Anomalous Evasion Signals: concealed WHOIS or obfuscated contact channels.
        """
        if not attributions or all(a.weight <= 0 for a in attributions):
            narrative = (
                "Forensic inspection completed with clean telemetry. No pay-for-equipment phishing patterns, "
                "unauthorized payment channels, or domain registration anomalies were detected. "
                "The payload presents standard enterprise recruitment characteristics."
            )
            return None, [], [], narrative

        # Sort positive attributions by weight descending
        sorted_attrs = sorted([a for a in attributions if a.weight > 0], key=lambda a: a.weight, reverse=True)
        primary_driver = sorted_attrs[0]
        corroborating = sorted_attrs[1:]

        evasion_signals = [
            a for a in attributions
            if "WHOIS" in a.feature_name or "Webmail" in a.feature_name or "Urgency" in a.feature_name
        ]

        # Compose executive legal/forensic narrative
        lines = [
            f"The candidate communication was evaluated with a Threat Index rating of {threat_evaluation.score:.0f}% ({threat_evaluation.risk_level}).",
            f"The PRIMARY DRIVER of this assessment is: {primary_driver.feature_name} (+{primary_driver.weight:.0f}%), characterized by {primary_driver.evidence}."
        ]

        if corroborating:
            corroborating_summary = "; ".join([f"{c.feature_name} (+{c.weight:.0f}%)" for c in corroborating[:3]])
            lines.append(f"This assessment is corroborated by secondary indicators: {corroborating_summary}.")

        if evasion_signals:
            evasion_summary = ", ".join([e.feature_name for e in evasion_signals])
            lines.append(f"Notable evasion and social engineering traits include: {evasion_summary}.")

        lines.append("Conclusion: Maintain zero-trust protocols. Prevent PII disclosure or financial transactions until identity is verified out-of-band.")

        narrative = " ".join(lines)
        return primary_driver, corroborating, evasion_signals, narrative

    @classmethod
    def generate_highlighted_html(
        cls,
        raw_text: str,
        matched_snippets: List[Dict[str, str]],
        attributions: List[FeatureAttribution],
        doc_result: Optional[DocumentAnalysisResult] = None
    ) -> str:
        """
        Renders the scanned job offer text with an interactive, XSS-safe HTML/CSS color-coded overlay:
        - Red: Critical fraud triggers (equipment checks, advance fees, crypto/wire transfer, reply-to mismatch).
        - Amber: Urgency and social engineering pressure points.
        - Blue: Recruiter contacts and domain references.
        Includes hover tooltips indicating exact percentage points added.
        """
        if not raw_text or not raw_text.strip():
            return "<div style='color: #94a3b8; font-style: italic;'>No offer text provided for attribution highlighting.</div>"

        # 1. CRITICAL: Strictly sanitize input to prevent Cross-Site Scripting (XSS)
        safe_text = html.escape(raw_text)

        # 2. Build term-to-style mapping
        # Term -> (category, color_class, tooltip_text)
        term_map: Dict[str, Tuple[str, str, str]] = {}

        for item in matched_snippets:
            term = html.escape(item.get("term", "").strip())
            category = item.get("category", "")
            if not term or len(term) < 2:
                continue

            if category in ["Financial Channel", "Pay-For-Equipment Trap", "Advance Fee / Deposit"]:
                color_class = "hl-red"
                tooltip = f"CRITICAL FRAUD TRIGGER: +20% Threat Impact ({category})"
            elif category == "Urgent Coercion":
                color_class = "hl-amber"
                tooltip = "COERCIVE PRESSURE: +15% Threat Impact (Social Engineering)"
            elif category == "Recruiter Impersonation":
                color_class = "hl-blue"
                tooltip = "RECRUITER SPOOFING: +25% Threat Impact (Identity Anomaly)"
            else:
                color_class = "hl-amber"
                tooltip = f"THREAT INDICATOR: {category}"

            term_map[term.lower()] = (term, color_class, tooltip)

        # Document/Email Telemetry Terms
        if doc_result and doc_result.email_metadata:
            em = doc_result.email_metadata
            if em.reply_to_mismatch and em.reply_to:
                clean_rt = html.escape(em.reply_to.strip())
                if len(clean_rt) >= 3:
                    term_map[clean_rt.lower()] = (clean_rt, "hl-red", "REPLY-TO REDIRECTION: +25% Threat Impact (Spoofing)")
            for att in em.attachments:
                if att.is_suspicious and att.filename:
                    clean_att = html.escape(att.filename.strip())
                    term_map[clean_att.lower()] = (clean_att, "hl-red", f"HIGH-RISK ATTACHMENT: +20% Threat Impact ({att.reason})")

        # 3. Sort terms by length descending to prevent sub-string overlap corruption
        sorted_terms = sorted(term_map.keys(), key=len, reverse=True)

        # 4. Perform bounded regex replacement on the sanitized HTML string
        highlighted = safe_text
        for term_lower in sorted_terms:
            orig_term, color_class, tooltip = term_map[term_lower]
            pattern = re.compile(re.escape(orig_term), re.IGNORECASE)
            
            def replace_fn(match):
                matched_str = match.group(0)
                return (
                    f'<mark class="xai-mark {color_class}" data-tooltip="{tooltip}">'
                    f'{matched_str}'
                    f'</mark>'
                )

            highlighted = pattern.sub(replace_fn, highlighted)

        # Convert line breaks to HTML breaks for formatting
        highlighted = highlighted.replace("\n", "<br>")

        return f'<div class="xai-text-container">{highlighted}</div>'
