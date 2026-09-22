"""
Live Threat Inspector View.
Main scanner tab for analyzing offer letters and domain infrastructure,
displaying interactive threat gauges, radar charts, and IoC breakdowns.
"""

import hashlib
from dataclasses import asdict
import streamlit as st

from src.config.settings import (
    SAMPLE_EQUIPMENT_SCAM,
    SAMPLE_SECURITY_DEPOSIT_SCAM,
    SAMPLE_LEGITIMATE_OFFER,
)
from src.database.db_manager import DatabaseManager
from src.services.text_parser import TextParser
from src.services.domain_verifier import DomainVerifier
from src.services.document_parser import DocumentParser
from src.services.scoring_engine import ThreatScoringEngine
from src.services.xai_engine import ExplainabilityEngine
from src.ui.components.metric_cards import (
    render_threat_banner,
    render_threat_gauge,
    render_radar_breakdown,
    render_telemetry_cards,
)
from src.ui.components.evidence_viewer import (
    render_ioc_list,
    render_snippets,
    render_mitre_mapping,
    render_playbook,
)
from src.ui.components.text_highlighter import render_text_highlight_heatmap
from src.ui.components.xai_visualizer import render_xai_dashboard
from src.ui.components.document_viewer import render_document_forensic_card


def render_inspector_view(
    db: DatabaseManager,
    parser: TextParser,
    verifier: DomainVerifier
) -> None:
    """Main Threat Inspector Tab for analyzing offer letters, mail documents, and domains."""
    # Pre-populate state
    default_text = st.session_state.get("sample_text", "")
    default_domain = st.session_state.get("sample_domain", "")
    doc_result = st.session_state.get("active_doc_result", None)

    # Input Mode Tabs
    tab_upload, tab_paste = st.tabs([
        "📁 Upload Mail / Document (.eml, .pdf, .docx, .txt, .html)",
        "✍️ Paste Raw Text & Quick Presets"
    ])

    with tab_upload:
        st.markdown(
            """
            <div style="font-size: 0.82rem; color: #94a3b8; margin-bottom: 8px;">
                Upload suspect job offer letters, recruiter email files (<code>.eml</code>, <code>.msg</code>), 
                or documents (<code>.pdf</code>, <code>.docx</code>, <code>.txt</code>, <code>.html</code>) for automated header extraction and linguistic threat analysis.
            </div>
            """,
            unsafe_allow_html=True
        )
        uploaded_file = st.file_uploader(
            "Select Document / Email File",
            type=["eml", "msg", "pdf", "docx", "txt", "html", "htm", "rtf"],
            label_visibility="collapsed",
            key="file_uploader_widget"
        )

        if uploaded_file is not None:
            # Check if file has changed
            current_file_hash = hashlib.sha256(uploaded_file.getvalue()).hexdigest()
            if st.session_state.get("last_uploaded_hash") != current_file_hash:
                with st.spinner(f"Parsing {uploaded_file.name}..."):
                    parsed_doc = DocumentParser.parse_file(uploaded_file.getvalue(), uploaded_file.name)
                    st.session_state["active_doc_result"] = parsed_doc
                    st.session_state["last_uploaded_hash"] = current_file_hash
                    st.session_state["sample_text"] = parsed_doc.extracted_text

                    # Auto-fill domain from email headers if available
                    if parsed_doc.email_metadata and parsed_doc.email_metadata.sender_domain:
                        st.session_state["sample_domain"] = parsed_doc.email_metadata.sender_domain
                    elif parsed_doc.embedded_urls:
                        # Extract domain from first embedded URL
                        first_url = parsed_doc.embedded_urls[0]
                        dom_part = first_url.split("//")[-1].split("/")[0].split(":")[0]
                        st.session_state["sample_domain"] = dom_part

                    st.session_state["has_scanned"] = False
                    st.rerun()

        if doc_result:
            st.success(
                f"✅ **Loaded {doc_result.file_format} artifact:** `{doc_result.filename}` "
                f"({doc_result.file_size / 1024.0:.1f} KB, {len(doc_result.extracted_text)} characters extracted)"
            )

    with tab_paste:
        # Top 1-Click Scenario Preset Cards
        st.markdown("##### ⚡ Quick-Load Forensic Threat Presets")
        sc_col1, sc_col2, sc_col3 = st.columns(3)

        with sc_col1:
            if st.button("Load Equipment Scam Sample", key="main_eq_sample", use_container_width=True):
                st.session_state["sample_text"] = SAMPLE_EQUIPMENT_SCAM["text"]
                st.session_state["sample_domain"] = SAMPLE_EQUIPMENT_SCAM["domain"]
                st.session_state["active_doc_result"] = None
                st.session_state["has_scanned"] = False
                st.rerun()

        with sc_col2:
            if st.button("Load Security Deposit Sample", key="main_dep_sample", use_container_width=True):
                st.session_state["sample_text"] = SAMPLE_SECURITY_DEPOSIT_SCAM["text"]
                st.session_state["sample_domain"] = SAMPLE_SECURITY_DEPOSIT_SCAM["domain"]
                st.session_state["active_doc_result"] = None
                st.session_state["has_scanned"] = False
                st.rerun()

        with sc_col3:
            if st.button("Load Legitimate Offer Sample", key="main_leg_sample", use_container_width=True):
                st.session_state["sample_text"] = SAMPLE_LEGITIMATE_OFFER["text"]
                st.session_state["sample_domain"] = SAMPLE_LEGITIMATE_OFFER["domain"]
                st.session_state["active_doc_result"] = None
                st.session_state["has_scanned"] = False
                st.rerun()

    st.markdown("<div style='margin-bottom: 12px;'></div>", unsafe_allow_html=True)

    # Re-fetch after potential rerun or tab switch
    default_text = st.session_state.get("sample_text", "")
    default_domain = st.session_state.get("sample_domain", "")
    doc_result = st.session_state.get("active_doc_result", None)

    col_input1, col_input2 = st.columns([2, 1])
    with col_input1:
        # Metadata counter
        char_count = len(default_text)
        word_count = len(default_text.split()) if default_text else 0
        hash_preview = hashlib.sha256(default_text.encode("utf-8")).hexdigest()[:12] if default_text else "e3b0c44298fc"

        st.markdown(
            f"""
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <span style="font-weight: 700; font-size: 0.88rem; color: #f8fafc;">📄 ACTIVE PAYLOAD / EXTRACTED TEXT:</span>
                <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.72rem; color: #94a3b8;">
                    CHARS: <b>{char_count}</b> | WORDS: <b>{word_count}</b> | SHA-256: <code style="color: #38bdf8;">{hash_preview}...</code>
                </span>
            </div>
            """,
            unsafe_allow_html=True
        )
        offer_text = st.text_area(
            "Input Text",
            value=default_text,
            height=240,
            label_visibility="collapsed",
            placeholder="Paste suspect job offer letters, recruiter emails, or view text extracted from uploaded documents..."
        )

    with col_input2:
        st.markdown(
            """
            <div style="font-weight: 700; font-size: 0.88rem; color: #f8fafc; margin-bottom: 6px;">
                🌐 RECRUITER DOMAIN / SENDER EMAIL:
            </div>
            """,
            unsafe_allow_html=True
        )
        domain_input = st.text_input(
            "Domain Input",
            value=default_domain,
            label_visibility="collapsed",
            placeholder="e.g. careers-google.com or hr@techcorp.xyz"
        )
        st.markdown(
            """
            <div style='background: rgba(17, 24, 39, 0.7); border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 8px; padding: 12px; font-size: 0.75rem; margin-top: 10px;'>
                <div style="color: #38bdf8; font-weight: 700; margin-bottom: 6px;">🎯 WEIGHTED SCORING MATRIX</div>
                <div>• Newly Registered Domain (&lt;180d): <b style="color: #f87171;">+40%</b></div>
                <div>• High-Risk Payment Channel: <b style="color: #f87171;">+20% each</b></div>
                <div>• Email Reply-To Mismatch: <b style="color: #f87171;">+25%</b></div>
                <div>• Masked WHOIS Privacy Shield: <b style="color: #fbbf24;">+20%</b></div>
                <div>• Suspicious File Attachment: <b style="color: #fbbf24;">+20%</b></div>
                <div>• Pay-for-Equipment / Advance Fee: <b style="color: #fbbf24;">+20%</b></div>
                <div>• Recruiter Free Webmail: <b style="color: #fbbf24;">+25%</b></div>
            </div>
            """,
            unsafe_allow_html=True
        )

        st.markdown("<div style='margin-top: 14px;'></div>", unsafe_allow_html=True)
        scan_clicked = st.button("⚡ EXECUTE FORENSIC INSPECTION", type="primary", key="btn_exec_scan", use_container_width=True)

    if scan_clicked or (default_text and not st.session_state.get("has_scanned", False)):
        st.session_state["has_scanned"] = True
        if not offer_text.strip() and not domain_input.strip():
            st.warning("⚠️ Please provide an offer letter payload or a recruiter domain to inspect.")
            return

        with st.spinner("Analyzing threat indicators, extracting IoCs, querying WHOIS/DNS intel..."):
            # 1. Text Parsing
            text_result = parser.analyze_text(offer_text)

            # 2. Domain Verification
            domain_result = None
            if domain_input.strip():
                domain_result = verifier.verify_domain(domain_input)

            # 3. Threat Scoring (with Document/Email Telemetry)
            eval_result = ThreatScoringEngine.evaluate(
                text_result,
                domain_result,
                doc_result=doc_result
            )

            # 4. Persistent Logging
            target_dom = domain_result.domain if domain_result else None
            scan_type = "Full Inspection" if (offer_text and domain_input) else ("Text Only" if offer_text else "Domain Only")
            if doc_result:
                scan_type = f"Document ({doc_result.file_format})"

            details = {
                "text_analysis": asdict(text_result),
                "domain_analysis": asdict(domain_result) if domain_result else None,
                "score_breakdown": eval_result.score_breakdown,
                "document_analysis": asdict(doc_result) if doc_result else None
            }
            db.log_scan(
                scan_type=scan_type,
                target_domain=target_dom,
                threat_score=eval_result.score,
                risk_level=eval_result.risk_level,
                detected_flags=eval_result.all_flags,
                details=details,
                payload_hash=text_result.payload_hash or (doc_result.sha256_hash if doc_result else "N/A")
            )

        # RENDER THREAT RESULTS
        st.markdown("---")
        _render_threat_results(
            eval_result,
            text_result,
            domain_result,
            raw_text=offer_text,
            doc_result=doc_result
        )


def _render_threat_results(
    eval_result,
    text_result,
    domain_result,
    raw_text: str = "",
    doc_result: Optional[DocumentAnalysisResult] = None
) -> None:
    """Renders comprehensive, color-coded executive security assessment, document forensics, and XAI explainability."""
    score = eval_result.score
    risk_level = eval_result.risk_level

    # Document / Email Forensics (If uploaded)
    if doc_result:
        render_document_forensic_card(doc_result)

    # Threat Banner Callout
    render_threat_banner(eval_result)

    # Dynamic Progress Bar
    progress_val = min(1.0, max(0.0, score / 100.0))
    st.progress(progress_val)

    # High-Level Metric Tiles
    col_m1, col_m2, col_m3, col_m4 = st.columns(4)
    with col_m1:
        st.metric("Threat Index", f"{score:.0f} / 100")
    with col_m2:
        st.metric("Risk Severity", risk_level)
    with col_m3:
        st.metric("Financial Keywords", text_result.financial_keyword_count)
    with col_m4:
        dom_age = f"{domain_result.domain_age_days} days" if (domain_result and domain_result.domain_age_days is not None) else "N/A"
        st.metric("Domain Age", dom_age)

    # Dual Visualization Cockpit: Gauge + Radar
    row1_col1, row1_col2 = st.columns([1, 1])

    with row1_col1:
        st.markdown("##### ⚡ Threat Severity Gauge")
        gauge_fig = render_threat_gauge(score, risk_level)
        st.plotly_chart(gauge_fig, use_container_width=True)

    with row1_col2:
        st.markdown("##### 🧭 6-Axis Threat Vector Radar")
        radar_fig = render_radar_breakdown(eval_result, text_result, domain_result)
        st.plotly_chart(radar_fig, use_container_width=True)

    # Infrastructure Telemetry Cards
    render_telemetry_cards(eval_result, text_result, domain_result)

    # --------------------------------------------------------------------------
    # EXPLAINABLE AI (XAI) SECTION: Heatmap + Attribution Waterfall + What-If
    # --------------------------------------------------------------------------
    xai_explanation = ExplainabilityEngine.explain(
        threat_evaluation=eval_result,
        text_result=text_result,
        domain_result=domain_result,
        raw_text=raw_text,
        doc_result=doc_result
    )

    # Render Visual Text Highlighting & Attribution Heatmap
    render_text_highlight_heatmap(xai_explanation)

    # Render Feature Attribution Waterfall & Counterfactual Reasoning
    render_xai_dashboard(xai_explanation)

    st.markdown("---")

    # Two-Column Detailed Findings & Playbook
    col_res1, col_res2 = st.columns([1.2, 1])

    with col_res1:
        st.markdown(f"##### 🚨 Detected Indicators of Compromise ({len(eval_result.all_flags)})")
        render_ioc_list(eval_result.score_breakdown)
        render_snippets(text_result.matched_snippets)

    with col_res2:
        render_mitre_mapping(eval_result.mitre_tags)
        render_playbook(eval_result.recommendations)
