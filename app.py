"""
================================================================================
           FAKE OFFER LETTER & PHISHING INSPECTOR - ENTERPRISE EDITION
================================================================================
Main application entry point orchestrating modular presentation views,
core threat analysis engines, and persistent SQLite audit logging.

Author: Principal Software Architect & Security Engineer
Tech Stack: Streamlit, Python 3.10+, SQLite (WAL), Plotly, python-whois
================================================================================
"""

import sys
import os
import logging
import streamlit as st

# Ensure project root is on sys.path for direct script execution
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Core Configuration & Settings
from src.config.settings import (
    SAMPLE_EQUIPMENT_SCAM,
    SAMPLE_SECURITY_DEPOSIT_SCAM,
    SAMPLE_LEGITIMATE_OFFER,
)

# Domain Models
from src.models.schemas import (
    TextAnalysisResult,
    DomainAnalysisResult,
    ThreatEvaluation,
    AuditRecord,
    User,
)

# Persistence & Services
from src.database.db_manager import DatabaseManager
from src.services.text_parser import TextParser
from src.services.domain_verifier import DomainVerifier
from src.services.scoring_engine import ThreatScoringEngine

# Presentation Components & Views
from src.ui.styles import inject_custom_css
from src.ui.components.metric_cards import render_header, render_kpi_bar
from src.ui.components.splash_screen import render_splash_screen
from src.ui.views.auth_view import render_auth_view
from src.ui.views.inspector_view import render_inspector_view
from src.ui.views.ledger_view import render_ledger_view
from src.ui.views.methodology_view import render_methodology_view

# Configure structured audit logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [SOC-AUDIT] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("JobKavach.App")


def render_sidebar(db: DatabaseManager) -> None:
    """Renders sidebar controls, analyst session info, database metrics, and sample loaders."""
    with st.sidebar:
        user = st.session_state.get("authenticated_user")
        if user:
            st.markdown(
                f"""
                <div style="background: rgba(15, 23, 42, 0.9); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 10px; padding: 12px; margin-bottom: 14px;">
                    <div style="font-size: 0.72rem; color: #38bdf8; font-weight: 800; letter-spacing: 0.08em; text-transform: uppercase;">
                        AUTHENTICATED ANALYST
                    </div>
                    <div style="font-weight: 700; color: #f8fafc; font-size: 0.95rem; margin-top: 2px;">
                        {user.full_name}
                    </div>
                    <div style="font-size: 0.74rem; color: #94a3b8; font-family: 'JetBrains Mono', monospace;">
                        {user.email}
                    </div>
                    <div style="margin-top: 6px;">
                        <span style="background: rgba(16, 185, 129, 0.2); color: #10b981; border: 1px solid #10b981; font-size: 0.68rem; font-weight: 700; padding: 2px 6px; border-radius: 4px;">
                            {user.role}
                        </span>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
            if st.button("🚪 Log Out", key="sb_logout_btn", use_container_width=True):
                st.session_state["authenticated_user"] = None
                st.session_state["show_splash"] = False
                st.rerun()

        st.subheader("⚡ Threat Intel Controls")
        st.info(
            "JobKavach inspects suspect job offer letters, recruiter emails, and domain "
            "infrastructure for advance-fee fraud, check overpayment schemes, "
            "and domain impersonation."
        )

        st.markdown("### 🧪 Load Evaluation Samples")
        if st.button("Load Equipment Scam Sample", key="sb_eq_sample", use_container_width=True):
            st.session_state["sample_text"] = SAMPLE_EQUIPMENT_SCAM["text"]
            st.session_state["sample_domain"] = SAMPLE_EQUIPMENT_SCAM["domain"]
            st.session_state["active_doc_result"] = None
            st.session_state["has_scanned"] = False
            st.rerun()

        if st.button("Load Security Deposit Sample", key="sb_dep_sample", use_container_width=True):
            st.session_state["sample_text"] = SAMPLE_SECURITY_DEPOSIT_SCAM["text"]
            st.session_state["sample_domain"] = SAMPLE_SECURITY_DEPOSIT_SCAM["domain"]
            st.session_state["active_doc_result"] = None
            st.session_state["has_scanned"] = False
            st.rerun()

        if st.button("Load Legitimate Offer Sample", key="sb_leg_sample", use_container_width=True):
            st.session_state["sample_text"] = SAMPLE_LEGITIMATE_OFFER["text"]
            st.session_state["sample_domain"] = SAMPLE_LEGITIMATE_OFFER["domain"]
            st.session_state["active_doc_result"] = None
            st.session_state["has_scanned"] = False
            st.rerun()

        st.markdown("---")
        st.markdown("### 📊 Ledger Metrics")
        metrics = db.get_summary_metrics()
        col_a, col_b = st.columns(2)
        with col_a:
            st.metric("Total Scans", metrics["total_scans"])
            st.metric("Critical", metrics["critical_scans"])
        with col_b:
            st.metric("Avg Threat", f"{metrics['avg_threat_score']}%")
            st.metric("Suspicious", metrics["suspicious_scans"])


def main():
    """Application bootstrap entrypoint orchestrating UI, authentication, and services."""
    st.set_page_config(
        page_title="JobKavach - AI Phishing & Fake Offer Defense",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # 1. Initialize Persistence Layer & Business Services
    db_manager = DatabaseManager(db_path="threat_scanner.db")
    text_parser = TextParser()
    domain_verifier = DomainVerifier()

    # 2. Inject Dark SOC Cyber Styles
    inject_custom_css()

    # 3. Splashscreen Routing (Displayed on first visit or when requested)
    if st.session_state.get("show_splash", True):
        render_splash_screen()
        return

    # 4. Authentication Guard
    if not st.session_state.get("authenticated_user"):
        render_auth_view(db_manager)
        return

    # 5. Authenticated SOC Command Center Shell
    render_header()
    render_sidebar(db_manager)

    summary_metrics = db_manager.get_summary_metrics()
    render_kpi_bar(summary_metrics)

    # 6. Render Modular Views across 3 Core Tabs
    tab_inspect, tab_ledger, tab_arch = st.tabs([
        "Live Threat Inspector",
        "SOC Audit Ledger",
        "Architecture & Methodology"
    ])

    with tab_inspect:
        render_inspector_view(db=db_manager, parser=text_parser, verifier=domain_verifier)

    with tab_ledger:
        render_ledger_view(db=db_manager)

    with tab_arch:
        render_methodology_view()


if __name__ == "__main__":
    main()

# Re-exports for backwards compatibility and automated testing harnesses
__all__ = [
    "DatabaseManager",
    "TextParser",
    "DomainVerifier",
    "ThreatScoringEngine",
    "TextAnalysisResult",
    "DomainAnalysisResult",
    "ThreatEvaluation",
    "AuditRecord",
    "main",
]
