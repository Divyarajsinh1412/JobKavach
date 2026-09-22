"""
Metric Cards, Threat Gauges, and Telemetry Widgets.
Provides visualizations for executive KPIs, Plotly neon gauges,
6-axis polar radar charts, and infrastructure badges.
"""

from typing import Dict, Optional, Any
import streamlit as st
import plotly.graph_objects as go

from src.models.schemas import ThreatEvaluation, TextAnalysisResult, DomainAnalysisResult


def render_header() -> None:
    """Renders top corporate header and SOC telemetry bar."""
    st.markdown(
        """
        <div class="soc-header-bar">
            <div>
                <div style="display: flex; align-items: center; gap: 12px;">
                    <span style="font-size: 1.8rem;">🛡️</span>
                    <div>
                        <h1 class="soc-brand-title">JOBKAVACH</h1>
                        <p class="soc-brand-subtitle">AI-Powered Offer Letter & Recruitment Phishing Defense System</p>
                    </div>
                </div>
            </div>
            <div style="display: flex; align-items: center; gap: 14px;">
                <div class="radar-pulse-box">
                    <div class="radar-dot"></div>
                    <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; color: #10b981; font-weight: 700;">
                        LIVE MONITORING
                    </span>
                </div>
                <span class="cyber-badge">ENGINE: O(N) LINEAR</span>
                <span class="cyber-badge">DB: WAL CONCURRENT</span>
                <span class="cyber-badge cyber-badge-green">ZERO-TRUST STRICT</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )


def render_kpi_bar(metrics: Dict[str, Any]) -> None:
    """Renders 5 high-density executive SIEM KPI cards."""
    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-label"><span>📊</span> Total Audited Scans</div>
                <div class="kpi-value">{metrics['total_scans']}</div>
                <div class="kpi-sub">Immutable Audit Records</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with col2:
        st.markdown(
            f"""
            <div class="kpi-card kpi-card-danger">
                <div class="kpi-label" style="color: #f87171;"><span>🚨</span> Critical Threats</div>
                <div class="kpi-value" style="color: #f87171;">{metrics['critical_scans']}</div>
                <div class="kpi-sub">Immediate Block Protocol</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with col3:
        st.markdown(
            f"""
            <div class="kpi-card kpi-card-warning">
                <div class="kpi-label" style="color: #fbbf24;"><span>⚠️</span> Suspicious In Triage</div>
                <div class="kpi-value" style="color: #fbbf24;">{metrics['suspicious_scans']}</div>
                <div class="kpi-sub">Secondary HR Review</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with col4:
        st.markdown(
            f"""
            <div class="kpi-card kpi-card-success">
                <div class="kpi-label" style="color: #34d399;"><span>🛡️</span> Verified Low Risk</div>
                <div class="kpi-value" style="color: #34d399;">{metrics['low_risk_scans']}</div>
                <div class="kpi-sub">Clean Corporate Profile</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with col5:
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-label"><span>⚡</span> Mean Threat Index</div>
                <div class="kpi-value" style="color: #38bdf8;">{metrics['avg_threat_score']}%</div>
                <div class="kpi-sub">Fleet Threat Average</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    st.markdown("<div style='margin-bottom: 20px;'></div>", unsafe_allow_html=True)


def render_threat_banner(eval_result: ThreatEvaluation) -> None:
    """Renders the top threat severity callout banner."""
    score = eval_result.score
    risk_level = eval_result.risk_level

    if risk_level == "CRITICAL":
        banner_class = "threat-banner-critical"
        badge_icon = "🚨"
        badge_text = "CRITICAL THREAT: IMMEDIATE BLOCK PROTOCOL"
        badge_color = "#f87171"
    elif risk_level == "SUSPICIOUS":
        banner_class = "threat-banner-suspicious"
        badge_icon = "⚠️"
        badge_text = "SUSPICIOUS OFFER: SECONDARY REVIEW REQUIRED"
        badge_color = "#fbbf24"
    else:
        banner_class = "threat-banner-low"
        badge_icon = "🛡️"
        badge_text = "LOW RISK: VERIFIED CORPORATE PROFILE"
        badge_color = "#34d399"

    st.markdown(
        f"""
        <div class="threat-banner {banner_class}">
            <div>
                <div style="font-size: 0.8rem; font-weight: 700; letter-spacing: 1px; color: {badge_color};">
                    {badge_icon} SECURITY VERDICT // {badge_text}
                </div>
                <div style="font-size: 1.8rem; font-weight: 800; font-family: 'Plus Jakarta Sans', sans-serif; color: #f8fafc; margin-top: 4px;">
                    Threat Index Rating: <span style="font-family: 'JetBrains Mono'; color: {badge_color};">{score:.0f}%</span>
                </div>
                <div style="font-size: 0.82rem; color: #cbd5e1; margin-top: 4px;">
                    Evaluation identified <b>{len(eval_result.all_flags)}</b> indicator(s) of compromise across linguistic and infrastructure vectors.
                </div>
            </div>
            <div style="text-align: right;">
                <span class="cyber-badge" style="font-size: 0.85rem; padding: 6px 14px; border-color: {badge_color}; color: {badge_color};">
                    LEVEL: {risk_level}
                </span>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )


def render_threat_gauge(score: float, risk_level: str) -> go.Figure:
    """Renders an interactive dark-styled neon threat gauge."""
    color_map = {
        "CRITICAL": "#ef4444",
        "SUSPICIOUS": "#f59e0b",
        "LOW RISK": "#10b981",
    }
    accent_color = color_map.get(risk_level, "#38bdf8")

    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            number={"suffix": "%", "font": {"size": 48, "color": "#f8fafc", "family": "JetBrains Mono"}},
            title={"text": f"RISK POSTURE: {risk_level}", "font": {"size": 13, "color": "#94a3b8", "family": "Plus Jakarta Sans"}},
            gauge={
                "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "#475569"},
                "bar": {"color": accent_color, "thickness": 0.28},
                "bgcolor": "#0d1322",
                "borderwidth": 1,
                "bordercolor": "#1e293b",
                "steps": [
                    {"range": [0, 29], "color": "rgba(16, 185, 129, 0.12)"},
                    {"range": [29, 69], "color": "rgba(245, 158, 11, 0.12)"},
                    {"range": [69, 100], "color": "rgba(239, 68, 68, 0.18)"},
                ],
                "threshold": {
                    "line": {"color": "#dc2626", "width": 4},
                    "thickness": 0.75,
                    "value": 70,
                },
            },
        )
    )
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        height=250,
        margin=dict(l=25, r=25, t=35, b=25),
    )
    return fig


def render_radar_breakdown(
    eval_result: ThreatEvaluation,
    text_result: TextAnalysisResult,
    domain_result: Optional[DomainAnalysisResult]
) -> go.Figure:
    """Renders an interactive 6-axis polar threat radar chart."""
    categories = [
        "Domain Age (<180d)",
        "WHOIS Privacy",
        "Financial Keywords",
        "Equipment Scam",
        "Webmail Spoofing",
        "Urgency Pressure",
    ]
    val_domain_age = 40.0 if (domain_result and domain_result.is_new_domain) else 0.0
    val_whois = 20.0 if (domain_result and domain_result.is_masked) else 0.0
    val_financial = min(40.0, text_result.financial_keyword_count * 20.0)
    val_equip = 20.0 if (text_result.equipment_flags or text_result.deposit_flags) else 0.0
    val_webmail = 25.0 if text_result.webmail_flags else 0.0
    val_urgency = 15.0 if text_result.urgency_flags else 0.0

    values = [val_domain_age, val_whois, val_financial, val_equip, val_webmail, val_urgency]
    categories_closed = categories + [categories[0]]
    values_closed = values + [values[0]]

    fig = go.Figure(
        data=go.Scatterpolar(
            r=values_closed,
            theta=categories_closed,
            fill="toself",
            fillcolor="rgba(56, 189, 248, 0.22)",
            line=dict(color="#38bdf8", width=2),
            marker=dict(color="#38bdf8", size=6),
        )
    )
    fig.update_layout(
        polar=dict(
            radialaxis=dict(visible=True, range=[0, 45], color="#64748b", gridcolor="#1e293b"),
            angularaxis=dict(color="#94a3b8", gridcolor="#1e293b"),
            bgcolor="#0d1322",
        ),
        paper_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=35, r=35, t=25, b=25),
        height=250,
        showlegend=False,
    )
    return fig


def render_telemetry_cards(
    eval_result: ThreatEvaluation,
    text_result: TextAnalysisResult,
    domain_result: Optional[DomainAnalysisResult]
) -> None:
    """Renders 4 infrastructure & forensic telemetry cyber tiles."""
    st.markdown("##### 🌐 Infrastructure & Forensic Telemetry")
    t_col1, t_col2, t_col3, t_col4 = st.columns(4)

    with t_col1:
        dom_age = f"{domain_result.domain_age_days} Days" if (domain_result and domain_result.domain_age_days is not None) else "Unresolved / N/A"
        is_new = domain_result.is_new_domain if domain_result else False
        badge_cls = "cyber-badge-red" if is_new else "cyber-badge-green"
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-label">Domain Registration Age</div>
                <div class="kpi-value" style="font-size: 1.4rem;">{dom_age}</div>
                <div style="margin-top: 6px;"><span class="cyber-badge {badge_cls}">{"<180d HIGH RISK" if is_new else "MATURE DOMAIN"}</span></div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with t_col2:
        is_masked = domain_result.is_masked if domain_result else False
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-label">WHOIS Privacy Shield</div>
                <div class="kpi-value" style="font-size: 1.4rem;">{'ACTIVE' if is_masked else 'PUBLIC'}</div>
                <div style="margin-top: 6px;"><span class="cyber-badge {'cyber-badge-amber' if is_masked else 'cyber-badge-green'}">{'MASKED PROXY' if is_masked else 'ATTRIBUTED'}</span></div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with t_col3:
        reg_name = domain_result.registrar if (domain_result and domain_result.registrar) else "Unknown"
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-label">Domain Registrar</div>
                <div class="kpi-value" style="font-size: 1.1rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">{reg_name[:18]}</div>
                <div style="margin-top: 6px;"><span class="cyber-badge">DNS VERIFIED</span></div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with t_col4:
        hash_display = text_result.payload_hash[:16] + "..." if text_result.payload_hash else "N/A"
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-label">Payload SHA-256</div>
                <div class="kpi-value" style="font-size: 1.0rem; font-family: monospace;">{hash_display}</div>
                <div style="margin-top: 6px;"><span class="cyber-badge">CHAIN OF CUSTODY</span></div>
            </div>
            """,
            unsafe_allow_html=True
        )
    st.markdown("<div style='margin-bottom: 20px;'></div>", unsafe_allow_html=True)
