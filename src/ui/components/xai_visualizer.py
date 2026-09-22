"""
Explainable AI (XAI) Visualizer Component.
Renders SHAP-style feature attribution waterfall/bar charts, algorithmic decision confidence meters,
forensic executive summaries, and counterfactual 'what-if' reasoning scenarios.
"""

from typing import List, Dict, Any
import streamlit as st
import plotly.graph_objects as go

from src.models.schemas import XAIExplanation, FeatureAttribution, CounterfactualScenario


def render_xai_dashboard(xai_explanation: XAIExplanation) -> None:
    """Renders the comprehensive Explainable AI dashboard."""
    st.markdown("### 🧠 Explainable AI (XAI) // Decision Attribution & Reasoning")
    st.caption("Transparent algorithmic breakdown: SHAP-style feature attribution, confidence metrics, and counterfactual analysis.")

    # 1. Decision Confidence & Forensic Rationale Banner
    _render_forensic_rationale_card(xai_explanation)

    # 2. Dual Column: Attribution Waterfall Chart + Counterfactual What-If Reasoning
    col_chart, col_whatif = st.columns([1.2, 1])

    with col_chart:
        st.markdown("##### 📊 SHAP-Style Feature Attribution Path")
        attribution_fig = render_attribution_waterfall(xai_explanation)
        st.plotly_chart(attribution_fig, use_container_width=True)

    with col_whatif:
        st.markdown("##### 🔮 Counterfactual 'What-If' Reasoning")
        _render_counterfactual_card(xai_explanation)


def _render_forensic_rationale_card(xai: XAIExplanation) -> None:
    """Renders algorithmic confidence and structured forensic rationale."""
    conf = xai.decision_confidence
    if conf >= 80.0:
        conf_badge = f'<span class="cyber-badge cyber-badge-green">HIGH CERTAINTY: {conf:.0f}%</span>'
    elif conf >= 50.0:
        conf_badge = f'<span class="cyber-badge cyber-badge-amber">MODERATE CERTAINTY: {conf:.0f}%</span>'
    else:
        conf_badge = f'<span class="cyber-badge cyber-badge-red">LOW CERTAINTY: {conf:.0f}%</span>'

    st.markdown(
        f"""
        <div style="background: linear-gradient(135deg, rgba(15, 23, 42, 0.95) 0%, rgba(20, 30, 55, 0.9) 100%); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 10px; padding: 18px 22px; margin-bottom: 20px; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                <div style="font-family: 'Plus Jakarta Sans', sans-serif; font-weight: 700; font-size: 1.05rem; color: #f8fafc; display: flex; align-items: center; gap: 8px;">
                    <span>⚖️</span> Executive Forensic Rationale & Attributions
                </div>
                <div>
                    {conf_badge}
                </div>
            </div>
            <div style="font-size: 0.85rem; color: #cbd5e1; line-height: 1.6; margin-bottom: 14px;">
                {xai.forensic_narrative}
            </div>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 12px; font-size: 0.78rem;">
                <div style="background: rgba(10, 15, 30, 0.7); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 6px; padding: 10px 12px;">
                    <div style="color: #f87171; font-weight: 700; text-transform: uppercase; font-family: 'JetBrains Mono'; margin-bottom: 4px;">
                        🎯 Primary Driver (+{xai.primary_driver.weight if xai.primary_driver else 0:.0f}%)
                    </div>
                    <div style="color: #f1f5f9; font-weight: 600;">
                        {xai.primary_driver.feature_name if xai.primary_driver else "None (Clean Telemetry)"}
                    </div>
                </div>
                <div style="background: rgba(10, 15, 30, 0.7); border: 1px solid rgba(245, 158, 11, 0.3); border-radius: 6px; padding: 10px 12px;">
                    <div style="color: #fbbf24; font-weight: 700; text-transform: uppercase; font-family: 'JetBrains Mono'; margin-bottom: 4px;">
                        🛡️ Corroborating Signals ({len(xai.corroborating_evidence)})
                    </div>
                    <div style="color: #f1f5f9;">
                        {', '.join([c.feature_name for c in xai.corroborating_evidence[:2]]) if xai.corroborating_evidence else "No secondary corroborating triggers"}
                    </div>
                </div>
                <div style="background: rgba(10, 15, 30, 0.7); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 6px; padding: 10px 12px;">
                    <div style="color: #38bdf8; font-weight: 700; text-transform: uppercase; font-family: 'JetBrains Mono'; margin-bottom: 4px;">
                        🕵️ Evasion / Obfuscation ({len(xai.evasion_signals)})
                    </div>
                    <div style="color: #f1f5f9;">
                        {', '.join([e.feature_name for e in xai.evasion_signals[:2]]) if xai.evasion_signals else "Standard transparent infrastructure"}
                    </div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )


def render_attribution_waterfall(xai: XAIExplanation) -> go.Figure:
    """
    Renders an interactive Plotly horizontal bar/waterfall chart illustrating
    the additive path from baseline risk (0%) to the final Threat Index score.
    """
    if not xai.attributions:
        # Render baseline 0% chart
        fig = go.Figure(go.Bar(
            x=[0.0],
            y=["Baseline Prior Risk"],
            orientation="h",
            marker=dict(color="#10b981")
        ))
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            xaxis=dict(range=[0, 100], color="#94a3b8", gridcolor="#1e293b", title="Threat Index Contribution (%)"),
            yaxis=dict(color="#f8fafc"),
            height=280,
            margin=dict(l=20, r=20, t=20, b=20)
        )
        return fig

    # Build waterfall trace
    x_labels = ["Baseline (Prior)"]
    y_deltas = [0.0]
    measures = ["absolute"]
    text_labels = ["0%"]

    for attr in xai.attributions:
        # Abbreviate long names
        short_name = attr.feature_name if len(attr.feature_name) <= 24 else attr.feature_name[:22] + ".."
        x_labels.append(short_name)
        y_deltas.append(attr.weight)
        measures.append("relative")
        text_labels.append(f"+{attr.weight:.0f}%" if attr.weight > 0 else f"{attr.weight:.0f}%")

    x_labels.append("Final Threat Index")
    y_deltas.append(xai.posterior_score)
    measures.append("total")
    text_labels.append(f"{xai.posterior_score:.0f}%")

    fig = go.Figure(go.Waterfall(
        name="Feature Attribution",
        orientation="v",
        measure=measures,
        x=x_labels,
        textposition="outside",
        text=text_labels,
        y=y_deltas,
        connector={"line": {"color": "#475569", "width": 1, "dash": "dot"}},
        decreasing={"marker": {"color": "#10b981"}},
        increasing={"marker": {"color": "#ef4444"}},
        totals={"marker": {"color": "#38bdf8"}}
    ))

    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="JetBrains Mono, monospace", size=11, color="#94a3b8"),
        yaxis=dict(range=[0, max(105, xai.posterior_score + 10)], gridcolor="#1e293b", title="Threat Index Score (%)"),
        xaxis=dict(gridcolor="#1e293b", tickangle=-20),
        height=320,
        margin=dict(l=20, r=20, t=30, b=20),
        showlegend=False
    )
    return fig


def _render_counterfactual_card(xai: XAIExplanation) -> None:
    """Renders counterfactual 'What-If' reasoning cards."""
    if not xai.counterfactuals:
        st.info("No counterfactual scenarios available for this evaluation.")
        return

    scenario = xai.counterfactuals[0]

    st.markdown(
        f"""
        <div style="background: rgba(15, 23, 42, 0.8); border: 1px solid rgba(56, 189, 248, 0.25); border-left: 4px solid #38bdf8; border-radius: 8px; padding: 16px 18px; margin-bottom: 14px;">
            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.76rem; color: #38bdf8; font-weight: 700; text-transform: uppercase; margin-bottom: 6px;">
                🎯 Pathway to LOW RISK (What Must Change)
            </div>
            <div style="font-size: 0.85rem; color: #e2e8f0; line-height: 1.5; margin-bottom: 12px;">
                {scenario.narrative}
            </div>
            <div style="display: flex; gap: 10px; align-items: center;">
                <div style="background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.4); border-radius: 6px; padding: 6px 12px; font-size: 0.8rem; color: #34d399; font-family: 'JetBrains Mono';">
                    Projected Target: <b>{scenario.target_score:.0f}%</b> ({scenario.target_risk_tier})
                </div>
                <div style="background: rgba(56, 189, 248, 0.15); border: 1px solid rgba(56, 189, 248, 0.4); border-radius: 6px; padding: 6px 12px; font-size: 0.8rem; color: #38bdf8; font-family: 'JetBrains Mono';">
                    Required Delta: <b>-{scenario.score_reduction:.0f}%</b>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    if scenario.factors_to_change:
        st.markdown("###### 📋 Mandatory Action Items to Eliminate Risk:")
        for idx, factor in enumerate(scenario.factors_to_change, start=1):
            st.markdown(
                f"""
                <div style="display: flex; align-items: center; gap: 8px; font-size: 0.8rem; color: #cbd5e1; margin-bottom: 6px; background: rgba(10, 15, 30, 0.6); padding: 6px 10px; border-radius: 6px; border: 1px solid rgba(30, 41, 59, 0.8);">
                    <span style="color: #38bdf8; font-weight: 800;">{idx}.</span>
                    <span>Remove or remediate: <code style="color: #fca5a5;">{factor}</code></span>
                </div>
                """,
                unsafe_allow_html=True
            )
