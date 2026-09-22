"""
Text Highlighter and Attribution Heatmap Component.
Renders sanitized, color-coded interactive overlays for scanned offer letter text
with CSS hover tooltips showing exact threat percentage contributions.
"""

import streamlit as st
from src.models.schemas import XAIExplanation


def render_text_highlight_heatmap(xai_explanation: XAIExplanation) -> None:
    """
    Renders the scanned job offer text with an interactive HTML/CSS color-coded attribution overlay:
    - Red: Critical fraud triggers (equipment checks, advance fees, crypto/wire transfer).
    - Amber: Urgency and social engineering pressure points.
    - Blue/Grey: Recruiter contacts and domain references.
    Includes hover tooltips indicating exact percentage points added.
    """
    st.markdown("##### 🔬 Forensic Text Highlighting & Attribution Heatmap")
    st.caption("Interactive linguistic overlay: hover over highlighted phrases to inspect exact threat deltas.")

    # Custom CSS for high-fidelity XAI highlighting and tooltips
    st.markdown("""
    <style>
        .xai-legend-bar {
            display: flex;
            align-items: center;
            gap: 16px;
            margin-bottom: 12px;
            padding: 8px 14px;
            background: rgba(15, 23, 42, 0.7);
            border: 1px solid rgba(30, 41, 59, 0.8);
            border-radius: 8px;
            font-size: 0.76rem;
            font-family: 'JetBrains Mono', monospace;
        }
        .legend-item {
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .legend-dot {
            width: 10px;
            height: 10px;
            border-radius: 2px;
        }
        .xai-text-container {
            background: rgba(10, 15, 30, 0.85);
            border: 1px solid rgba(30, 41, 59, 0.8);
            border-left: 4px solid #38bdf8;
            border-radius: 8px;
            padding: 18px 20px;
            font-family: 'Inter', sans-serif;
            font-size: 0.88rem;
            line-height: 1.7;
            color: #f1f5f9;
            max-height: 380px;
            overflow-y: auto;
            box-shadow: inset 0 2px 10px rgba(0, 0, 0, 0.5);
        }

        /* Highlighting Mark Styles */
        .xai-mark {
            position: relative;
            padding: 2px 6px;
            border-radius: 4px;
            font-weight: 600;
            cursor: help;
            transition: all 0.2s ease;
            display: inline;
        }
        .hl-red {
            background-color: rgba(239, 68, 68, 0.25);
            color: #fca5a5;
            border-bottom: 2px solid #ef4444;
        }
        .hl-red:hover {
            background-color: rgba(239, 68, 68, 0.45);
            color: #ffffff;
            box-shadow: 0 0 10px rgba(239, 68, 68, 0.4);
        }
        .hl-amber {
            background-color: rgba(245, 158, 11, 0.25);
            color: #fde68a;
            border-bottom: 2px solid #f59e0b;
        }
        .hl-amber:hover {
            background-color: rgba(245, 158, 11, 0.45);
            color: #ffffff;
            box-shadow: 0 0 10px rgba(245, 158, 11, 0.4);
        }
        .hl-blue {
            background-color: rgba(56, 189, 248, 0.25);
            color: #bae6fd;
            border-bottom: 2px solid #38bdf8;
        }
        .hl-blue:hover {
            background-color: rgba(56, 189, 248, 0.45);
            color: #ffffff;
            box-shadow: 0 0 10px rgba(56, 189, 248, 0.4);
        }

        /* Tooltip Behavior */
        .xai-mark:hover::after {
            content: attr(data-tooltip);
            position: absolute;
            bottom: 125%;
            left: 50%;
            transform: translateX(-50%);
            background-color: #0f172a;
            color: #38bdf8;
            padding: 5px 10px;
            border-radius: 6px;
            font-size: 0.72rem;
            font-family: 'JetBrains Mono', monospace;
            white-space: nowrap;
            z-index: 1000;
            border: 1px solid rgba(56, 189, 248, 0.4);
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.6);
            pointer-events: none;
        }
        .xai-mark:hover::before {
            content: '';
            position: absolute;
            bottom: 105%;
            left: 50%;
            transform: translateX(-50%);
            border-width: 5px;
            border-style: solid;
            border-color: #0f172a transparent transparent transparent;
            z-index: 1000;
        }
    </style>
    """, unsafe_allow_html=True)

    # Render Visual Legend
    st.markdown("""
    <div class="xai-legend-bar">
        <span style="color: #94a3b8; font-weight: 700;">HEATMAP LEGEND:</span>
        <div class="legend-item">
            <div class="legend-dot" style="background-color: #ef4444;"></div>
            <span style="color: #fca5a5;">Critical Fraud Triggers (+20%)</span>
        </div>
        <div class="legend-item">
            <div class="legend-dot" style="background-color: #f59e0b;"></div>
            <span style="color: #fde68a;">Coercive Urgency (+15%)</span>
        </div>
        <div class="legend-item">
            <div class="legend-dot" style="background-color: #38bdf8;"></div>
            <span style="color: #bae6fd;">Recruiter Spoofing (+25%)</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Render the XSS-safe highlighted HTML container
    st.markdown(xai_explanation.highlighted_html, unsafe_allow_html=True)
    st.markdown("<div style='margin-bottom: 20px;'></div>", unsafe_allow_html=True)
