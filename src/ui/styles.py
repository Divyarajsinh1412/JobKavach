"""
SOC Dark-Mode Theme and Custom CSS Injection.
Provides enterprise cyber defense styling, glowing radar indicators,
responsive KPI cards, and custom typography.
"""

import streamlit as st


def inject_custom_css() -> None:
    """Injects ultra-advanced dark SOC aesthetic styling, glowing accents, and typography."""
    st.markdown("""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&family=Plus+Jakarta+Sans:wght@600;700;800&display=swap');

        /* Global Background & Color Palette */
        .stApp {
            background-color: #040711;
            color: #e2e8f0;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        }

        /* Ambient Glow Backdrop */
        .stApp::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            height: 450px;
            background: radial-gradient(circle 800px at 50% -100px, rgba(14, 165, 233, 0.12), transparent 80%),
                        radial-gradient(circle 600px at 85% 150px, rgba(99, 102, 241, 0.08), transparent 70%);
            pointer-events: none;
            z-index: 0;
        }

        /* Top SOC Header Container */
        .soc-header-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 16px 24px;
            background: linear-gradient(135deg, rgba(15, 23, 42, 0.9) 0%, rgba(10, 15, 30, 0.8) 100%);
            border: 1px solid rgba(56, 189, 248, 0.2);
            border-radius: 12px;
            margin-bottom: 24px;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
            backdrop-filter: blur(12px);
        }

        .soc-brand-title {
            font-family: 'Plus Jakarta Sans', sans-serif;
            font-weight: 800;
            font-size: 1.45rem;
            letter-spacing: -0.5px;
            background: linear-gradient(135deg, #ffffff 0%, #94a3b8 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin: 0;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .soc-brand-subtitle {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.76rem;
            color: #38bdf8;
            letter-spacing: 0.5px;
            margin-top: 3px;
        }

        /* Live Radar Telemetry Pulse */
        .radar-pulse-box {
            display: flex;
            align-items: center;
            gap: 8px;
            background: rgba(15, 23, 42, 0.7);
            border: 1px solid rgba(16, 185, 129, 0.3);
            padding: 6px 14px;
            border-radius: 20px;
        }

        .radar-dot {
            width: 9px;
            height: 9px;
            background-color: #10b981;
            border-radius: 50%;
            box-shadow: 0 0 12px #10b981;
            animation: pulse-green 2s infinite cubic-bezier(0.4, 0, 0.6, 1);
        }

        @keyframes pulse-green {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.4; transform: scale(1.25); }
        }

        /* Cyber Badges */
        .cyber-badge {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            font-weight: 600;
            padding: 4px 10px;
            border-radius: 6px;
            background: rgba(15, 23, 42, 0.8);
            border: 1px solid rgba(56, 189, 248, 0.3);
            color: #38bdf8;
            letter-spacing: 0.5px;
        }
        .cyber-badge-red {
            border-color: rgba(239, 68, 68, 0.5);
            color: #f87171;
            background: rgba(127, 29, 29, 0.2);
        }
        .cyber-badge-green {
            border-color: rgba(16, 185, 129, 0.5);
            color: #34d399;
            background: rgba(6, 78, 59, 0.2);
        }
        .cyber-badge-amber {
            border-color: rgba(245, 158, 11, 0.5);
            color: #fbbf24;
            background: rgba(120, 53, 15, 0.2);
        }

        /* KPI Metric Cards */
        .kpi-card {
            background: linear-gradient(135deg, rgba(15, 23, 42, 0.85) 0%, rgba(20, 27, 45, 0.85) 100%);
            border: 1px solid rgba(30, 41, 59, 0.8);
            border-top: 1px solid rgba(56, 189, 248, 0.2);
            border-radius: 10px;
            padding: 16px 18px;
            backdrop-filter: blur(10px);
            box-shadow: 0 4px 20px -2px rgba(0, 0, 0, 0.4);
            transition: transform 0.2s ease, border-color 0.2s ease;
        }
        .kpi-card:hover {
            transform: translateY(-2px);
            border-top-color: #38bdf8;
            box-shadow: 0 8px 25px -4px rgba(56, 189, 248, 0.15);
        }
        .kpi-card-danger {
            border-top-color: #ef4444;
        }
        .kpi-card-warning {
            border-top-color: #f59e0b;
        }
        .kpi-card-success {
            border-top-color: #10b981;
        }

        .kpi-label {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.74rem;
            color: #94a3b8;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            margin-bottom: 6px;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .kpi-value {
            font-family: 'JetBrains Mono', monospace;
            font-size: 1.85rem;
            font-weight: 700;
            color: #f8fafc;
            line-height: 1.1;
        }
        .kpi-sub {
            font-size: 0.72rem;
            color: #64748b;
            margin-top: 4px;
        }

        /* Threat Severity Callout Banner */
        .threat-banner {
            padding: 20px 24px;
            border-radius: 12px;
            margin: 16px 0 24px 0;
            border-left: 6px solid;
            backdrop-filter: blur(12px);
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 10px 30px -10px rgba(0, 0, 0, 0.5);
        }
        .threat-banner-critical {
            background: linear-gradient(90deg, rgba(127, 29, 29, 0.35) 0%, rgba(15, 23, 42, 0.6) 100%);
            border-left-color: #ef4444;
            border-top: 1px solid rgba(239, 68, 68, 0.3);
            border-right: 1px solid rgba(239, 68, 68, 0.2);
            border-bottom: 1px solid rgba(239, 68, 68, 0.2);
        }
        .threat-banner-suspicious {
            background: linear-gradient(90deg, rgba(120, 53, 15, 0.35) 0%, rgba(15, 23, 42, 0.6) 100%);
            border-left-color: #f59e0b;
            border-top: 1px solid rgba(245, 158, 11, 0.3);
            border-right: 1px solid rgba(245, 158, 11, 0.2);
            border-bottom: 1px solid rgba(245, 158, 11, 0.2);
        }
        .threat-banner-low {
            background: linear-gradient(90deg, rgba(6, 78, 59, 0.35) 0%, rgba(15, 23, 42, 0.6) 100%);
            border-left-color: #10b981;
            border-top: 1px solid rgba(16, 185, 129, 0.3);
            border-right: 1px solid rgba(16, 185, 129, 0.2);
            border-bottom: 1px solid rgba(16, 185, 129, 0.2);
        }

        /* IoC Alert Cards */
        .ioc-card-advanced {
            background: rgba(17, 24, 39, 0.7);
            border: 1px solid rgba(31, 41, 55, 0.8);
            border-left: 4px solid #ef4444;
            border-radius: 0 8px 8px 0;
            padding: 14px 18px;
            margin-bottom: 12px;
            backdrop-filter: blur(10px);
            transition: transform 0.15s ease;
        }
        .ioc-card-advanced:hover {
            transform: translateX(3px);
        }

        /* Tab styling */
        .stTabs [data-baseweb="tab-list"] {
            gap: 10px;
            background-color: rgba(15, 23, 42, 0.7);
            padding: 6px;
            border-radius: 10px;
            border: 1px solid rgba(31, 41, 55, 0.8);
        }
        .stTabs [data-baseweb="tab"] {
            color: #94a3b8;
            font-weight: 700;
            font-size: 0.85rem;
            letter-spacing: 0.5px;
            border-radius: 6px;
            padding: 10px 20px;
            transition: all 0.2s ease;
        }
        .stTabs [aria-selected="true"] {
            background: linear-gradient(135deg, rgba(30, 41, 59, 0.9) 0%, rgba(15, 23, 42, 0.9) 100%) !important;
            color: #38bdf8 !important;
            border: 1px solid rgba(56, 189, 248, 0.3) !important;
            box-shadow: 0 0 12px rgba(56, 189, 248, 0.15);
        }

        /* Custom Button Gradient */
        .stButton > button {
            font-family: 'Plus Jakarta Sans', sans-serif !important;
            font-weight: 700 !important;
            letter-spacing: 0.5px !important;
            border-radius: 8px !important;
            transition: all 0.25s ease !important;
        }
        .stButton > button:hover {
            box-shadow: 0 0 20px rgba(56, 189, 248, 0.3) !important;
            transform: translateY(-1px) !important;
        }
    </style>
    """, unsafe_allow_html=True)
