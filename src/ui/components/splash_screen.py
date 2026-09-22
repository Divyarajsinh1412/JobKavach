"""
JobKavach Animated Cyber-Defense Splashscreen Component.
Features an SVG glowing Kavach (Shield) emblem, rotating orbital defense rings,
radar wave animations, and an interactive zero-trust boot diagnostic sequence.
"""

import streamlit as st


def render_splash_screen() -> None:
    """Renders the animated JobKavach cyber-defense splashscreen."""
    # CSS Animations for Shield, Orbital Rings, and Neon Glow
    st.markdown(
        """
        <style>
        @keyframes rotate-clockwise {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        @keyframes rotate-counter {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(-360deg); }
        }
        @keyframes pulse-shield {
            0%, 100% {
                filter: drop-shadow(0 0 15px rgba(56, 189, 248, 0.6)) drop-shadow(0 0 35px rgba(16, 185, 129, 0.4));
                transform: scale(1);
            }
            50% {
                filter: drop-shadow(0 0 30px rgba(56, 189, 248, 0.9)) drop-shadow(0 0 60px rgba(16, 185, 129, 0.7));
                transform: scale(1.03);
            }
        }
        @keyframes scan-line {
            0% { top: 0%; opacity: 0; }
            50% { opacity: 0.8; }
            100% { top: 100%; opacity: 0; }
        }
        @keyframes text-glow {
            0%, 100% { text-shadow: 0 0 10px rgba(56, 189, 248, 0.5), 0 0 20px rgba(56, 189, 248, 0.3); }
            50% { text-shadow: 0 0 20px rgba(56, 189, 248, 0.9), 0 0 40px rgba(16, 185, 129, 0.7); }
        }

        .splash-container {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 30px 20px;
            text-align: center;
            position: relative;
            background: radial-gradient(circle at 50% 30%, rgba(15, 23, 42, 0.95), rgba(3, 7, 18, 0.98));
            border: 1px solid rgba(56, 189, 248, 0.25);
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.8), 0 0 50px rgba(56, 189, 248, 0.15);
            margin: 20px auto;
            max-width: 880px;
            overflow: hidden;
        }

        .shield-stage {
            position: relative;
            width: 220px;
            height: 220px;
            margin: 0 auto 20px auto;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .orbital-ring-1 {
            position: absolute;
            width: 210px;
            height: 210px;
            border: 2px dashed rgba(56, 189, 248, 0.4);
            border-radius: 50%;
            animation: rotate-clockwise 14s linear infinite;
        }

        .orbital-ring-2 {
            position: absolute;
            width: 170px;
            height: 170px;
            border: 2px dotted rgba(16, 185, 129, 0.5);
            border-radius: 50%;
            animation: rotate-counter 9s linear infinite;
        }

        .kavach-emblem {
            animation: pulse-shield 3.5s ease-in-out infinite;
            z-index: 10;
        }

        .brand-title {
            font-family: 'Orbitron', 'Inter', sans-serif;
            font-size: 3.2rem;
            font-weight: 900;
            letter-spacing: 0.25em;
            color: #ffffff;
            margin: 0;
            animation: text-glow 4s ease-in-out infinite;
            text-transform: uppercase;
        }

        .brand-subtitle {
            font-size: 0.92rem;
            color: #38bdf8;
            letter-spacing: 0.15em;
            font-weight: 700;
            margin-top: 8px;
            text-transform: uppercase;
        }

        .brand-desc {
            font-size: 0.85rem;
            color: #94a3b8;
            max-width: 620px;
            margin: 12px auto 20px auto;
            line-height: 1.6;
        }

        .boot-console {
            background: rgba(3, 7, 18, 0.9);
            border: 1px solid rgba(56, 189, 248, 0.3);
            border-radius: 8px;
            padding: 14px 20px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.76rem;
            color: #38bdf8;
            text-align: left;
            width: 90%;
            max-width: 640px;
            margin: 0 auto 24px auto;
            box-shadow: inset 0 0 20px rgba(0, 0, 0, 0.7);
        }

        .boot-line-ok {
            color: #10b981;
            margin-bottom: 4px;
        }
        .boot-line-info {
            color: #94a3b8;
            margin-bottom: 4px;
        }
        .boot-line-highlight {
            color: #38bdf8;
            font-weight: 700;
            margin-top: 6px;
        }
        </style>

        <div class="splash-container">
            <!-- Animated Shield Stage -->
            <div class="shield-stage">
                <div class="orbital-ring-1"></div>
                <div class="orbital-ring-2"></div>
                <div class="kavach-emblem">
                    <svg width="110" height="130" viewBox="0 0 100 120" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <!-- Shield Outer Contour -->
                        <path d="M50 5L90 22V58C90 88 50 115 50 115C50 115 10 88 10 58V22L50 5Z" 
                              fill="url(#shield_grad)" stroke="#38bdf8" stroke-width="3" stroke-linejoin="round"/>
                        <!-- Inner Cyber Core -->
                        <path d="M50 20L78 33V58C78 80 50 98 50 98C50 98 22 80 22 58V33L50 20Z" 
                              fill="url(#core_grad)" stroke="#10b981" stroke-width="1.8"/>
                        <!-- Central Checkmark / Circuit Lock -->
                        <path d="M38 58L47 67L64 48" stroke="#ffffff" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>
                        <!-- Gradients -->
                        <defs>
                            <linearGradient id="shield_grad" x1="50" y1="5" x2="50" y2="115" gradientUnits="userSpaceOnUse">
                                <stop offset="0%" stop-color="#0284c7" stop-opacity="0.8"/>
                                <stop offset="50%" stop-color="#0369a1" stop-opacity="0.5"/>
                                <stop offset="100%" stop-color="#0f172a" stop-opacity="0.9"/>
                            </linearGradient>
                            <linearGradient id="core_grad" x1="50" y1="20" x2="50" y2="98" gradientUnits="userSpaceOnUse">
                                <stop offset="0%" stop-color="#10b981" stop-opacity="0.4"/>
                                <stop offset="100%" stop-color="#047857" stop-opacity="0.1"/>
                            </linearGradient>
                        </defs>
                    </svg>
                </div>
            </div>

            <!-- Brand Identity -->
            <h1 class="brand-title">JOBKAVACH</h1>
            <div class="brand-subtitle">AI-POWERED OFFER LETTER & RECRUITMENT PHISHING DEFENSE</div>
            <p class="brand-desc">
                An enterprise-grade Zero-Trust SOC platform shielding job seekers, HR compliance teams, 
                and enterprises from employment scams, fake offer letters, and credential harvesting campaigns 
                with Explainable AI (XAI).
            </p>

            <!-- Boot Diagnostic Sequence -->
            <div class="boot-console">
                <div class="boot-line-ok">✔ [BOOT 01] Zero-Trust Verification Subsystems: INITIALIZED</div>
                <div class="boot-line-ok">✔ [BOOT 02] O(N) Linear NLP Fraud Pattern Engine: ACTIVE (5 Taxonomies)</div>
                <div class="boot-line-ok">✔ [BOOT 03] Live WHOIS & Privacy Shield Enumeration: CONNECTED</div>
                <div class="boot-line-ok">✔ [BOOT 04] Explainable AI (XAI) SHAP Attribution Matrix: CALIBRATED</div>
                <div class="boot-line-ok">✔ [BOOT 05] RFC 822 / Document Forensics (.eml, .pdf, .docx): READY</div>
                <div class="boot-line-highlight">⚡ DEFENSE STATUS: JOBKAVACH SHIELD ACTIVE & SECURE</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Centered High-Impact Entry Action
    _, col_btn, _ = st.columns([1, 2, 1])
    with col_btn:
        if st.button(
            "🛡️ ENTER JOBKAVACH COMMAND CENTER",
            key="btn_enter_platform",
            type="primary",
            use_container_width=True
        ):
            st.session_state["show_splash"] = False
            st.rerun()
