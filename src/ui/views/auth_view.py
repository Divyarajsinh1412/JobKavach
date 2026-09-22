"""
JobKavach Authentication View.
Renders enterprise login and registration interfaces with PBKDF2 password verification,
role selection, and 1-click demo analyst credentials.
"""

import streamlit as st
from src.database.db_manager import DatabaseManager
from src.services.auth_service import (
    AuthService,
    DEFAULT_DEMO_EMAIL,
    DEFAULT_DEMO_PASSWORD,
)


def render_auth_view(db: DatabaseManager) -> None:
    """Renders the JobKavach authentication portal (Login & Register)."""
    # Ensure default demo analyst account exists
    AuthService.bootstrap_demo_analyst(db)

    st.markdown(
        """
        <div style="text-align: center; margin-bottom: 24px;">
            <div style="font-size: 2.2rem; font-weight: 900; letter-spacing: 0.2em; color: #f8fafc; font-family: 'Orbitron', 'Inter', sans-serif;">
                🛡️ JOBKAVACH
            </div>
            <div style="font-size: 0.85rem; color: #38bdf8; letter-spacing: 0.12em; font-weight: 700;">
                SECURE ANALYST ACCESS PORTAL
            </div>
            <div style="font-size: 0.78rem; color: #94a3b8; margin-top: 4px;">
                Authenticate to access the live SIEM command center, XAI threat engine, and audit ledger.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    _, col_auth, _ = st.columns([1, 1.8, 1])

    with col_auth:
        tab_login, tab_register = st.tabs(["🔐 Analyst Login", "📝 Register New Account"])

        # ======================================================================
        # TAB 1: LOGIN
        # ======================================================================
        with tab_login:
            st.markdown("<div style='margin-top: 10px;'></div>", unsafe_allow_html=True)
            login_email = st.text_input(
                "Corporate / Analyst Email",
                placeholder="analyst@jobkavach.sec",
                key="login_email_input"
            )
            login_password = st.text_input(
                "Password",
                type="password",
                placeholder="••••••••••••",
                key="login_password_input"
            )

            btn_login = st.button("LOG IN TO COMMAND CENTER", type="primary", use_container_width=True, key="btn_do_login")

            if btn_login:
                if not login_email or not login_password:
                    st.error("Please enter both email and password.")
                else:
                    success, msg, user = AuthService.login(db, login_email, login_password)
                    if success and user:
                        st.session_state["authenticated_user"] = user
                        st.success(msg)
                        st.rerun()
                    else:
                        st.error(msg)

            st.markdown("<div style='margin-top: 16px; border-top: 1px solid rgba(148, 163, 184, 0.2); padding-top: 14px;'></div>", unsafe_allow_html=True)

            # 1-Click Demo Credentials
            st.markdown(
                """
                <div style="font-size: 0.76rem; color: #94a3b8; margin-bottom: 8px;">
                    ⚡ <b>EVALUATION ACCESS:</b> Use pre-configured demo credentials below for instant access:
                </div>
                """,
                unsafe_allow_html=True
            )

            if st.button("🚀 1-CLICK DEMO LOGIN (Alex Vance - Lead SOC Analyst)", use_container_width=True, key="btn_demo_login"):
                success, msg, user = AuthService.login(db, DEFAULT_DEMO_EMAIL, DEFAULT_DEMO_PASSWORD)
                if success and user:
                    st.session_state["authenticated_user"] = user
                    st.success(f"Authenticated as {user.full_name}")
                    st.rerun()
                else:
                    st.error("Demo account initialization error.")

        # ======================================================================
        # TAB 2: REGISTER
        # ======================================================================
        with tab_register:
            st.markdown("<div style='margin-top: 10px;'></div>", unsafe_allow_html=True)
            reg_name = st.text_input("Full Name", placeholder="e.g. Jordan Smith", key="reg_name_input")
            reg_email = st.text_input("Email Address", placeholder="e.g. j.smith@enterprise.com", key="reg_email_input")

            reg_role = st.selectbox(
                "Designated Platform Role",
                [
                    "SOC Security Analyst",
                    "Lead Security Analyst",
                    "HR Compliance Specialist",
                    "Job Seeker / Candidate",
                    "Threat Intelligence Researcher"
                ],
                key="reg_role_input"
            )

            reg_pwd1 = st.text_input("Password (min. 8 chars)", type="password", key="reg_pwd1_input")
            reg_pwd2 = st.text_input("Confirm Password", type="password", key="reg_pwd2_input")

            btn_register = st.button("CREATE SECURE ACCOUNT", type="primary", use_container_width=True, key="btn_do_register")

            if btn_register:
                if not reg_name or not reg_email or not reg_pwd1:
                    st.error("All fields are mandatory.")
                elif reg_pwd1 != reg_pwd2:
                    st.error("Passwords do not match.")
                else:
                    success, msg, new_user = AuthService.register(
                        db=db,
                        email=reg_email,
                        full_name=reg_name,
                        password=reg_pwd1,
                        role=reg_role
                    )
                    if success and new_user:
                        st.session_state["authenticated_user"] = new_user
                        st.success(f"Account created successfully! Welcome, {new_user.full_name}.")
                        st.rerun()
                    else:
                        st.error(msg)
