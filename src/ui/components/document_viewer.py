"""
Document & Email Forensic Telemetry Viewer Component.
Renders email transport headers, SPF/DKIM verification badges, Reply-To mismatch alerts,
attachment threat inspection tables, and extracted hyperlinks.
"""

import html
import streamlit as st
from typing import Optional

from src.models.schemas import DocumentAnalysisResult


def render_document_forensic_card(doc_result: Optional[DocumentAnalysisResult]) -> None:
    """Renders comprehensive email and document forensic telemetry."""
    if not doc_result:
        return

    # 1. File Metadata Banner
    size_kb = doc_result.file_size / 1024.0
    st.markdown(
        f"""
        <div style="background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 10px; padding: 14px 18px; margin-bottom: 16px;">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
                <div>
                    <span style="background: #0284c7; color: #fff; font-weight: 800; font-size: 0.72rem; padding: 3px 8px; border-radius: 4px; letter-spacing: 0.05em;">
                        {doc_result.file_format} ARTIFACT
                    </span>
                    <span style="font-weight: 700; font-size: 0.95rem; color: #f8fafc; margin-left: 10px;">
                        📄 {html.escape(doc_result.filename)}
                    </span>
                </div>
                <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.74rem; color: #94a3b8;">
                    SIZE: <b style="color: #e2e8f0;">{size_kb:.1f} KB</b> | SHA-256: <code style="color: #38bdf8;">{doc_result.sha256_hash[:16]}...</code>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # 2. Email Forensic Headers (If .eml / .msg)
    if doc_result.email_metadata:
        em = doc_result.email_metadata
        st.markdown("##### ✉️ Email Transport & Header Telemetry")

        # Reply-To Mismatch Alert Banner
        if em.reply_to_mismatch:
            st.markdown(
                f"""
                <div style="background: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444; border-radius: 8px; padding: 12px 16px; margin-bottom: 14px;">
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <span style="font-size: 1.3rem;">🚨</span>
                        <div>
                            <div style="font-weight: 800; color: #fca5a5; font-size: 0.88rem;">
                                CRITICAL: EMAIL REPLY-TO MISMATCH DETECTED (+25% Threat Weight)
                            </div>
                            <div style="font-size: 0.78rem; color: #fecaca; margin-top: 2px;">
                                Sender identity is <code>{html.escape(em.sender)}</code>, but replies are redirected to 
                                <b style="color: #ffffff; text-decoration: underline;">{html.escape(em.reply_to)}</b>. 
                                This is a hallmark of executive recruiter impersonation and BEC (Business Email Compromise).
                            </div>
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        # Header Grid
        h_col1, h_col2 = st.columns(2)
        with h_col1:
            st.markdown(
                f"""
                <div style="background: rgba(30, 41, 59, 0.6); border: 1px solid rgba(148, 163, 184, 0.2); border-radius: 8px; padding: 12px; font-size: 0.82rem;">
                    <div style="color: #94a3b8; font-size: 0.72rem; text-transform: uppercase;">Subject</div>
                    <div style="font-weight: 700; color: #f8fafc; margin-top: 2px;">{html.escape(em.subject or '(No Subject)')}</div>
                    <div style="margin-top: 8px; color: #94a3b8; font-size: 0.72rem; text-transform: uppercase;">From (Sender)</div>
                    <div style="color: #38bdf8; font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; margin-top: 2px;">{html.escape(em.sender or 'Unknown')}</div>
                    <div style="margin-top: 8px; color: #94a3b8; font-size: 0.72rem; text-transform: uppercase;">Reply-To</div>
                    <div style="color: {'#ef4444' if em.reply_to_mismatch else '#94a3b8'}; font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; margin-top: 2px;">
                        {html.escape(em.reply_to or '(None specified)')}
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with h_col2:
            # Authentication Status Badges
            spf_badge = (
                '<span style="background: #166534; color: #86efac; padding: 2px 8px; border-radius: 4px; font-weight: 700;">PASS</span>'
                if em.spf_status == "PASS" else
                ('<span style="background: #991b1b; color: #fca5a5; padding: 2px 8px; border-radius: 4px; font-weight: 700;">FAIL</span>'
                 if em.spf_status in ("FAIL", "SOFTFAIL") else
                 '<span style="background: #334155; color: #94a3b8; padding: 2px 8px; border-radius: 4px;">NOT EVALUATED</span>')
            )
            dkim_badge = (
                '<span style="background: #166534; color: #86efac; padding: 2px 8px; border-radius: 4px; font-weight: 700;">PASS</span>'
                if em.dkim_status == "PASS" else
                ('<span style="background: #991b1b; color: #fca5a5; padding: 2px 8px; border-radius: 4px; font-weight: 700;">FAIL</span>'
                 if em.dkim_status == "FAIL" else
                 '<span style="background: #334155; color: #94a3b8; padding: 2px 8px; border-radius: 4px;">NOT EVALUATED</span>')
            )

            st.markdown(
                f"""
                <div style="background: rgba(30, 41, 59, 0.6); border: 1px solid rgba(148, 163, 184, 0.2); border-radius: 8px; padding: 12px; font-size: 0.82rem;">
                    <div style="color: #94a3b8; font-size: 0.72rem; text-transform: uppercase;">Message Date</div>
                    <div style="color: #e2e8f0; margin-top: 2px;">{html.escape(em.date or 'N/A')}</div>
                    <div style="margin-top: 8px; color: #94a3b8; font-size: 0.72rem; text-transform: uppercase;">SPF Policy Verification</div>
                    <div style="margin-top: 3px;">{spf_badge}</div>
                    <div style="margin-top: 8px; color: #94a3b8; font-size: 0.72rem; text-transform: uppercase;">DKIM Cryptographic Signature</div>
                    <div style="margin-top: 3px;">{dkim_badge}</div>
                </div>
                """,
                unsafe_allow_html=True
            )

        # 3. Attachments Inspection Table
        if em.attachments:
            st.markdown(f"##### 📎 Extracted Attachments ({len(em.attachments)})")
            att_rows = []
            for att in em.attachments:
                size_str = f"{att.size_bytes / 1024.0:.1f} KB"
                status_badge = (
                    '<span style="background: #991b1b; color: #fca5a5; font-weight: 800; padding: 2px 8px; border-radius: 4px; font-size: 0.7rem;">🚨 HIGH RISK</span>'
                    if att.is_suspicious else
                    '<span style="background: #1e293b; color: #10b981; font-weight: 700; padding: 2px 8px; border-radius: 4px; font-size: 0.7rem;">✅ STANDARD</span>'
                )
                att_rows.append(
                    f"""
                    <tr>
                        <td style="padding: 8px; font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; color: #f8fafc;">{html.escape(att.filename)}</td>
                        <td style="padding: 8px; font-size: 0.78rem; color: #94a3b8;">{html.escape(att.file_type)}</td>
                        <td style="padding: 8px; font-size: 0.78rem; color: #94a3b8;">{size_str}</td>
                        <td style="padding: 8px;">{status_badge}</td>
                        <td style="padding: 8px; font-size: 0.78rem; color: {'#f87171' if att.is_suspicious else '#94a3b8'};">{html.escape(att.reason)}</td>
                    </tr>
                    """
                )

            st.markdown(
                f"""
                <div style="border: 1px solid rgba(148, 163, 184, 0.2); border-radius: 8px; overflow: hidden; margin-bottom: 14px;">
                    <table style="width: 100%; border-collapse: collapse; text-align: left; background: rgba(15, 23, 42, 0.7);">
                        <thead>
                            <tr style="background: rgba(30, 41, 59, 0.9); color: #cbd5e1; font-size: 0.72rem; text-transform: uppercase;">
                                <th style="padding: 8px;">Filename</th>
                                <th style="padding: 8px;">MIME Type</th>
                                <th style="padding: 8px;">Size</th>
                                <th style="padding: 8px;">Threat Status</th>
                                <th style="padding: 8px;">Forensic Assessment</th>
                            </tr>
                        </thead>
                        <tbody>
                            {''.join(att_rows)}
                        </tbody>
                    </table>
                </div>
                """,
                unsafe_allow_html=True
            )

    # 4. Extracted Embedded URLs
    if doc_result.embedded_urls:
        st.markdown(f"##### 🔗 Embedded Hyperlinks Detected ({len(doc_result.embedded_urls)})")
        url_pills = []
        for u in doc_result.embedded_urls[:10]:
            clean_u = html.escape(u)
            url_pills.append(
                f'<code style="background: rgba(30, 41, 59, 0.8); border: 1px solid rgba(56, 189, 248, 0.3); color: #38bdf8; padding: 3px 8px; border-radius: 4px; font-size: 0.75rem; margin: 3px; display: inline-block;">{clean_u}</code>'
            )
        st.markdown(f"<div style='margin-bottom: 14px;'>{' '.join(url_pills)}</div>", unsafe_allow_html=True)
