"""
Evidence Viewer and Forensic Artifact Components.
Renders detected IoC cards, extracted text snippets, MITRE ATT&CK mapping,
incident playbooks, and raw JSON telemetry inspectors.
"""

import json
from typing import List, Dict, Any
import streamlit as st


def render_ioc_list(score_breakdown: List[Dict[str, Any]]) -> None:
    """Renders the list of detected indicators of compromise."""
    if not score_breakdown:
        st.success("✅ No indicators of compromise detected in the analyzed payload.")
        return

    for item in score_breakdown:
        st.markdown(
            f"""
            <div class="ioc-card-advanced">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-weight: 700; color: #f8fafc; font-size: 0.95rem;">{item['factor']}</span>
                    <span class="cyber-badge cyber-badge-red">{item['weight']}</span>
                </div>
                <div style="color: #94a3b8; font-size: 0.82rem; margin-top: 4px;">
                    {item['detail']}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )


def render_snippets(snippets: List[Dict[str, str]]) -> None:
    """Renders contextual matched text snippets."""
    if not snippets:
        return

    st.markdown("##### 🔎 Forensically Matched Text Snippets")
    for snippet in snippets:
        st.markdown(
            f"""
            <div style="background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(31, 41, 55, 0.8); border-radius: 6px; padding: 8px 12px; margin-bottom: 8px;">
                <div style="font-size: 0.75rem; color: #38bdf8; font-weight: 700; margin-bottom: 4px;">
                    [{snippet['category']}] Term: "{snippet['term']}"
                </div>
                <code style="color: #f1f5f9; font-size: 0.8rem;">{snippet['snippet']}</code>
            </div>
            """,
            unsafe_allow_html=True
        )


def render_mitre_mapping(mitre_tags: List[str]) -> None:
    """Renders MITRE ATT&CK tactical tags."""
    st.markdown("##### 🧭 MITRE ATT&CK Tactical Mapping")
    for tag in mitre_tags:
        st.markdown(
            f"""
            <div style="background: rgba(17, 24, 39, 0.7); border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 6px; padding: 10px 14px; margin-bottom: 8px;">
                <div style="color: #38bdf8; font-weight: 700; font-size: 0.85rem; font-family: 'JetBrains Mono';">
                    {tag}
                </div>
                <div style="color: #94a3b8; font-size: 0.75rem; margin-top: 2px;">
                    Aligned with enterprise cyber threat taxonomy v14.1
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )


def render_playbook(recommendations: List[str]) -> None:
    """Renders executive incident containment steps."""
    st.markdown("##### 📋 Executive Incident Containment Playbook")
    for idx, rec in enumerate(recommendations, start=1):
        st.markdown(
            f"""
            <div style="display: flex; align-items: flex-start; gap: 10px; background: rgba(17, 24, 39, 0.6); border: 1px solid rgba(31, 41, 55, 0.8); border-radius: 6px; padding: 10px 12px; margin-bottom: 8px;">
                <div style="background: rgba(56, 189, 248, 0.2); color: #38bdf8; font-weight: 800; font-size: 0.8rem; width: 22px; height: 22px; border-radius: 50%; display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
                    {idx}
                </div>
                <div style="font-size: 0.82rem; color: #e2e8f0; line-height: 1.4;">
                    {rec}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )


def render_json_inspector(record: Dict[str, Any]) -> None:
    """Renders raw JSON telemetry in a collapsible code inspector."""
    telemetry_view = {
        "record_id": record.get("id"),
        "timestamp_utc": record.get("timestamp"),
        "scan_type": record.get("scan_type"),
        "target_domain": record.get("target_domain"),
        "threat_score": record.get("threat_score"),
        "risk_level": record.get("risk_level"),
        "flag_count": record.get("flag_count"),
        "detected_flags": json.loads(record.get("detected_flags_json", "[]")),
        "details": json.loads(record.get("details_json", "{}")) if "details_json" in record else {},
        "payload_hash": record.get("payload_hash")
    }
    st.json(telemetry_view)
