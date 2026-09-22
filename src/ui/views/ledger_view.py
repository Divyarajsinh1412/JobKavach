"""
SOC Audit Ledger View.
Displays historical scan records, summary metrics, filtering controls,
CSV export, and deep forensic JSON telemetry inspection.
"""

import json
from datetime import datetime, timezone
import streamlit as st
import pandas as pd

from src.database.db_manager import DatabaseManager
from src.ui.components.evidence_viewer import render_json_inspector


def render_ledger_view(db: DatabaseManager) -> None:
    """Renders the historical audit ledger backed by SQLite with filtering and CSV export."""
    st.markdown("### 📜 Forensic Audit Ledger & Historical Logs")
    st.caption("Immutable record of all previous threat inspections with cryptographic payload hashes.")

    # Summary Metrics Row (Total Scans, Critical Count, Avg Score)
    metrics = db.get_summary_metrics()
    sm_col1, sm_col2, sm_col3, sm_col4 = st.columns(4)
    with sm_col1:
        st.metric("Total Scans", metrics["total_scans"])
    with sm_col2:
        st.metric("Critical Count", metrics["critical_scans"])
    with sm_col3:
        st.metric("Avg Score", f"{metrics['avg_threat_score']}%")
    with sm_col4:
        st.metric("Suspicious Count", metrics["suspicious_scans"])

    st.markdown("<div style='margin-bottom: 12px;'></div>", unsafe_allow_html=True)

    history = db.get_history(limit=100)
    if not history:
        st.info("No scan records found in the local ledger. Run an inspection to populate the database.")
        return

    # Filtering controls
    col_f1, col_f2 = st.columns([1, 3])
    with col_f1:
        risk_filter = st.selectbox("Filter by Severity:", ["ALL", "CRITICAL", "SUSPICIOUS", "LOW RISK"])
    with col_f2:
        search_query = st.text_input("Search Domain or Hash:", placeholder="Type domain or hash to filter...")

    filtered_history = [
        row for row in history
        if (risk_filter == "ALL" or row["risk_level"] == risk_filter)
        and (
            not search_query.strip()
            or search_query.lower() in str(row.get("target_domain", "")).lower()
            or search_query.lower() in str(row.get("payload_hash", "")).lower()
        )
    ]

    # Display Data Table
    table_rows = []
    for row in filtered_history:
        table_rows.append({
            "Record ID": f"SCAN-{row['id']:04d}",
            "Timestamp (UTC)": row["timestamp"],
            "Scan Type": row["scan_type"],
            "Target Domain": row["target_domain"] or "N/A",
            "Threat Score": f"{row['threat_score']:.0f}%",
            "Risk Tier": row["risk_level"],
            "IoC Flags": row["flag_count"],
            "SHA-256 Digest": row["payload_hash"][:16] + "..."
        })

    df_display = pd.DataFrame(table_rows)
    st.dataframe(df_display, use_container_width=True, hide_index=True)

    # CSV Export
    full_df = pd.DataFrame(filtered_history)
    csv_bytes = full_df.to_csv(index=False).encode("utf-8")
    st.download_button(
        label="📥 Export Audit Ledger as CSV",
        data=csv_bytes,
        file_name=f"soc_audit_ledger_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv",
    )

    st.markdown("---")
    # JSON Inspector for forensic audits
    with st.expander("🔬 Deep Forensic JSON Telemetry Inspector"):
        selected_id = st.number_input(
            "Enter Record ID to inspect:",
            min_value=1,
            max_value=max(r["id"] for r in history),
            value=history[0]["id"]
        )
        record = next((r for r in history if r["id"] == selected_id), None)
        if record:
            render_json_inspector(record)
