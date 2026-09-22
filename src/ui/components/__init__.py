"""
UI Components package for Fake Offer Letter & Phishing Inspector.
"""

from .metric_cards import (
    render_header,
    render_kpi_bar,
    render_threat_banner,
    render_threat_gauge,
    render_radar_breakdown,
    render_telemetry_cards,
)
from .evidence_viewer import (
    render_ioc_list,
    render_snippets,
    render_mitre_mapping,
    render_playbook,
    render_json_inspector,
)
from .text_highlighter import render_text_highlight_heatmap
from .xai_visualizer import render_xai_dashboard, render_attribution_waterfall
from .document_viewer import render_document_forensic_card
from .splash_screen import render_splash_screen

__all__ = [
    "render_header",
    "render_kpi_bar",
    "render_threat_banner",
    "render_threat_gauge",
    "render_radar_breakdown",
    "render_telemetry_cards",
    "render_ioc_list",
    "render_snippets",
    "render_mitre_mapping",
    "render_playbook",
    "render_json_inspector",
    "render_text_highlight_heatmap",
    "render_xai_dashboard",
    "render_attribution_waterfall",
    "render_document_forensic_card",
    "render_splash_screen",
]
