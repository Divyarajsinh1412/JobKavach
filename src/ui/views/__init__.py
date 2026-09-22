"""
UI Views package for Fake Offer Letter & Phishing Inspector.
"""

from .inspector_view import render_inspector_view
from .ledger_view import render_ledger_view
from .methodology_view import render_methodology_view
from .auth_view import render_auth_view

__all__ = [
    "render_inspector_view",
    "render_ledger_view",
    "render_methodology_view",
    "render_auth_view",
]
