"""
Utility Helper Routines for the Policy Engine.

Provides helper routines for string normalization and diagnostic metadata formatters.
"""

from __future__ import annotations


def normalize_threat_name(threat: str) -> str:
    """
    Normalizes a threat name string to lowercase stripped format.
    """
    return str(threat).lower().strip()

