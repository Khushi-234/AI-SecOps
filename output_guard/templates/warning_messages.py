"""
Safety warning messages for Output Guard blocked and warned responses.
"""

from __future__ import annotations

from typing import Mapping

WARNING_MESSAGES: Mapping[str, str] = {
    "BLOCK_SAFETY": "Output response was blocked due to critical safety policy violations.",
    "BLOCK_SECRET": "Output response was blocked because confidential credentials were detected.",
    "BLOCK_PROMPT_LEAK": "Output response was blocked to prevent system instruction leakage.",
    "WARN_TOXIC": "Warning: Output text contains potential safety policy warnings.",
}

__all__ = ["WARNING_MESSAGES"]
