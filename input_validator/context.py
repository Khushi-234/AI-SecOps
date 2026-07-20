# context.py
"""Validation context used across validators.

The :class:`ValidationContext` carries the input data and any auxiliary
information that validators might need (e.g., pre‑computed resources).
"""

from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class ValidationContext:
    """Container for validation data.

    Attributes:
        data: The raw input dictionary to be validated.
        meta: Optional dictionary for auxiliary information that can be
            populated by earlier validators and consumed by later ones.
    """

    data: Dict[str, Any]
    meta: Dict[str, Any] = None

    def __post_init__(self):
        if self.meta is None:
            self.meta = {}
