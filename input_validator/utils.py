# utils.py
"""Utility functions shared across validators.

Currently includes simple helpers such as checking for empty strings, length bounds,
and encoding validation. Extend this module as needed.
"""

import re
from typing import Any


def is_empty(value: Any) -> bool:
    """Return ``True`` if *value* is considered empty.

    Handles ``None`` and empty strings/lists/dicts.
    """
    if value is None:
        return True
    if isinstance(value, (str, bytes)) and len(value) == 0:
        return True
    if isinstance(value, (list, dict, set, tuple)) and len(value) == 0:
        return True
    return False


def within_length(value: str, min_len: int = 0, max_len: int = 1024) -> bool:
    """Check that ``value`` length is within ``[min_len, max_len]``.
    """
    return min_len <= len(value) <= max_len


def is_valid_utf8(data: bytes) -> bool:
    """Return ``True`` if ``data`` can be decoded as UTF‑8 without errors.
    """
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def matches_regex(pattern: str, text: str) -> bool:
    """Shortcut for ``re.fullmatch``.
    """
    return re.fullmatch(pattern, text) is not None
