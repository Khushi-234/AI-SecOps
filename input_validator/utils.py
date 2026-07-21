# utils.py
"""Utility functions shared across validators.

Currently includes simple helpers such as checking for empty strings, length bounds,
and encoding validation. Extend this module as needed.
"""

import re
from typing import Any

import json
import unicodedata
from pathlib import PurePath
from typing import Any, Literal, Optional
from .models import ConversationPayload, ConversationMessage


def parse_raw_payload(data: Any) -> Optional[ConversationPayload]:
    """Safely parses raw input dict or JSON string into a structured ConversationPayload.

    Preserves malformed history entries as fallback messages so downstream validators
    can explicitly evaluate and flag them rather than dropping them silently.

    Args:
        data: Dict or JSON string representing the request body.

    Returns:
        ConversationPayload if the top-level contract matches, otherwise None.
    """
    if isinstance(data, (str, bytes, bytearray)):
        try:
            data = json.loads(data)
        except (ValueError, TypeError):
            return None

    if not isinstance(data, dict):
        return None

    user_prompt = data.get("user")
    if not isinstance(user_prompt, str):
        return None

    raw_history = data.get("history", [])
    if not isinstance(raw_history, list):
        return None

    parsed_history = []
    for item in raw_history:
        if isinstance(item, dict):
            role = str(item.get("role", "unknown"))
            content = str(item.get("content", ""))
            parsed_history.append(ConversationMessage(role=role, content=content))
        else:
            # Preserve invalid history items with a placeholder role to let ContextValidator fail it
            parsed_history.append(ConversationMessage(role="invalid_structure", content=str(item)))

    return ConversationPayload(user=user_prompt, history=parsed_history)


def normalize_unicode_text(
    text: str, 
    form: Literal["NFC", "NFD", "NFKC", "NFKD"] = "NFKC"
    ) -> str:
    """Normalizes Unicode text to prevent visual spoofing and encoding tricks.

    Args:
        text: Input string.
        form: Canonical normalization form ('NFC', 'NFKC', 'NFD', 'NFKD').

    Returns:
        str: Standardized Unicode string.
    """
    if not text:
        return ""
    return unicodedata.normalize(form, text)


def count_utf8_bytes(text: str) -> int:
    """Calculates exact byte size of a UTF-8 encoded string.

    Returns:
        int: Total size in bytes.
    """
    if not text:
        return 0
    return len(text.encode("utf-8", errors="surrogatepass"))


def extract_file_extension(filename: str) -> str:
    """Extracts lowercased file extension safely using path semantics.

    Handles dotfiles (e.g., '.env') and directory paths cleanly.

    Returns:
        str: Extension without leading dot (e.g., 'json', 'pdf') or empty string.
    """
    if not filename:
        return ""
    path = PurePath(filename)
    # Ignore dotfiles without secondary extensions (e.g., '.gitignore' -> suffix is '')
    suffix = path.suffix
    return suffix.lstrip(".").lower() if suffix else ""


def truncate_text(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """Safely truncates text for logging outputs without slicing surrogate pairs.

    Args:
        text: Input string to truncate.
        max_length: Maximum allowed output string length.
        suffix: Indicator string appended when truncation occurs.

    Returns:
        str: Truncated string.
    """
    if not text:
        return ""
    if len(text) <= max_length:
        return text
    return f"{text[:max_length]}{suffix}"


def is_empty(value: Any) -> bool:
    """Return ``True`` if *value* is considered empty.    """
    if value is None:
        return True
    if isinstance(value, (str, bytes)) and len(value) == 0:
        return True
    if isinstance(value, (list, dict, set, tuple)) and len(value) == 0:
        return True
    return False


def within_length(value: str, min_len: int = 0, max_len: int = 1024) -> bool:
    """Check that ``value`` length is within ``[min_len, max_len]``."""
    return min_len <= len(value) <= max_len


def is_valid_utf8(data: bytes) -> bool:
    """Return ``True`` if ``data`` can be decoded as UTF‑8 without errors."""
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def matches_regex(pattern: str, text: str) -> bool:
    """Shortcut for ``re.fullmatch``."""
    return re.fullmatch(pattern, text) is not None
