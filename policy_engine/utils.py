"""
Utility Helper Routines for the Policy Engine.

Provides helper routines for text manipulation, index range offsets, and sanitization diffs.
"""

from __future__ import annotations

import re
from typing import Sequence

from policy_engine.models import SanitizationEdit


def apply_sanitization_edits(
    prompt: str, edits: Sequence[SanitizationEdit]
) -> str:
    """
    Applies a sequence of SanitizationEdit objects to a prompt string cleanly.

    To maintain index integrity, edits are processed in reverse order of starting position.

    Args:
        prompt: Original prompt text.
        edits: Sequence of SanitizationEdit records.

    Returns:
        Resulting sanitized prompt string.
    """
    if not edits:
        return prompt

    # Sort edits by start_char descending
    sorted_edits = sorted(edits, key=lambda e: e.start_char, reverse=True)
    result = list(prompt)

    for edit in sorted_edits:
        start = edit.start_char
        end = edit.end_char
        if 0 <= start <= len(result) and 0 <= end <= len(result) and start <= end:
            result[start:end] = list(edit.replacement_text)

    return "".join(result)


def sanitize_pattern(
    prompt: str,
    pattern: re.Pattern[str] | str,
    replacement: str,
    sanitization_type_str: str,
) -> tuple[str, list[SanitizationEdit]]:
    """
    Utility function searching a prompt using regex and returning the sanitized string
    along with corresponding SanitizationEdit records.
    """
    if isinstance(pattern, str):
        pattern = re.compile(pattern, re.IGNORECASE)

    edits: list[SanitizationEdit] = []
    edit_counter = 1

    for match in pattern.finditer(prompt):
        original = match.group(0)
        start, end = match.span()
        edit_id = f"{sanitization_type_str.lower()}_edit_{edit_counter}"
        edit_counter += 1

        edits.append(
            SanitizationEdit(
                edit_id=edit_id,
                sanitization_type=sanitization_type_str,
                original_text=original,
                replacement_text=replacement,
                start_char=start,
                end_char=end,
            )
        )

    sanitized = apply_sanitization_edits(prompt, edits)
    return sanitized, edits
