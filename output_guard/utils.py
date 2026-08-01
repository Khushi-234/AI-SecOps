"""
Reusable helper utilities for Output Guard sanitizers and pipeline execution.
"""

from __future__ import annotations

from contextlib import contextmanager
import re
import time
from typing import Callable, Generator, Pattern


@contextmanager
def measure_execution_time() -> Generator[Callable[[], float], None, None]:
    """
    Context manager to measure execution time in milliseconds.

    Usage:
        with measure_execution_time() as elapsed:
            # do work
        ms = elapsed()
    """
    start = time.perf_counter()
    duration = lambda: (time.perf_counter() - start) * 1000.0
    try:
        yield duration
    finally:
        pass


def find_regex_matches(
    text: str, pattern: Pattern[str]
) -> list[tuple[str, int, int]]:
    """
    Finds all occurrences of a regex pattern in text.

    Returns:
        List of tuples containing (matched_text, start_index, end_index).
    """
    if not text or not pattern:
        return []
    matches = []
    for match in pattern.finditer(text):
        matched_str = match.group(0)
        matches.append((matched_str, match.start(), match.end()))
    return matches


def replace_regex_matches(
    text: str,
    pattern: Pattern[str],
    replacement: str | Callable[[re.Match[str]], str],
) -> tuple[str, int]:
    """
    Replaces all occurrences of a regex pattern in text.

    Returns:
        Tuple of (sanitized_text, count_of_replacements).
    """
    if not text:
        return "", 0
    return pattern.subn(replacement, text)


def normalize_output(text: str) -> str:
    """
    Normalizes string content by trimming whitespace and normalizing line endings.
    """
    if text is None:
        return ""
    # Normalize CRLF to LF
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    return normalized.strip()


def truncate_output(text: str, max_length: int, suffix: str = "...") -> str:
    """
    Truncates text if it exceeds max_length.
    """
    if not text or len(text) <= max_length:
        return text
    allowed_length = max(0, max_length - len(suffix))
    return text[:allowed_length] + suffix


def mask_string(
    text: str, visible_prefix: int = 0, visible_suffix: int = 0, mask_char: str = "*"
) -> str:
    """
    Masks a string, preserving optional visible prefix and suffix counts.
    """
    if not text:
        return text
    total_len = len(text)
    if visible_prefix + visible_suffix >= total_len:
        return text
    masked_part = mask_char * (total_len - visible_prefix - visible_suffix)
    return text[:visible_prefix] + masked_part + (text[total_len - visible_suffix :] if visible_suffix > 0 else "")


__all__ = [
    "measure_execution_time",
    "find_regex_matches",
    "replace_regex_matches",
    "normalize_output",
    "truncate_output",
    "mask_string",
]
